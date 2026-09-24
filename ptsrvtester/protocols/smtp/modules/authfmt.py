"""AUTHFMT — AUTH LOGIN identity format probe."""
import ipaddress, random, secrets, smtplib, ssl, threading, time
from base64 import b64decode, b64encode

from ..utils.ptntlmauth.ptntlmauth import get_NegotiateMessage_data, decode_ChallengeMessage_blob

try:
    from ntlm_auth.ntlm import NtlmContext
except ImportError:
    NtlmContext = None

from ..._base import Out
from ..utils.helpers import AUTH_ENUM_SYNTHETIC_INVALID_COUNT, auth_enum_candidate_names, auth_enum_ntlm_identity_note
from ..utils.progress import ThreadedProgress

from ..utils.helpers import *
from ..utils.results import *
from ..utils.registry import *

from ._auth import _get_smtp_for_auth_enum
from ._common import eng


__MODULELABEL__ = "AUTH LOGIN format detection"
__MODULECODE__ = "AUTHFMT"
__ORDER__ = 55


def _auth_format_last_two_labels(fqdn: str) -> str | None:
    """Last two DNS labels (no PSL — UK/JP etc. often wrong for 'organizational' domain)."""
    parts = fqdn.strip().lower().rstrip('.').split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return None


def _auth_format_resolve_target_domain(e, ehlo_text: str) -> AuthFormatTargetDomainDerivation:
    """
        Domain for probe B: from scan hostname or, if target is IP, from first EHLO hostname line.
        Documented limitation: not PSL-aware (mail.company.co.uk → co.uk).
        """
    raw = (e.args.target.ip or '').strip()
    host_l = raw.lower().rstrip('.')
    try:
        ipaddress.ip_address(host_l)
        is_ip = True
    except ValueError:
        is_ip = False
    if not is_ip:
        dom = _auth_format_last_two_labels(host_l)
        if dom:
            note = f"Derived '{dom}' as last 2 labels from scan target {host_l!r} (not PSL-aware — e.g. mail.company.co.uk → co.uk; compare probe B vs C if unsure)."
            return AuthFormatTargetDomainDerivation(dom, 'scan_last2', note, None, host_l)
        return AuthFormatTargetDomainDerivation(None, 'none', 'Scan target is not a multi-label hostname; probe B skipped.', None, host_l or None)
    eh = _get_hostname_from_ehlo_raw(ehlo_text)
    if not eh:
        return AuthFormatTargetDomainDerivation(None, 'none', 'Scan target is an IP and no suitable hostname on first EHLO line; probe B skipped.', None, None)
    dom = _auth_format_last_two_labels(eh)
    if not dom:
        return AuthFormatTargetDomainDerivation(None, 'none', f'Scan target is an IP; EHLO hostname {eh!r} is not suitable for last-2 derivation; probe B skipped.', eh, None)
    note = f"Scan target is an IP; derived '{dom}' from EHLO hostname {eh!r} (last 2 labels, not PSL-aware — EHLO may differ from connection target)."
    return AuthFormatTargetDomainDerivation(dom, 'ehlo_last2', note, eh, None)


def _ntlm_netbios_domain_probe(e) -> str | None:
    """One-shot NTLM negotiate to read NetBIOS/DNS name from challenge (optional 4th probe)."""
    smtp = None
    try:
        smtp, ehlo = _get_smtp_for_auth_enum(e)
        if 'NTLM' not in _get_auth_methods_from_ehlo(ehlo):
            return None
        code, resp = smtp.docmd('AUTH', 'NTLM')
        if code != 334:
            return None
        smtp.send(b64encode(get_NegotiateMessage_data()) + smtplib.bCRLF)
        code2, resp2 = smtp.getreply()
        if code2 != 334:
            return None
        info = decode_ChallengeMessage_blob(b64decode(resp2))
        return (info.netbios_domain or info.dns_domain or info.target_name or '').strip() or None
    except Exception:
        return None
    finally:
        if smtp:
            try:
                smtp.close()
            except Exception:
                pass


def _probe_auth_login_identity(e, identity: str) -> tuple[int | None, bool, int | None, str | None, bool, str | None]:
    """
        Fresh connection: AUTH LOGIN → optional challenge decode → base64 identity.
        Returns:
            code_after_identity, password_phase, code_after_password, reply_after_identity,
            rate_limited, challenge_decoded (from first 334 after AUTH LOGIN).
        """
    smtp = None
    ch_dec: str | None = None
    try:
        smtp, _ = _get_smtp_for_auth_enum(e)
        code, resp = smtp.docmd('AUTH', 'LOGIN')
        e._smtp_vv_io('AUTH LOGIN', f'{code} {e.bytes_to_str(resp) if resp else ""}')
        ch_dec = _auth_format_decode_login_challenge(resp)
        if code in (421, 450, 452):
            return (None, False, None, e.bytes_to_str(resp), True, ch_dec)
        if code != 334:
            return (code, False, None, e.bytes_to_str(resp), False, ch_dec)
        id_b64 = b64encode(identity.encode('utf-8')).decode('ascii')
        code_u, resp_u = smtp.docmd(id_b64)
        e._smtp_vv_io(f'AUTH LOGIN user {identity}', f'{code_u} {e.bytes_to_str(resp_u) if resp_u else ""}')
        if code_u in (421, 450, 452):
            return (None, False, None, e.bytes_to_str(resp_u), True, ch_dec)
        if code_u == 334:
            pw_b64 = b64encode(secrets.token_bytes(16)).decode('ascii')
            code_p, resp_p = smtp.docmd(pw_b64)
            e._smtp_vv_io('AUTH LOGIN password', f'{code_p} {e.bytes_to_str(resp_p) if resp_p else ""}')
            return (code_u, True, code_p, e.bytes_to_str(resp_u), False, ch_dec)
        return (code_u, False, None, e.bytes_to_str(resp_u), code_u in (421, 450, 452), ch_dec)
    finally:
        if smtp:
            try:
                smtp.close()
            except Exception:
                pass


def test_auth_format_probe(e) -> AuthFormatProbeResult:
    """
        PTL-SVC-SMTP-AUTH-FORMAT: infer expected AUTH LOGIN identity shape using a few non-destructive probes.
        Each probe uses a fresh connection; ~1.5s delay between probes to reduce rate-limit risk.
        """
    probe_user = f'ptauthfmt_{secrets.token_hex(4)}'
    try:
        sm0, ehlo0 = _get_smtp_for_auth_enum(e)
        try:
            sm0.close()
        except Exception:
            pass
    except Exception as ex:
        return AuthFormatProbeResult('', (), None, None, f'Connection failed: {ex}', 'error', None, None, False, True, str(ex), 'none', None, None, None)
    auth_methods = _get_auth_methods_from_ehlo(ehlo0)
    if 'LOGIN' not in auth_methods:
        return AuthFormatProbeResult('', (), None, None, 'Server does not advertise AUTH LOGIN', 'no_login', None, None, False, True, None, 'none', None, None, None)
    td_info = _auth_format_resolve_target_domain(e, ehlo0)
    target_domain = td_info.domain
    netbios_domain = _ntlm_netbios_domain_probe(e)
    plan: list[tuple[str, str, str | None, str | None]] = [('single_label', 'Single label', probe_user, None), ('target_domain', 'Target domain e-mail', f'{probe_user}@{target_domain}' if target_domain else None, None if target_domain else 'Target domain unknown (use hostname target or N/A)'), ('external_domain', f'External domain ({AUTH_FORMAT_EXTERNAL_SUFFIX})', f'{probe_user}@{AUTH_FORMAT_EXTERNAL_SUFFIX}', None), ('netbios', 'NetBIOS (DOMAIN\\user)', f'{netbios_domain}\\{probe_user}' if netbios_domain else None, None if netbios_domain else 'NTLM not advertised or domain not decoded')]
    rows_out: list[AuthFormatProbeRow] = []
    challenge_decoded: str | None = None
    challenge_hint: str | None = None
    rate_glob = False
    first_probe = True
    for pid, label, ident, skip_reason in plan:
        if not first_probe:
            time.sleep(AUTH_FORMAT_PROBE_DELAY_SEC)
        first_probe = False
        if rate_glob:
            rows_out.append(AuthFormatProbeRow(probe_id=pid, label=label, identity=ident or '', skipped=True, skip_reason='Skipped (previous probe rate-limited)', code_after_identity=None, password_phase=False, code_after_password=None, reply_after_identity=None, rate_limited=False))
            continue
        if ident is None:
            rows_out.append(AuthFormatProbeRow(probe_id=pid, label=label, identity='', skipped=True, skip_reason=skip_reason or 'Skipped', code_after_identity=None, password_phase=False, code_after_password=None, reply_after_identity=None, rate_limited=False))
            continue
        try:
            c_id, pwd_ph, c_pw, reply_id, rl, ch1 = _probe_auth_login_identity(e, ident)
        except Exception as ex:
            rows_out.append(AuthFormatProbeRow(probe_id=pid, label=label, identity=ident, skipped=False, skip_reason=None, code_after_identity=None, password_phase=False, code_after_password=None, reply_after_identity=str(ex), rate_limited=False))
            continue
        if challenge_decoded is None and ch1:
            challenge_decoded = ch1
            challenge_hint = _auth_format_hint_from_challenge_text(ch1)
        if rl:
            rate_glob = True
        if c_pw is not None and c_pw in (421, 450, 452):
            rate_glob = True
        rows_out.append(AuthFormatProbeRow(probe_id=pid, label=label, identity=ident, skipped=False, skip_reason=None, code_after_identity=c_id, password_phase=pwd_ph, code_after_password=c_pw, reply_after_identity=reply_id, rate_limited=rl))
    sym_map = {r.probe_id: _auth_format_row_symbol(r) for r in rows_out}
    sym_a = sym_map.get('single_label', '?')
    sym_b = sym_map.get('target_domain', 'skip')
    sym_c = sym_map.get('external_domain', '?')
    sym_d = sym_map.get('netbios', 'skip')
    b_ran = any((r.probe_id == 'target_domain' and (not r.skipped) for r in rows_out))
    d_ran = any((r.probe_id == 'netbios' and (not r.skipped) for r in rows_out))
    if rate_glob:
        cid, msg = ('rate_limited', 'Probe stopped early: server returned temporary failure (421/450/452) — possible rate limiting')
    elif sym_a == 'rate' or sym_b == 'rate' or sym_c == 'rate' or (sym_d == 'rate'):
        cid, msg = ('rate_limited', 'Temporary failure during probe (421/450/452) — possible rate limiting')
        rate_glob = True
    else:
        cid, msg = _auth_format_conclude(sym_a, sym_b, sym_c, sym_d, b_ran, d_ran, challenge_hint)
        if challenge_hint and cid == 'mixed_responses':
            msg = f'{msg} (LOGIN challenge hint: {challenge_hint})'
    indet = cid in ('error', 'no_login', 'rate_limited', 'indeterminate_no_target_domain', 'challenge_hint_only')
    return AuthFormatProbeResult(method_tested='LOGIN', rows=tuple(rows_out), challenge_decoded=challenge_decoded, challenge_hint=challenge_hint, conclusion=msg, conclusion_id=cid, target_domain_used=target_domain, netbios_domain_used=netbios_domain, rate_limited=rate_glob or sym_a == 'rate' or sym_b == 'rate' or (sym_c == 'rate') or (sym_d == 'rate'), indeterminate=indet, detail=None, target_domain_source=td_info.source, target_domain_analyst_note=td_info.analyst_note, target_domain_ehlo_hostname=td_info.ehlo_hostname, target_domain_scan_hostname=td_info.scan_hostname)


def _stream_auth_format_result(e) -> None:
    """PTL-SVC-SMTP-AUTH-FORMAT: text output for AUTH LOGIN identity-shape probes."""
    pp = e._ptprint_raw
    show = not e.use_json
    if (err := e.results.auth_format_error) is not None:
        pp(f'AUTH format probe failed: {err}', bullet_type='TITLE', condition=show, indent=4)
        return
    af = e.results.auth_format
    if af is None:
        return
    pp(f'AUTH Analysis ({af.method_tested})', bullet_type='INFO', condition=show, indent=4)
    if af.challenge_decoded is not None:
        pp(f'AUTH LOGIN challenge (decoded): {af.challenge_decoded!r}', bullet_type='TITLE', condition=show, indent=4)
    if af.challenge_hint:
        pp(f'Challenge heuristic: {af.challenge_hint}', bullet_type='TITLE', condition=show, indent=4)
    pp('Auth Format Probe:', bullet_type='TITLE', condition=show, indent=4)
    if af.target_domain_used:
        pp(f'Target domain used: {af.target_domain_used}', bullet_type='TITLE', condition=show, indent=8)
    for r in af.rows:
        if r.skipped:
            pp(f"{r.label}: skipped ({r.skip_reason or 'n/a'})", bullet_type='TITLE', condition=show, indent=8)
        elif r.password_phase:
            tail = f'final reply {r.code_after_password}' if r.code_after_password is not None else 'password phase'
            pp(f'{r.label}: accepted → password phase ({tail})', bullet_type='TITLE', condition=show, indent=8)
        else:
            rep = (r.reply_after_identity or '').replace('\r\n', ' ').strip()
            if len(rep) > 140:
                rep = rep[:137] + '...'
            pp(f'{r.label}: rejected at username ({r.code_after_identity}) {rep}'.rstrip(), bullet_type='TITLE', condition=show, indent=8)
    pp(f'Auth Identity Format: {af.conclusion}', bullet_type='TITLE', condition=show, indent=4)
    if af.conclusion_id == 'flexible_all_formats':
        ch_tail = ''
        hint_note = af.challenge_hint
        if hint_note and 'ambiguous' in hint_note.lower():
            hint_note = 'format ambiguous'
        if af.challenge_decoded is not None and hint_note:
            ch_tail = f' Challenge hint: {af.challenge_decoded!r} — {hint_note}.'
        elif af.challenge_decoded is not None:
            ch_tail = f' Challenge hint: {af.challenge_decoded!r}.'
        elif hint_note:
            ch_tail = f' Challenge hint: {hint_note}.'
        pp(f'Note: All probes that ran reached password phase — server may be masking expected format (catch-all behavior).{ch_tail}', bullet_type='TITLE', condition=show, indent=4)
    if af.netbios_domain_used:
        pp(f'NTLM-derived DOMAIN for NetBIOS probe: {af.netbios_domain_used}', bullet_type='TITLE', condition=show, indent=4)


def run(ctx):
    e = eng(ctx)
    e.args.auth_format = True
    try:
        e.results.auth_format = test_auth_format_probe(e)
    except Exception as ex:
        e.results.auth_format_error = str(ex)
        ctx.out(f"AUTHFMT failed: {ex}", "ERROR", indent=4)
        return
    _stream_auth_format_result(e)
