"""PROBEDOM — accepted recipient domain probe."""
import secrets, smtplib, socket, sys, threading, time

from ..._base import Out

from ..utils.helpers import *
from ..utils.results import *
from ..utils.registry import *

from ._common import eng
from .rcptlim import _rcpt_response_suggests_bad_domain


__MODULELABEL__ = ""
__MODULECODE__ = "PROBEDOM"
__ORDER__ = 215


def _build_accepted_domain_probe_candidates(e) -> list[str]:
    """Ordered domain candidates: -d only, else inferred + parent + invalid.invalid control."""
    seen: set[str] = set()
    out: list[str] = []

    def add(d: str) -> None:
        t = (d or '').strip().lower().rstrip('.')
        if not t or '.' not in t or t in seen:
            return
        seen.add(t)
        out.append(t)
    dom_arg = getattr(e.args, 'domain', None)
    if dom_arg and str(dom_arg).strip():
        add(str(dom_arg).strip())
    else:
        add(e._get_rcpt_limit_domain())
        if out:
            base = out[-1]
            if base.count('.') >= 2:
                add(e._to_parent_domain(base))
    add('invalid.invalid')
    return out[:12]


def _rcpt_reply_suggests_unknown_user(reply: str | bytes) -> bool:
    if isinstance(reply, bytes):
        up = reply.upper()
    else:
        up = str(reply).upper()
    keys = ('UNKNOWN', 'USER UNKNOWN', 'NO SUCH USER', 'MAILBOX UNAVAILABLE', 'ADDRESS REJECTED', 'NOT FOUND', 'INVALID RECIPIENT', '5.1.1')
    return any((k in up for k in keys))


def _probe_rcpt_acceptance_for_domain(e, smtp: smtplib.SMTP, domain: str, random_local: str) -> tuple[int, str, str]:
    """Score one domain: (0–100, confidence high|medium|low|none, short detail)."""
    mail_bracket = e._envelope_mail_from_bracket()
    try:
        smtp.docmd('RSET')
    except Exception:
        pass
    try:
        st_m, rep_m = smtp.docmd('MAIL FROM:', mail_bracket)
        e._smtp_vv_io(f'MAIL FROM:{mail_bracket}', f'{st_m} {e.bytes_to_str(rep_m) if rep_m else ""}')
    except Exception as ex:
        e._smtp_vv_io(f'MAIL FROM:{mail_bracket}', str(ex))
        return (0, 'none', f'MAIL FROM failed: {ex}')
    if st_m != 250:
        return (0, 'none', f'MAIL FROM not accepted ({st_m})')
    try:
        st_r, rep_r = smtp.docmd('RCPT TO:', f'<{random_local}@{domain}>')
        e._smtp_vv_io(f'RCPT TO:<{random_local}@{domain}>', f'{st_r} {e.bytes_to_str(rep_r) if rep_r else ""}')
    except Exception as ex:
        e._smtp_vv_io(f'RCPT TO:<{random_local}@{domain}>', str(ex))
        return (0, 'none', f'RCPT (probe) failed: {ex}')
    reply_r = e.bytes_to_str(rep_r) if rep_r else ''
    if 400 <= st_r < 500:
        return (5, 'none', f'RCPT probe temporary rejection ({st_r}); try later')
    try:
        smtp.docmd('RSET')
    except Exception:
        pass
    try:
        st_m2, rep_m2 = smtp.docmd('MAIL FROM:', mail_bracket)
        e._smtp_vv_io(f'MAIL FROM:{mail_bracket}', f'{st_m2} {e.bytes_to_str(rep_m2) if rep_m2 else ""}')
    except Exception as ex:
        return (0, 'none', f'MAIL FROM after RSET failed: {ex}')
    if st_m2 != 250:
        return (0, 'none', f'MAIL FROM not accepted after RSET ({st_m2})')
    try:
        st_p, rep_p = smtp.docmd('RCPT TO:', f'<Postmaster@{domain}>')
        e._smtp_vv_io(f'RCPT TO:<Postmaster@{domain}>', f'{st_p} {e.bytes_to_str(rep_p) if rep_p else ""}')
    except Exception as ex:
        return (0, 'none', f'RCPT Postmaster failed: {ex}')
    reply_p = e.bytes_to_str(rep_p) if rep_p else ''
    probe_ok = 200 <= st_r < 300
    post_ok = 200 <= st_p < 300
    bad_probe = _rcpt_response_suggests_bad_domain(reply_r)
    unk_probe = _rcpt_reply_suggests_unknown_user(reply_r) or (550 <= st_r < 560 and (not bad_probe) and (not probe_ok))
    if bad_probe and (not probe_ok):
        return (0, 'none', 'Domain-level or relay rejection on probe RCPT')
    if not probe_ok and unk_probe and (not bad_probe):
        if post_ok:
            return (95, 'high', 'Postmaster accepted; probe mailbox rejected as unknown user at this domain')
        return (92, 'high', 'Probe mailbox rejected as unknown user; server accepts this recipient domain; Postmaster not accepted or blocked by policy')
    if post_ok and probe_ok:
        return (40, 'low', 'Server accepts RCPT for probe and Postmaster (possible catch-all or deferred verify)')
    if probe_ok and (not post_ok):
        return (38, 'low', 'Server accepts probe mailbox; Postmaster not accepted (unusual)')
    if not probe_ok and 550 <= st_r < 560 and (not bad_probe) and (not unk_probe):
        return (25, 'none', f'RCPT probe rejected ({st_r}) without clear unknown-user semantics')
    return (0, 'none', 'No clear local-domain signal from RCPT responses')


def test_probe_accepted_domain(e) -> AcceptedDomainProbeResult:
    """Informational: infer which @domain RCPT treats as locally relevant (RFC 5321 RCPT semantics)."""
    if not getattr(e.results, 'info', None):
        _, info = e.initial_info(get_commands=True)
        e.results.info = InfoResult(info.banner, info.ehlo, getattr(info, 'ehlo_starttls', None))
        e.results.resolved_domain = e._get_domain_from_banner_or_ptr(e.results.info)
        e.results.banner_requested = False
        e.results.commands_requested = False
    candidates = _build_accepted_domain_probe_candidates(e)
    random_local = f'ptsrvnx{secrets.token_hex(4)}'
    best: tuple[int, str, str, str] | None = None
    universal = False
    tried: list[str] = []
    smtp: smtplib.SMTP | None = None
    try:
        smtp = e.get_smtp_handler()
        smtp.docmd('EHLO', e.fqdn)
        for dom in candidates:
            tried.append(dom)
            sc, conf, det = _probe_rcpt_acceptance_for_domain(e, smtp, dom, random_local)
            if dom.lower() == 'invalid.invalid' and sc >= 38:
                universal = True
            if dom.lower() != 'invalid.invalid':
                if best is None or sc > best[0]:
                    best = (sc, dom, conf, det)
    finally:
        if smtp is not None:
            try:
                smtp.close()
            except Exception:
                pass
    min_score = 38
    if best is None or best[0] < min_score:
        detail = (best[3] if best else '') or 'No tested domain produced a confident local-domain pattern.'
        if universal:
            extra = 'Server is "Accept-All" or uses deferred verification (invalid.invalid accepted).'
            detail = f'{detail} {extra}'.strip() if detail else extra
        return AcceptedDomainProbeResult(None, 'none', detail, tuple(tried), universal)
    _sc, dom, conf, det = best
    placeholder = _accepted_domain_is_placeholder(dom)
    if conf == 'high' and (universal or placeholder):
        conf = 'medium'
    detail = det
    return AcceptedDomainProbeResult(dom, conf, detail, tuple(tried), universal, placeholder)


def _stream_accepted_domain_probe_result(e) -> None:
    pp = e._ptprint_raw
    show = not e.use_json
    if e.use_json:
        return
    if (err := e.results.accepted_domain_probe_error) is not None:
        pp(f'Test failed: {err}', bullet_type='VULN', condition=show, indent=4)
        return
    r = e.results.accepted_domain_probe
    if r is None:
        return
    if r.universal_accept_detected:
        pp('Server is "Accept-All" or uses deferred verification (invalid.invalid accepted).', bullet_type='TITLE', condition=show, indent=4)
    domain_line_bullet = 'WARNING' if r.universal_accept_detected or getattr(r, 'likely_placeholder_domain', False) else 'TITLE'
    if r.domain and r.confidence != 'none':
        pp(f'Accepted recipient domain: {r.domain} (confidence: {r.confidence})', bullet_type=domain_line_bullet, condition=show, indent=4)
        if r.detail:
            pp(r.detail, bullet_type='TITLE', condition=show, indent=4)
        if getattr(r, 'likely_placeholder_domain', False):
            pp(f'WARNING: {r.domain} matches a known placeholder / example domain; this often reflects default MTA configuration, not an operational recipient namespace.', bullet_type='WARNING', condition=show, indent=4)
    else:
        no_dom_bullet = 'WARNING' if r.universal_accept_detected else 'TITLE'
        pp('Could not determine an accepted recipient domain', bullet_type=no_dom_bullet, condition=show, indent=4)
        if r.detail:
            pp(r.detail, bullet_type='TITLE', condition=show, indent=4)


def _accepted_domain_probe_props_json(e) -> dict[str, object]:
    """JSON fragment for -pd (no vulnerabilities)."""
    out: dict[str, object] = {}
    if (err := e.results.accepted_domain_probe_error) is not None:
        out['acceptedRecipientDomainProbeError'] = err
        return out
    pr = e.results.accepted_domain_probe
    if pr is None:
        return out
    obj: dict[str, object] = {'domain': pr.domain, 'confidence': pr.confidence, 'candidatesTested': list(pr.candidates_tested), 'universalAcceptDetected': pr.universal_accept_detected, 'likelyPlaceholderDomain': pr.likely_placeholder_domain}
    if pr.detail:
        obj['detail'] = pr.detail
    out['acceptedRecipientDomainProbe'] = obj
    return out


def run(ctx):
    e = eng(ctx)
    try:
        e.results.accepted_domain_probe = test_probe_accepted_domain(e)
    except Exception as ex:
        e.results.accepted_domain_probe_error = str(ex)
        ctx.out(f"PROBEDOM failed: {ex}", "ERROR", indent=4)
        return
    _stream_accepted_domain_probe_result(e)
