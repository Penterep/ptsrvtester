"""AUTHDN — AUTH downgrade after failed authentication."""
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

from ._common import eng


__MODULELABEL__ = "Authentication Downgrade Test"
__MODULECODE__ = "AUTHDN"
__ORDER__ = 60


def _get_smtp_for_auth_downgrade(e) -> tuple[smtplib.SMTP, str]:
    """
        Get SMTP connection with AUTH over TLS (STARTTLS or implicit).
        For port 25/587: upgrade via STARTTLS if not already encrypted.
        """
    smtp = e.get_smtp_handler()
    _, ehlo_bytes = smtp.ehlo(e.fqdn)
    ehlo = ehlo_bytes.decode() if ehlo_bytes else ''
    auth_methods = _get_auth_methods_from_ehlo(ehlo)
    needs_starttls = 'STARTTLS' in ehlo.upper() and e.args.target.port != 465 and (not e.args.tls) and (not e.args.starttls)
    if needs_starttls:
        status, _ = smtp.docmd('STARTTLS')
        if status == 220:
            ctx = ssl._create_unverified_context()
            try:
                _is_ip = ipaddress.ip_address(e.args.target.ip)
                server_hostname = None
            except ValueError:
                server_hostname = e.args.target.ip
            sock_ssl = ctx.wrap_socket(smtp.sock, server_hostname=server_hostname)
            smtp.sock = sock_ssl
            smtp.file = None
            smtp.helo_resp = None
            smtp.ehlo_resp = None
            smtp.esmtp_features = {}
            smtp.does_esmtp = False
            _, ehlo_bytes = smtp.ehlo(e.fqdn)
            ehlo = ehlo_bytes.decode() if ehlo_bytes else ''
    return (smtp, ehlo)


def test_auth_downgrade(e) -> AuthDowngradeResult:
    """
        Test AUTH downgrade: server changes AUTH offer after failed authentication.
        RFC 4954: session state undefined after failed AUTH; RSET before second EHLO.
        """
    WEAK_METHODS = {'PLAIN', 'LOGIN'}
    AUTH_TRIGGER_PREFERENCE = ['XOAUTH2', 'OAUTHBEARER', 'SCRAM-SHA-256', 'SCRAM-SHA-1', 'PLAIN']
    try:
        smtp, ehlo_before = _get_smtp_for_auth_downgrade(e)
    except Exception as ex:
        return AuthDowngradeResult(vulnerable=False, weakness=False, indeterminate=True, info_defensive=False, methods_before=[], methods_after=[], auth_method_used='', server_response=None, detail=f'Connection failed: {ex}', rset_ok=None)
    methods_before = sorted(_get_auth_methods_from_ehlo(ehlo_before))
    if not methods_before:
        return AuthDowngradeResult(vulnerable=False, weakness=False, indeterminate=True, info_defensive=False, methods_before=[], methods_after=[], auth_method_used='', server_response=None, detail='Server does not advertise AUTH', rset_ok=None)
    auth_method_used = None
    for method in AUTH_TRIGGER_PREFERENCE:
        if method in {m.upper() for m in methods_before}:
            auth_method_used = method
            break
    if not auth_method_used:
        auth_method_used = methods_before[0] if methods_before else 'PLAIN'
    bogus_token = e._AUTH_DOWNGRADE_BOGUS_XOAUTH2
    if auth_method_used == 'PLAIN':
        bogus_token = b64encode(b'\x00test\x00test').decode()
    elif auth_method_used in ('OAUTHBEARER', 'XOAUTH2'):
        bogus_token = e._AUTH_DOWNGRADE_BOGUS_XOAUTH2
    server_response: str | None = None
    try:
        try:
            code, resp = smtp.docmd('AUTH', f'{auth_method_used} {bogus_token}')
            e._smtp_vv_io(f'AUTH {auth_method_used}', f'{code} {e.bytes_to_str(resp) if resp else ""}')
        except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError) as ex:
            e._smtp_vv_io(f'AUTH {auth_method_used}', str(ex))
            return AuthDowngradeResult(vulnerable=False, weakness=False, indeterminate=True, info_defensive=False, methods_before=methods_before, methods_after=[], auth_method_used=auth_method_used, server_response=str(ex), detail='Connection closed after failed auth (defensive reaction)', rset_ok=None)
        server_response = f'[{code}] {e.bytes_to_str(resp)}'.strip() if resp else str(code)
        if code == 421:
            return AuthDowngradeResult(vulnerable=False, weakness=False, indeterminate=True, info_defensive=False, methods_before=methods_before, methods_after=[], auth_method_used=auth_method_used, server_response=server_response, detail='Server closed session (421) after failed auth', rset_ok=None)
        try:
            rset_code, rset_resp = smtp.docmd('RSET')
            e._smtp_vv_io('RSET', f'{rset_code} {e.bytes_to_str(rset_resp) if rset_resp else ""}')
        except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError) as ex:
            e._smtp_vv_io('RSET', str(ex))
            return AuthDowngradeResult(vulnerable=False, weakness=False, indeterminate=True, info_defensive=False, methods_before=methods_before, methods_after=[], auth_method_used=auth_method_used, server_response=server_response, detail='Connection closed after RSET (server may have terminated session on RSET)', rset_ok=False)
        try:
            ehlo_code, ehlo_after_bytes = smtp.ehlo(e.fqdn)
            e._smtp_vv_io(f'EHLO {e.fqdn}', f'{ehlo_code} {ehlo_after_bytes.decode() if ehlo_after_bytes else ""}')
        except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError) as ex:
            e._smtp_vv_io(f'EHLO {e.fqdn}', str(ex))
            return AuthDowngradeResult(vulnerable=False, weakness=False, indeterminate=True, info_defensive=False, methods_before=methods_before, methods_after=[], auth_method_used=auth_method_used, server_response=server_response, detail='Connection closed during second EHLO', rset_ok=True)
        ehlo_after = ehlo_after_bytes.decode() if ehlo_after_bytes else ''
        methods_after = sorted(_get_auth_methods_from_ehlo(ehlo_after))
    except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError) as ex:
        return AuthDowngradeResult(vulnerable=False, weakness=False, indeterminate=True, info_defensive=False, methods_before=methods_before, methods_after=[], auth_method_used=auth_method_used or '?', server_response=server_response or str(ex), detail='Connection closed during test', rset_ok=None)
    set_before = set((m.upper() for m in methods_before))
    set_after = set((m.upper() for m in methods_after))
    new_methods = set_after - set_before
    removed_methods = set_before - set_after
    if not methods_after:
        return AuthDowngradeResult(vulnerable=False, weakness=False, indeterminate=False, info_defensive=True, methods_before=methods_before, methods_after=[], auth_method_used=auth_method_used, server_response=server_response, detail='AUTH disappeared after failure (defensive reaction)', rset_ok=True)
    if new_methods:
        weak_new = new_methods & WEAK_METHODS
        detail = f'New methods after failure: {sorted(new_methods)}'
        if weak_new:
            detail += '; risk: credential sniffing'
        return AuthDowngradeResult(vulnerable=True, weakness=False, indeterminate=False, info_defensive=False, methods_before=methods_before, methods_after=methods_after, auth_method_used=auth_method_used, server_response=server_response, detail=detail, rset_ok=True)
    if removed_methods and set_after & WEAK_METHODS:
        return AuthDowngradeResult(vulnerable=True, weakness=True, indeterminate=False, info_defensive=False, methods_before=methods_before, methods_after=methods_after, auth_method_used=auth_method_used, server_response=server_response, detail=f'Strong methods removed, PLAIN/LOGIN remained: {sorted(removed_methods)}', rset_ok=True)
    return AuthDowngradeResult(vulnerable=False, weakness=False, indeterminate=False, info_defensive=False, methods_before=methods_before, methods_after=methods_after, auth_method_used=auth_method_used, server_response=server_response, detail='No authentication downgrade detected', rset_ok=True)


def _stream_auth_downgrade_result(e) -> None:
    pp = e._ptprint_raw
    show = not e.use_json
    if (err := e.results.auth_downgrade_error) is not None:
        pp(f'AUTH downgrade test failed: {err}', bullet_type='VULN', condition=show, indent=4)
        return
    ad = e.results.auth_downgrade
    if ad is None:
        return
    before = ', '.join(ad.methods_before) if ad.methods_before else '(none)'
    after = ', '.join(ad.methods_after) if ad.methods_after else '(none)'
    if not e.args.debug:
        pp(f'AUTH methods: {before}', bullet_type='TITLE', condition=show, indent=4)
        if ad.auth_method_used:
            pp(f'AUTH {ad.auth_method_used}: {ad.server_response or "(no reply)"}', bullet_type='TITLE', condition=show, indent=4)
        if ad.rset_ok is False:
            pp('Connection closed after RSET', bullet_type='WARNING', condition=show, indent=4)
        elif ad.methods_after or ad.rset_ok:
            pp(f'AUTH methods after failure: {after}', bullet_type='TITLE', condition=show, indent=4)
    else:
        pp(f'AUTH methods: {before} → {after}', bullet_type='TITLE', condition=show, indent=4)
    if ad.indeterminate:
        pp(f"Indeterminate: {ad.detail or 'Could not determine'}", bullet_type='WARNING', condition=show, indent=4)
        return
    if ad.info_defensive:
        pp(ad.detail, bullet_type='TITLE', condition=show, indent=4)
        return
    if ad.vulnerable:
        pp(ad.detail, bullet_type='VULN', condition=show, indent=4)
    else:
        pp(ad.detail, bullet_type='NOTVULN', condition=show, indent=4)


def run(ctx):
    e = eng(ctx)
    try:
        e.results.auth_downgrade = test_auth_downgrade(e)
    except Exception as ex:
        e.results.auth_downgrade_error = str(ex)
        ctx.out(f"AUTHDN failed: {ex}", "ERROR", indent=4)
        return
    _stream_auth_downgrade_result(e)
