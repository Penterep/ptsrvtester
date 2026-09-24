"""ROLE — MTA / Submission / Hybrid identification."""
import smtplib

from ..._base import Out

from ..utils.helpers import *
from ..utils.results import *
from ..utils.registry import *

from ._common import ensure_info


__MODULELABEL__ = "Identified Role"
__MODULECODE__ = "ROLE"
__ORDER__ = 20


def _role_rcpt_probe(e, smtp: smtplib.SMTP, target_domain: str | None) -> tuple[bool | None, str]:
    """Send MAIL FROM + RCPT TO without AUTH to determine if server requires authentication.

        Returns (auth_required, detail):
          True   -- server requires auth for RCPT TO (530)
          False  -- server accepts RCPT TO without auth (MTA or hybrid behaviour)
          None   -- could not determine (no domain, connection error, etc.)

        Guarantees: smtp handler is returned to a clean state (RSET) on all code
        paths so that subsequent tests (open_relay, enumeration, ...) can start
        a fresh MAIL transaction without 503 errors.
        """
    if not target_domain:
        target_domain = f'[{e.target_ip}]'
    ext_domain = 'gmail.com'
    mail_from = '<roletest@example.com>'
    local_rcpt = f'postmaster@{target_domain}'
    ext_rcpt = f'roletest@{ext_domain}'

    def _reply_one_line(raw: str | bytes, limit: int=160) -> str:
        if isinstance(raw, str):
            s = raw.strip().replace('\r\n', ' ').replace('\n', ' ')
        else:
            s = e.bytes_to_str(raw).strip().replace('\r\n', ' ').replace('\n', ' ')
        return s if len(s) <= limit else s[:limit - 3] + '...'

    def _log_step(step: str, status: int, reply: str | bytes) -> None:
        e._smtp_vv_io(step, f'{status} {_reply_one_line(reply)}')
    local_auth_required: bool | None = None
    local_detail = ''
    try:
        try:
            smtp.docmd('RSET')
        except Exception:
            pass
        try:
            status, reply = smtp.docmd('MAIL FROM:', mail_from)
            _log_step(f'MAIL FROM:{mail_from}', status, reply)
            if status not in (250, 251):
                return (None, f'MAIL FROM rejected: {status} {e.bytes_to_str(reply)}')
        except Exception as ex:
            return (None, f'MAIL FROM error: {ex}')
        try:
            local_env = f'<{local_rcpt}>'
            status, reply = smtp.docmd('RCPT TO:', local_env)
            reply_str = e.bytes_to_str(reply)
            _log_step(f'RCPT TO:{local_env}', status, reply)
            if status in (250, 251):
                local_auth_required = False
                local_detail = f'RCPT TO:{local_env} accepted without auth ({status})'
            elif 530 <= status <= 535:
                local_auth_required = True
                local_detail = f'RCPT TO:{local_env} requires authentication ({status})'
            elif status in (550, 551, 553):
                local_auth_required = False
                local_detail = f'RCPT TO:{local_env} rejected user ({status}) but no auth required'
            elif status in (450, 451, 452):
                local_auth_required = False
                local_detail = f'RCPT TO:{local_env} greylisting detected ({status}); no auth required'
            elif status == 421:
                return (None, f'Server closed connection ({status})')
            else:
                local_detail = f'RCPT TO:{local_env} unexpected response: {status} {reply_str}'
        except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError) as ex:
            return (None, f'Connection lost during RCPT TO probe: {ex}')
        except Exception as ex:
            return (None, f'RCPT TO error: {ex}')
        if local_auth_required is False:
            try:
                smtp.docmd('RSET')
                status, reply = smtp.docmd('MAIL FROM:', mail_from)
                _log_step(f'MAIL FROM:{mail_from}', status, reply)
                if status not in (250, 251):
                    pass
                else:
                    ext_env = f'<{ext_rcpt}>'
                    status, reply = smtp.docmd('RCPT TO:', ext_env)
                    reply_str = e.bytes_to_str(reply)
                    _log_step(f'RCPT TO:{ext_env}', status, reply)
                    if status in (250, 251):
                        local_detail += f'; RCPT TO:{ext_env} also accepted (possible open relay)'
            except Exception:
                pass
        if local_auth_required is not None:
            return (local_auth_required, local_detail)
        return (None, local_detail or 'Could not determine auth requirement')
    finally:
        try:
            smtp.docmd('RSET')
        except Exception:
            pass


def test_role(e, smtp: smtplib.SMTP, info: InfoResult) -> RoleResult:
    """Identify SMTP server role based on port, AUTH availability, and RCPT TO probe.

        Decision matrix:
          port_hint  | AUTH advertised | RCPT TO probe    | Result
          -----------|-----------------|------------------|------------
          mta (25)   | no              | (skip)           | MTA
          mta (25)   | yes             | auth required    | Submission (unusual port)
          mta (25)   | yes             | no auth required | Hybrid
          sub (587+) | yes             | (skip)           | Submission
          sub (587+) | no              | no auth required | MTA (unusual port)
          sub (587+) | no              | auth required    | Submission
          any        | indeterminate   | indeterminate    | Indeterminate
        """
    if getattr(e.args, 'smtp_role', None):
        e.ptdebug(f'Declared server role (--role): {e.args.smtp_role} (overrides port-based MTA vs Submission classification)', Out.INFO)
    port_hint = e._role_port_hint()
    auth_plain, methods_plain = e._ehlo_has_auth(info.ehlo)
    auth_starttls, methods_starttls = e._ehlo_has_auth(getattr(info, 'ehlo_starttls', None))
    auth_advertised = auth_plain or auth_starttls
    auth_methods = sorted(set(methods_plain + methods_starttls))
    target_domain = getattr(e.results, 'resolved_domain', None)
    if port_hint == 'mta' and (not auth_advertised):
        detail = 'Port 25, AUTH not advertised'
        return RoleResult('mta', port_hint, False, None, detail)
    if port_hint == 'submission' and auth_advertised:
        methods_str = ', '.join(auth_methods) if auth_methods else 'unknown'
        detail = f'Port {e.args.target.port}, AUTH advertised ({methods_str})'
        return RoleResult('submission', port_hint, True, None, detail)
    auth_required, probe_detail = _role_rcpt_probe(e, smtp, target_domain)
    if port_hint == 'mta' and auth_advertised:
        methods_str = ', '.join(auth_methods) if auth_methods else 'unknown'
        if auth_required is True:
            detail = f'Port 25 but AUTH required for RCPT TO ({methods_str}); {probe_detail}'
            return RoleResult('submission', port_hint, True, True, detail)
        elif auth_required is False:
            detail = f'Port 25, AUTH advertised ({methods_str}) but RCPT TO accepted without auth; {probe_detail}'
            return RoleResult('hybrid', port_hint, True, False, detail)
        else:
            detail = f'Port 25, AUTH advertised ({methods_str}), probe inconclusive; {probe_detail}'
            return RoleResult('indeterminate', port_hint, True, None, detail)
    if port_hint == 'submission' and (not auth_advertised):
        if auth_required is True:
            detail = f'Port {e.args.target.port}, AUTH not in EHLO but required for RCPT TO; {probe_detail}'
            return RoleResult('submission', port_hint, False, True, detail)
        elif auth_required is False:
            detail = f'Port {e.args.target.port} (typical Submission) but no AUTH and RCPT TO accepted; {probe_detail}'
            return RoleResult('mta', port_hint, False, False, detail)
        else:
            detail = f'Port {e.args.target.port}, AUTH not in EHLO, probe inconclusive; {probe_detail}'
            return RoleResult('indeterminate', port_hint, False, None, detail)
    if auth_advertised:
        methods_str = ', '.join(auth_methods) if auth_methods else 'unknown'
        if auth_required is True:
            detail = f'Port {e.args.target.port}, AUTH advertised ({methods_str}), required for RCPT TO; {probe_detail}'
            return RoleResult('submission', port_hint, True, True, detail)
        elif auth_required is False:
            detail = f'Port {e.args.target.port}, AUTH advertised ({methods_str}), RCPT TO accepted without auth; {probe_detail}'
            return RoleResult('hybrid', port_hint, True, False, detail)
        else:
            detail = f'Port {e.args.target.port}, AUTH advertised ({methods_str}), probe inconclusive; {probe_detail}'
            return RoleResult('indeterminate', port_hint, True, None, detail)
    elif auth_required is False:
        detail = f'Port {e.args.target.port}, no AUTH, RCPT TO accepted without auth; {probe_detail}'
        return RoleResult('mta', port_hint, False, False, detail)
    elif auth_required is True:
        detail = f'Port {e.args.target.port}, no AUTH in EHLO but required for RCPT TO; {probe_detail}'
        return RoleResult('submission', port_hint, False, True, detail)
    else:
        detail = f'Port {e.args.target.port}, no AUTH, probe inconclusive; {probe_detail}'
        return RoleResult('indeterminate', port_hint, False, None, detail)


def _stream_role_result(e) -> None:
    """Print role identification result."""
    pp = e._ptprint_raw
    show = not e.use_json
    if (role_error := e.results.role_error) is not None:
        pp(f'Role identification failed: {role_error}', bullet_type='VULN', condition=show, indent=4)
        return
    role_r = e.results.role
    if role_r is None:
        return
    port = e.args.target.port
    port_labels = {25: 'typical MTA port', 587: 'typical Submission port (STARTTLS)', 465: 'typical Submission port (implicit TLS)', 2525: 'alternative Submission port'}
    port_label = port_labels.get(port, 'non-standard SMTP port')
    pp(f'Port {port} ({port_label})', bullet_type='TITLE', condition=show, indent=4)
    if role_r.auth_advertised:
        _, methods_plain = e._ehlo_has_auth(e.results.info.ehlo if e.results.info else None)
        _, methods_starttls = e._ehlo_has_auth(getattr(e.results.info, 'ehlo_starttls', None) if e.results.info else None)
        methods = sorted(set(methods_plain + methods_starttls))
        methods_str = ', '.join(methods) if methods else 'unknown'
        pp(f'AUTH advertised in EHLO ({methods_str})', bullet_type='TITLE', condition=show, indent=4)
    else:
        pp('AUTH not advertised in EHLO', bullet_type='TITLE', condition=show, indent=4)
    if role_r.auth_required is True:
        pp('RCPT TO requires authentication', bullet_type='TITLE', condition=show, indent=4)
    elif role_r.auth_required is False:
        pp('RCPT TO accepted without authentication', bullet_type='TITLE', condition=show, indent=4)
    if 'greylisting detected' in role_r.detail.lower():
        pp('Greylisting detected (server returned 450/451)', bullet_type='TITLE', condition=show, indent=4)
    role_display = {'mta': ('MTA (Public Mail Server)', 'NOTVULN'), 'submission': ('Submission (Mail Submission Agent)', 'NOTVULN'), 'hybrid': ('Hybrid (MTA + Submission) -- consider separating roles', 'VULN'), 'indeterminate': ('Indeterminate -- could not reliably determine role', 'WARNING')}
    label, bullet = role_display.get(role_r.role, ('Unknown', 'VULN'))
    pp(label, bullet_type=bullet, condition=show, indent=4)


def run(ctx):
    e = ensure_info(ctx, get_commands=True)
    if getattr(e.results, "info_error", None):
        return
    try:
        e.results.role = test_role(e, e.smtp, e.results.info)
    except Exception as ex:
        e.results.role_error = str(ex)
        ctx.out(f"Role identification failed: {ex}", "ERROR", indent=4)
        return
    _stream_role_result(e)
