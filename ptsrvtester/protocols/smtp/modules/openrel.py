"""OPENREL — open relay."""
import secrets, smtplib, socket, sys, threading, time

from ..._base import Out

from ..utils.helpers import *
from ..utils.results import *
from ..utils.registry import *

from ._common import ensure_info


__MODULELABEL__ = "Open relay"
__MODULECODE__ = "OPENREL"
__ORDER__ = 40


def open_relay_test(e, smtp, mail_from, rcpt_to) -> bool:
    """OWASP/Nmap-style multi-vector open relay test. Tests: empty FROM, internal→external,
        external→external, literal IP sender. Returns True if any vector succeeds."""
    verbose = bool(e.args.debug and (not e.args.json))
    ext_domain = 'external.relaytest.local'
    host_domain = e.fqdn or 'relaytest.local'
    target_ip = getattr(e.args.target, 'ip', None) or '127.0.0.1'
    sample_to = rcpt_to or f'relaytest@{ext_domain}'
    sample_from = mail_from or f'relaytest@{host_domain}'
    msg = f'From: <{sample_from}>\r\nTo: <{sample_to}>\r\nSubject: {e._outbound_subject()}\r\n\r\n{e._outbound_data()}\r\n'
    vectors: list[tuple[str, str, str]] = [('MAIL FROM:<> (null sender)', '<>', f'relaytest@{ext_domain}'), (f'relaytest@{host_domain} -> external', f'relaytest@{host_domain}', f'relaytest@{ext_domain}'), (f'relaytest@[{target_ip}] -> external', f'relaytest@[{target_ip}]', f'relaytest@{ext_domain}'), ('external -> external', f'relaytest@{ext_domain}', f'relaytest@other.{ext_domain}')]
    if mail_from and rcpt_to:
        vectors.insert(0, (f'user: {mail_from} -> {rcpt_to}', mail_from, rcpt_to))

    def _reply_one_line(raw: str | bytes, limit: int=160) -> str:
        if isinstance(raw, str):
            s = raw.strip().replace('\r\n', ' ').replace('\n', ' ')
        else:
            s = e.bytes_to_str(raw).strip().replace('\r\n', ' ').replace('\n', ' ')
        return s if len(s) <= limit else s[:limit - 3] + '...'

    def _envelope_addr(addr: str) -> str:
        if addr == '<>':
            return '<>'
        if addr.startswith('<') and addr.endswith('>'):
            return addr
        return f'<{addr}>'

    def _relay_vector(label: str, from_addr: str, to_addr: str) -> bool | None:
        """Run one relay vector. True = open, False = denied, None = timeout/disconnect."""
        mail_env = _envelope_addr(from_addr)
        rcpt_env = _envelope_addr(to_addr)
        try:
            smtp.docmd('RSET')
        except Exception:
            pass
        try:
            mail_status, mail_reply = smtp.docmd('MAIL FROM:', mail_env)
            mail_rep = _reply_one_line(mail_reply)
            e._smtp_vv_io(f'MAIL FROM:{mail_env}', f'{mail_status} {mail_rep}')
            if mail_status not in (250, 251):
                return None if 400 <= mail_status < 500 else False
            rcpt_status, rcpt_reply = smtp.docmd('RCPT TO:', rcpt_env)
            rcpt_rep = _reply_one_line(rcpt_reply)
            e._smtp_vv_io(f'RCPT TO:{rcpt_env}', f'{rcpt_status} {rcpt_rep}')
            if rcpt_status not in (250, 251, 252):
                return None if 400 <= rcpt_status < 500 else False
            data_status, data_reply = smtp.data(msg)
            data_rep = _reply_one_line(data_reply)
            if verbose:
                e._stream_smtp_trace_line(e._data_trace_entry(msg, data_status, data_reply))
            if data_status == 250:
                return True
            return None if 400 <= data_status < 500 else False
        except smtplib.SMTPRecipientsRefused as ex:
            detail = _reply_one_line(str(ex))
            if verbose:
                e.ptdebug(f'Open relay ({label}): RCPT TO:{rcpt_env} → {detail}', Out.INFO)
            else:
                e.ptdebug(f'Relay rejected: {label} — RCPT TO {detail}', Out.INFO)
            return False
        except smtplib.SMTPResponseException as ex:
            code = getattr(ex, 'smtp_code', None)
            err = _reply_one_line(getattr(ex, 'smtp_error', b'') or str(ex))
            transient = isinstance(code, int) and 400 <= code < 500
            if verbose:
                e.ptdebug(f'Open relay ({label}): SMTP [{code}] {err}', Out.INFO)
            elif transient or e._smtp_exc_is_timeout(ex):
                e.ptdebug(f'Open relay ({label}): transient error — [{code}] {err}', Out.INFO)
            else:
                e.ptdebug(f'Relay rejected: {label} — [{code}] {err}', Out.INFO)
            if transient or e._smtp_exc_is_timeout(ex):
                return None
            return False
        except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError, TimeoutError, socket.timeout) as ex:
            detail = _reply_one_line(str(ex))
            if verbose:
                e.ptdebug(f'Open relay ({label}): connection error — {detail}', Out.INFO)
            else:
                e.ptdebug(f'Open relay ({label}): timed out / disconnected — {detail}', Out.INFO)
            return None
        except Exception as ex:
            detail = _reply_one_line(str(ex))
            if verbose:
                e.ptdebug(f'Open relay ({label}): error — {detail}', Out.INFO)
            else:
                e.ptdebug(f'Open relay ({label}): error — {detail}', Out.INFO)
            return None
        try:
            smtp.docmd('RSET')
        except Exception:
            pass
        return False
    incomplete = False
    e.results.open_relay_incomplete = False
    for label, from_addr, to_addr in vectors:
        outcome = _relay_vector(label, from_addr, to_addr)
        if outcome is True:
            return True
        if outcome is None:
            incomplete = True
            try:
                smtp.docmd('RSET')
            except Exception:
                pass
            try:
                smtp.close()
            except Exception:
                pass
                try:
                    smtp, status, _ = e.connect(timeout=15.0, fatal=False)
                    if status == 220:
                        smtp.docmd('EHLO', e.fqdn)
                except Exception as ex:
                    e.ptdebug(f'Open relay: reconnect after timeout failed — {ex}', Out.INFO)
    if incomplete:
        e.results.open_relay_incomplete = True
        e.ptdebug('Open relay not confirmed (timeout, disconnect, or transient SMTP error)', Out.INFO)
        return False
    e.ptdebug('Server is not vulnerable to Open relay', Out.NOTVULN)
    return False


def _stream_open_relay_result(e) -> None:
    pp = e._ptprint_raw
    show = not e.use_json
    if (open_relay_error := e.results.open_relay_error) is not None:
        pp(f'Open relay test failed: {open_relay_error}', bullet_type='VULN', condition=show, indent=4)
        return
    if getattr(e.results, 'open_relay_incomplete', False):
        pp('Open relay not confirmed (timeout, disconnect, or transient SMTP error)', bullet_type='WARNING', condition=show, indent=4)
        return
    if (open_relay := e.results.open_relay) is None:
        return
    if open_relay:
        pp('Open relay is allowed', bullet_type='VULN', condition=show, indent=4)
    else:
        pp('Open relay is denied', bullet_type='NOTVULN', condition=show, indent=4)


def run(ctx):
    e = ensure_info(ctx, get_commands=False)
    if getattr(e.results, "info_error", None):
        return
    mail_from = e.args.mail_from or f"relaytest@{e.fqdn}"
    rcpt_to = e.args.rcpt_to or "relaytest@external.relaytest.local"
    try:
        e.results.open_relay = open_relay_test(e, e.smtp, mail_from, rcpt_to)
    except Exception as ex:
        e.results.open_relay_error = str(ex)
        ctx.out(f"Open relay probe failed: {ex}", "ERROR", indent=4)
        return
    _stream_open_relay_result(e)
