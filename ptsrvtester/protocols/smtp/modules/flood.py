"""FLOOD — queue flood."""
import ipaddress, queue, shutil, smtplib, socket, ssl, statistics, sys, threading, time

from ..._base import Out
from ..utils.ptprinthelper import get_colored_text

from ..utils.helpers import *
from ..utils.results import *
from ..utils.registry import *

from ._common import eng


__MODULELABEL__ = "Queue Flood Test"
__MODULECODE__ = "FLOOD"
__ORDER__ = 240

# Declaration only. The body is never this large.
_DECLARED_SIZE = 1024 ** 4
# One follow-up body when EHLO gives no fixed maximum. Above the RFC 5321 64 KiB minimum.
_BODY_PROBE = 128 * 1024
# Do not upload more than this to prove a limit. A larger over-limit body is described, not sent.
_BODY_CAP = 2 * 1024 * 1024


def _bytes_phrase(n: int) -> str:
    if n == 1024 ** 4:
        return f"1 TiB ({n} bytes)"
    if n >= 1024 * 1024 and n % (1024 * 1024) == 0:
        return f"{n} bytes ({n // (1024 * 1024)} MiB)"
    if n >= 1024 and n % 1024 == 0:
        return f"{n} bytes ({n // 1024} KiB)"
    return f"{n} bytes"


def _messages(n: int) -> str:
    return "1 message" if n == 1 else f"{n} messages"


def _attempts(n: int) -> str:
    return "1 attempt" if n == 1 else f"{n} attempts"


def _clean(text: str) -> str:
    return (text or "").strip().rstrip(".")


def _note(kind: str, text: str) -> str:
    return f"{kind}|{text}"


def test_flood(e) -> FloodResult:
    """
        Test FLOOD – queue overload, SIZE extension (PTL-SVC-SMTP-FLOOD).
        Phases: SIZE_CHECK, SIZE_ENFORCEMENT, QUEUE_STRESS.
        Panic stop on 421; secure on 452.
        """
    host = e.args.target.ip
    port = e.args.target.port
    mail_from = e.args.mail_from or f'floodtest@{e.fqdn}'
    mail_from = str(mail_from).strip()
    rcpt = getattr(e.args, 'rcpt_to', None)
    rcpt = str(rcpt).strip() if rcpt else None
    flood_count = max(1, min(getattr(e.args, 'flood_count', 150), 500))
    flood_timeout = max(10.0, getattr(e.args, 'flood_timeout', 90.0))
    skip_size_test = getattr(e.args, 'flood_skip_size_test', False)
    start_time = time.perf_counter()
    smtp_trace: list[str] = []
    auth_used = False
    _ssl_ctx = ssl._create_unverified_context()
    use_tls = e.args.tls or port == 465
    use_starttls = e.args.starttls and (not use_tls)

    def _connect_flood() -> tuple[smtplib.SMTP | smtplib.SMTP_SSL | None, str]:
        try:
            if use_tls:
                sock = socket.create_connection((host, port), timeout=15)
                try:
                    ipaddress.ip_address(host)
                    _sni = None
                except ValueError:
                    _sni = host
                sock_ssl = _ssl_ctx.wrap_socket(sock, server_hostname=_sni)
                smtp = smtplib.SMTP(timeout=15)
                smtp.sock = sock_ssl
                smtp.file = None
                st, reply = smtp.getreply()
                e._mail_test_trace_append(smtp_trace, f'Connect: {e._smtp_trace_reply(st, reply)}')
                if st != 220:
                    return (None, e._smtp_trace_reply(st, reply))
                return (smtp, '')
            smtp = smtplib.SMTP(timeout=15)
            st, reply = smtp.connect(host, port)
            e._mail_test_trace_append(smtp_trace, f'Connect: {e._smtp_trace_reply(st, reply)}')
            if st != 220:
                return (None, e._smtp_trace_reply(st, reply))
            if use_starttls:
                st2, reply2 = smtp.docmd('STARTTLS')
                e._mail_test_trace_append(smtp_trace, f'STARTTLS: {e._smtp_trace_reply(st2, reply2)}')
                if st2 != 220:
                    return (None, e._smtp_trace_reply(st2, reply2))
                try:
                    ipaddress.ip_address(host)
                    _sni = None
                except ValueError:
                    _sni = host
                sock_ssl = _ssl_ctx.wrap_socket(smtp.sock, server_hostname=_sni)
                smtp.sock = sock_ssl
                smtp.file = None
                smtp.helo_resp = None
                smtp.ehlo_resp = None
                smtp.esmtp_features = {}
                smtp.does_esmtp = False
            return (smtp, '')
        except Exception as ex:
            e._mail_test_trace_append(smtp_trace, f'Connect: {ex}')
            return (None, str(ex))
    smtp, conn_err = _connect_flood()
    if smtp is None:
        detail = f'Connection failed: {conn_err}'
        return FloodResult(vulnerable=False, indeterminate=True, partial_protection=False, size_advertised=False, size_limit_bytes=None, size_enforced=None, messages_sent=0, messages_accepted=0, messages_rejected=0, first_rejection_at=None, tarpitting_detected=False, elapsed_sec=time.perf_counter() - start_time, smtp_trace=tuple(smtp_trace), queue_attempts=0, flood_notes=(_note('WARN', detail),), auth_used=False, detail=detail)
    ehlo_name = e.fqdn or 'flood-test.local'
    try:
        ehlo_st, ehlo_raw = smtp.ehlo(ehlo_name)
    except Exception as ex:
        e._smtp_vv_io(f'EHLO {ehlo_name}', str(ex))
        smtp_trace.append(f'EHLO: {ex}')
        ehlo_str = ''
        try:
            smtp.quit()
        except Exception:
            pass
        return FloodResult(vulnerable=False, indeterminate=True, partial_protection=False, size_advertised=False, size_limit_bytes=None, size_enforced=None, messages_sent=0, messages_accepted=0, messages_rejected=0, first_rejection_at=None, tarpitting_detected=False, elapsed_sec=time.perf_counter() - start_time, smtp_trace=tuple(smtp_trace), queue_attempts=0, flood_notes=(_note('WARN', f'EHLO failed: {ex}'),), auth_used=False, detail=f'EHLO failed: {ex}')
    else:
        ehlo_reply = e._smtp_trace_reply(ehlo_st, ehlo_raw)
        e._smtp_vv_io(f'EHLO {ehlo_name}', ehlo_reply)
        smtp_trace.append(f'EHLO: {ehlo_reply}')
        ehlo_str = ehlo_raw.decode(errors='replace') if isinstance(ehlo_raw, bytes) else str(ehlo_raw or '')
        used_auth, auth_err = e._mail_test_auth_login(smtp, smtp_trace)
        if auth_err:
            try:
                smtp.quit()
            except Exception:
                pass
            elapsed = time.perf_counter() - start_time
            return FloodResult(vulnerable=False, indeterminate=True, partial_protection=False, size_advertised=False, size_limit_bytes=None, size_enforced=None, messages_sent=0, messages_accepted=0, messages_rejected=0, first_rejection_at=None, tarpitting_detected=False, elapsed_sec=elapsed, smtp_trace=tuple(smtp_trace), queue_attempts=0, flood_notes=(_note('WARN', auth_err),), auth_used=False, detail=auth_err)
        if used_auth:
            auth_used = True
        keyword, raw_limit = _size_offer_from_ehlo(ehlo_str)
    size_limit_bytes = raw_limit if isinstance(raw_limit, int) else None
    size_advertised = bool(size_limit_bytes)
    e._flood_phases_streamed = not e.use_json
    evidence: list[str] = []
    if size_advertised:
        ehlo_fact = f'advertises a fixed maximum of {_bytes_phrase(size_limit_bytes)}'
    elif keyword and raw_limit == 0:
        ehlo_fact = 'offers SIZE 0, which means no fixed maximum'
    elif keyword:
        ehlo_fact = 'offers SIZE with no byte limit, so no fixed maximum is advertised'
    else:
        ehlo_fact = 'does not offer the SIZE extension'
    e._mail_test_live_done('EHLO', ehlo_fact)
    evidence.append(f'EHLO {ehlo_fact}.')
    decl_status: int | None = None
    decl_text = ''
    if skip_size_test:
        e._mail_test_live_done('Size check', 'skipped (--flood-skip-size-test)')
        evidence.append('The SIZE check was skipped.')
    elif keyword:
        try:
            decl_status, decl_reply = smtp.docmd('MAIL', f'FROM:<{mail_from}> SIZE={_DECLARED_SIZE}')
            decl_text = e._smtp_trace_reply(decl_status, decl_reply)
            e._smtp_vv_io(f'MAIL FROM:<{mail_from}> SIZE={_DECLARED_SIZE}', decl_text)
            smtp_trace.append(f'MAIL SIZE: {decl_text}')
            if decl_status in (250, 251):
                try:
                    rset_st, rset_reply = smtp.docmd('RSET')
                    e._smtp_vv_io('RSET', e._smtp_trace_reply(rset_st, rset_reply))
                except Exception as ex:
                    e._smtp_vv_io('RSET', str(ex))
        except Exception as ex:
            decl_text = str(ex)
            e._smtp_vv_io(f'MAIL FROM:<{mail_from}> SIZE={_DECLARED_SIZE}', decl_text)
        if decl_status in (250, 251):
            decl_line = f'accepted ({decl_text}). The server agreed to a {_bytes_phrase(_DECLARED_SIZE)} message'
        elif decl_status == 552:
            decl_line = f'refused ({decl_text}). The limit is enforced before the message body'
        elif decl_status is not None and 500 <= decl_status <= 599:
            decl_line = f'refused ({decl_text})'
        elif decl_status == 452:
            decl_line = f'refused for now ({decl_text})'
        elif decl_status == 421:
            decl_line = f'stopped ({decl_text})'
        elif decl_status is None:
            decl_line = f'failed ({decl_text})'
        else:
            decl_line = f'answered ({decl_text})'
        e._mail_test_live_done('MAIL SIZE=1 TiB', decl_line)
        evidence.append(f'MAIL SIZE=1 TiB was {decl_line}.')
    else:
        e._mail_test_live_done('MAIL SIZE=1 TiB', 'not sent. EHLO does not offer SIZE, so this parameter would not show a limit')
        evidence.append('MAIL SIZE= was not sent, because EHLO does not offer SIZE.')
    try:
        smtp.quit()
    except Exception:
        pass
    body_status: int | None = None
    body_text = ''
    body_len = 0
    over_limit_body = False
    skipped_body = ''
    if not skip_size_test:
        if decl_status == 421:
            skipped_body = f'not sent. The SIZE declaration stopped on 421 ({decl_text})'
        elif keyword and size_advertised and decl_status in (250, 251):
            body_len = int(size_limit_bytes) + 1024
            over_limit_body = True
        elif keyword and (not size_advertised) and decl_status in (250, 251):
            body_len = _BODY_PROBE
        elif not keyword:
            body_len = _BODY_PROBE
        elif keyword and not (decl_status is not None and decl_status >= 500):
            skipped_body = 'not sent. The SIZE declaration did not complete'
        if body_len > _BODY_CAP:
            skipped_body = f'not sent. A body over the advertised limit would be {_bytes_phrase(body_len)}, above the {_bytes_phrase(_BODY_CAP)} cap for this probe'
            body_len = 0
        if body_len and (not rcpt):
            skipped_body = 'not sent. No recipient (-r) was given'
            body_len = 0
        if skipped_body:
            e._mail_test_live_done('Large message', skipped_body)
            evidence.append(f'Large message was {skipped_body}.')
    flood_test_id = e._new_mail_test_id() if rcpt else ''
    any_accepted = False
    rate_before_queue = ''

    def _message(body: str) -> str:
        return f'From: <{mail_from}>\r\nTo: <{rcpt}>\r\nSubject: {e._outbound_subject()}\r\n{EMAIL_HDR_TEST_ID}: {flood_test_id}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\n{body}\r\n'

    def _send_data(raw_msg: str) -> tuple[int | None, str]:
        nonlocal auth_used
        smtp2, err = _connect_flood()
        if smtp2 is None:
            return (None, err)
        try:
            st, reply = smtp2.docmd('EHLO', ehlo_name)
            text = e._smtp_trace_reply(st, reply)
            e._smtp_vv_io(f'EHLO {ehlo_name}', text)
            smtp_trace.append(f'EHLO: {text}')
            if st != 250:
                return (None, text)
            used, auth_err2 = e._mail_test_auth_login(smtp2, smtp_trace)
            if auth_err2:
                return (None, auth_err2)
            if used:
                auth_used = True
            mail_st, mail_reply = smtp2.docmd('MAIL', f'FROM:<{mail_from}>')
            mail_text = e._smtp_trace_reply(mail_st, mail_reply)
            e._mail_test_trace_append(smtp_trace, f'MAIL FROM <{mail_from}>: {mail_text}')
            if mail_st not in (250, 251):
                return (mail_st, mail_text)
            rcpt_st, rcpt_reply = smtp2.docmd('RCPT', f'TO:<{rcpt}>')
            rcpt_text = e._smtp_trace_reply(rcpt_st, rcpt_reply)
            e._mail_test_trace_append(smtp_trace, f'RCPT TO <{rcpt}>: {rcpt_text}')
            if rcpt_st not in (250, 251):
                return (rcpt_st, rcpt_text)
            data_st, data_reply = smtp2.data(raw_msg)
            data_text = e._smtp_trace_reply(data_st, data_reply)
            e._smtp_vv_io('DATA', data_text)
            smtp_trace.append(f'DATA: {data_text}')
            return (data_st, data_text)
        except smtplib.SMTPResponseException as ex:
            text = e._smtp_trace_reply(ex.smtp_code, ex.smtp_error)
            e._smtp_vv_io('DATA', text)
            return (ex.smtp_code, text)
        except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError, socket.timeout) as ex:
            e._smtp_vv_io('DATA', str(ex))
            return (None, str(ex))
        finally:
            try:
                smtp2.quit()
            except Exception:
                pass
    if body_len and rcpt:
        body_status, body_text = _send_data(_message('X' * body_len))
        if body_status == 250:
            any_accepted = True
            body_line = f'sent {_bytes_phrase(body_len)}. The server accepted it ({body_text})'
        elif body_status is not None and body_status >= 500:
            body_line = f'sent {_bytes_phrase(body_len)}. The server refused it ({body_text})'
        else:
            body_line = f'not completed ({body_text})'
        if (body_text or '').startswith('421') or body_status == 421:
            rate_before_queue = body_text or '421'
        e._mail_test_live_done('Large message', body_line)
        evidence.append(f'Large message: {body_line}.')
    panic_421 = bool(rate_before_queue) or decl_status == 421
    secure_452 = False
    stop_text = rate_before_queue or (decl_text if decl_status == 421 else '')
    hit_timeout = False
    min_body = 'X' * 10
    near_size_body_len = min(int((size_limit_bytes or 26214400) * 0.8), 10 * 1024 * 1024) if size_limit_bytes else 10240
    rtts: list[float] = []
    sent, accepted, rejected = (0, 0, 0)
    queue_attempts = 0
    first_rejection_at: int | None = None
    probe_len = body_len
    deadline = start_time + flood_timeout
    run_queue = bool(rcpt) and not rate_before_queue and decl_status != 421
    for idx in range(flood_count if run_queue else 0):
        if time.perf_counter() > deadline:
            hit_timeout = True
            break
        queue_attempts += 1
        queue_body_len = near_size_body_len if idx % 3 == 1 and size_advertised else len(min_body)
        body = 'X' * queue_body_len
        msg = f'From: <{mail_from}>\r\nTo: <{rcpt}>\r\nSubject: {e._outbound_subject()}\r\n{EMAIL_HDR_TEST_ID}: {flood_test_id}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\n{body}\r\n'
        smtp2, conn_err = _connect_flood()
        if smtp2 is None:
            rejected += 1
            if first_rejection_at is None:
                first_rejection_at = queue_attempts
            stop_text = conn_err
            if conn_err.startswith('421'):
                panic_421 = True
            elif conn_err.startswith('452'):
                secure_452 = True
            break
        try:
            ehlo_st, ehlo_reply = smtp2.docmd('EHLO', ehlo_name)
            ehlo_text = e._smtp_trace_reply(ehlo_st, ehlo_reply)
            e._smtp_vv_io(f'EHLO {ehlo_name}', ehlo_text)
            smtp_trace.append(f'EHLO: {ehlo_text}')
            used_auth, auth_err = e._mail_test_auth_login(smtp2, smtp_trace)
            if auth_err:
                e._mail_test_trace_append(smtp_trace, f'QUEUE_STRESS: {auth_err}')
                try:
                    smtp2.quit()
                except Exception:
                    pass
                continue
            if used_auth:
                auth_used = True
            mail_st, mail_reply = smtp2.docmd('MAIL', f'FROM:<{mail_from}>')
            e._mail_test_trace_append(smtp_trace, f'MAIL FROM <{mail_from}>: {e._smtp_trace_reply(mail_st, mail_reply)}')
            if mail_st not in (250, 251):
                rejected += 1
                if first_rejection_at is None:
                    first_rejection_at = queue_attempts
                stop_text = e._smtp_trace_reply(mail_st, mail_reply)
                if mail_st == 421:
                    panic_421 = True
                    break
                if mail_st == 452:
                    secure_452 = True
                    break
                try:
                    smtp2.quit()
                except Exception:
                    pass
                continue
            rcpt_st, rcpt_reply = smtp2.docmd('RCPT', f'TO:<{rcpt}>')
            e._mail_test_trace_append(smtp_trace, f'RCPT TO <{rcpt}>: {e._smtp_trace_reply(rcpt_st, rcpt_reply)}')
            if rcpt_st not in (250, 251):
                rejected += 1
                if first_rejection_at is None:
                    first_rejection_at = queue_attempts
                stop_text = e._smtp_trace_reply(rcpt_st, rcpt_reply)
                if rcpt_st == 421:
                    panic_421 = True
                    break
                if rcpt_st == 452:
                    secure_452 = True
                    break
                try:
                    smtp2.quit()
                except Exception:
                    pass
                continue
            t0 = time.perf_counter()
            data_status, data_reply = smtp2.data(msg)
            e._smtp_vv_io('DATA', e._smtp_trace_reply(data_status, data_reply))
            smtp_trace.append(f'QUEUE_STRESS: DATA {e._smtp_trace_reply(data_status, data_reply)}')
            rtt = time.perf_counter() - t0
            rtts.append(rtt)
            sent += 1
            if data_status == 250:
                accepted += 1
                any_accepted = True
            else:
                rejected += 1
                if first_rejection_at is None:
                    first_rejection_at = queue_attempts
                stop_text = e._smtp_trace_reply(data_status, data_reply)
                if data_status == 421:
                    panic_421 = True
                    break
                if data_status == 452:
                    secure_452 = True
                    break
        except smtplib.SMTPResponseException as ex:
            text = e._smtp_trace_reply(ex.smtp_code, ex.smtp_error)
            e._smtp_vv_io('DATA', text)
            rejected += 1
            if first_rejection_at is None:
                first_rejection_at = queue_attempts
            stop_text = text
            if ex.smtp_code == 421:
                panic_421 = True
            elif ex.smtp_code == 452:
                secure_452 = True
            break
        except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError, socket.timeout) as ex:
            rejected += 1
            if first_rejection_at is None:
                first_rejection_at = queue_attempts
            stop_text = str(ex)
            e._smtp_vv_io('(connection)', str(ex))
            break
        try:
            smtp2.quit()
        except Exception:
            pass
    tarpitting_detected = False
    if len(rtts) >= 5:
        first_half = sum(rtts[:len(rtts) // 2]) / (len(rtts) // 2)
        last_half = sum(rtts[-len(rtts) // 2:]) / (len(rtts) // 2)
        if last_half > first_half * 2.0:
            tarpitting_detected = True
    if not rcpt:
        q_fact = 'not tested. No recipient (-r) was given'
    elif not run_queue:
        why = rate_before_queue or decl_text or '421'
        q_fact = f'not started. An earlier connection was refused ({_clean(why)})'
    elif hit_timeout:
        q_fact = f'stopped at the time limit. {_messages(accepted)} accepted out of {flood_count}, {rejected} refused'
    elif panic_421:
        q_fact = f'stopped by 421 after {_messages(accepted)} accepted ({_clean(stop_text)})'
    elif secure_452:
        q_fact = f'stopped by 452, not enough storage, after {_messages(accepted)} accepted ({_clean(stop_text)})'
    else:
        q_fact = f'{_attempts(queue_attempts)}, {_messages(accepted)} accepted, {rejected} refused'
    e._mail_test_live_done('Queue', q_fact)
    evidence.append(f'Queue: {q_fact}.')
    elapsed = time.perf_counter() - start_time
    size_enforced: bool | None = None
    if over_limit_body and body_status == 250:
        size_enforced = False
    elif over_limit_body and body_status is not None and body_status >= 500:
        size_enforced = True
    elif decl_status is not None and decl_status >= 500:
        size_enforced = True
    elif (not keyword) and body_status is not None and body_status >= 500:
        size_enforced = True
    notes: list[str] = []
    if skip_size_test:
        notes.append(_note('WARN', 'Size check was skipped.'))
    elif size_enforced is False:
        notes.append(_note('BAD', f'Server accepted a {_bytes_phrase(probe_len)} message, larger than the advertised limit of {_bytes_phrase(int(size_limit_bytes or 0))}.'))
    elif over_limit_body and body_status is not None and body_status >= 500 and decl_status in (250, 251):
        notes.append(_note('WARN', 'MAIL accepted a 1 TiB declaration, above the advertised limit.'))
        notes.append(_note('OK', f'The message body over that limit was refused ({body_text}).'))
    elif size_enforced is True and decl_status is not None and decl_status >= 500:
        if size_advertised:
            notes.append(_note('OK', 'Size limit is enforced at MAIL.'))
        else:
            notes.append(_note('OK', 'A size limit is enforced at MAIL. EHLO gives no byte limit.'))
    elif (not keyword) and body_status is not None and body_status >= 500:
        notes.append(_note('OK', f'A {_bytes_phrase(probe_len)} message was refused ({body_text}). EHLO does not offer SIZE.'))
    elif keyword and decl_status in (250, 251) and body_status == 250:
        notes.append(_note('WARN', f'Server accepted a 1 TiB size declaration and a {_bytes_phrase(probe_len)} message. No fixed maximum is advertised.'))
    elif keyword and decl_status in (250, 251):
        notes.append(_note('WARN', 'Server accepted a 1 TiB size declaration. No oversized message body was delivered.'))
    elif (not keyword) and body_status == 250:
        notes.append(_note('WARN', f'EHLO does not offer SIZE. A {_bytes_phrase(probe_len)} message was accepted. This shows that this size was delivered, not the largest size the server will take.'))
    elif (not keyword) and (not rcpt):
        notes.append(_note('WARN', 'Size was not tested with a message body. EHLO does not offer SIZE, and no recipient (-r) was given.'))
    elif decl_status == 421 or (body_text or '').startswith('421'):
        notes.append(_note('WARN', f'Size check stopped ({decl_text or body_text}).'))
    else:
        notes.append(_note('WARN', 'Size limit was not fully tested.'))
    queue_flood = run_queue and accepted >= flood_count * 0.9 and (not panic_421) and (not secure_452) and (not tarpitting_detected)
    if not rcpt:
        notes.append(_note('WARN', 'Queue was not tested, because no recipient (-r) was given.'))
    elif not run_queue:
        notes.append(_note('OK', f'Queue was not started. An earlier connection was refused ({_clean(rate_before_queue or decl_text or "421")}).'))
    elif queue_flood:
        notes.append(_note('BAD', f'Queue accepted {_messages(accepted)} out of {flood_count}.'))
    elif panic_421:
        notes.append(_note('OK', f'Queue stopped by 421 after {_messages(accepted)} accepted ({_clean(stop_text)}).'))
    elif secure_452:
        notes.append(_note('OK', f'Queue stopped by 452, not enough storage, after {_messages(accepted)} accepted ({_clean(stop_text)}).'))
    elif tarpitting_detected:
        notes.append(_note('OK', f'Queue slowed down as messages were accepted. {_messages(accepted)} accepted out of {flood_count}.'))
    elif hit_timeout:
        notes.append(_note('WARN', f'Queue hit the time limit. {_messages(accepted)} accepted out of {flood_count}. The flood did not finish.'))
    elif sent == 0 and rejected == 0:
        notes.append(_note('WARN', 'Queue did not complete a message.'))
    else:
        notes.append(_note('OK', f'Queue refused mail before the flood finished. {_messages(accepted)} accepted out of {flood_count}, {rejected} refused.'))
    vulnerable = any(item.startswith('BAD|') for item in notes)
    partial = (not vulnerable) and any(item.startswith('WARN|') for item in notes)
    detail = ' '.join(evidence)
    delivered = any_accepted or accepted > 0
    return FloodResult(vulnerable=vulnerable, indeterminate=False, partial_protection=partial, size_advertised=size_advertised, size_limit_bytes=size_limit_bytes if size_advertised else None, size_enforced=size_enforced, messages_sent=sent, messages_accepted=accepted, messages_rejected=rejected, first_rejection_at=first_rejection_at, tarpitting_detected=tarpitting_detected, elapsed_sec=elapsed, smtp_trace=tuple(smtp_trace), queue_attempts=queue_attempts, flood_notes=tuple(notes), auth_used=auth_used, detail=detail, test_id=flood_test_id if delivered else '')


def _stream_flood_result(e) -> None:
    pp = e._ptprint_raw
    show = not e.use_json
    if (err := e.results.flood_error) is not None:
        pp(f'FLOOD test failed: {err}', bullet_type='VULN', condition=show, indent=4)
        return
    fr = e.results.flood
    if fr is None or not show:
        return
    tagged: list[tuple[str, str]] = []
    plain: list[str] = []
    for note in fr.flood_notes:
        kind, sep, text = note.partition('|')
        if sep and kind in ('OK', 'BAD', 'WARN') and text.strip():
            tagged.append((kind, text.strip()))
        elif note.strip():
            plain.append(note.strip())
    mail_probe: tuple[bool, bool, str | None, str, tuple[str, ...]] | None = None
    if fr.test_id and getattr(e.args, 'rcpt_to', None):
        mail_probe = (True, False, None, e._mail_sent_inbox_msg(str(e.args.rcpt_to).strip(), fr.test_id), ())
    e._pp_av_summary_block(pp, show=show, detail=None, elapsed_sec=fr.elapsed_sec, extra_lines=tuple(plain), verdict=None, mail_probe=mail_probe)
    bullets = {'OK': 'NOTVULN', 'BAD': 'VULN', 'WARN': 'WARNING'}
    for kind, text in tagged:
        pp(text, bullet_type=bullets[kind], condition=show, indent=4)


def run(ctx):
    e = eng(ctx)
    e.args.flood = True
    try:
        e.results.flood = test_flood(e)
    except Exception as ex:
        e.results.flood_error = str(ex)
        ctx.out(f"FLOOD failed: {ex}", "ERROR", indent=4)
        return
    _stream_flood_result(e)
