"""BOMB — mail bomb / rate limiting."""
import ipaddress, queue, shutil, smtplib, socket, ssl, statistics, sys, threading, time

from ..._base import Out
from ..utils.ptprinthelper import get_colored_text

from ..utils.helpers import *
from ..utils.results import *
from ..utils.registry import *

from ._common import eng


__MODULELABEL__ = "Mail Bomb / Rate Limiting Test"
__MODULECODE__ = "BOMB"
__ORDER__ = 230


def _bomb_progress_line_rt(e) -> None:
    """Redraw one terminal line: -bomb progress (non-JSON). Caller should hold bomb lock when updating outcomes.

        Long bars must stay on one physical line: wrapping breaks \\r clears and spams the screen.
        If bomb_count exceeds the terminal width budget, a compact bar (bucketed) + "k/n" suffix is used.
        """
    if e.use_json:
        return
    outcomes = getattr(e, '_bomb_rt_outcomes', None)
    n = int(getattr(e, '_bomb_rt_count', 0) or 0)
    if outcomes is None or n <= 0:
        return
    try:
        term_w = max(40, shutil.get_terminal_size(fallback=(100, 24)).columns)
    except (OSError, AttributeError, ValueError):
        term_w = 100
    prefix = f"    {get_colored_text('[*]', 'INFO')} Progress: "
    completed = sum((1 for o in outcomes if o is not None))
    budget_1to1 = max(8, term_w - 34)
    if n <= budget_1to1:
        parts: list[str] = []
        for i in range(n):
            o = outcomes[i]
            if o is None:
                parts.append('░')
            elif o:
                parts.append(get_colored_text('█', 'NOTVULN'))
            else:
                parts.append(get_colored_text('█', 'VULN'))
        bar = ''.join(parts)
        line = prefix + bar
    else:
        suffix = f' {completed}/{n}'
        w = max(8, term_w - 34 - len(suffix))
        parts = []
        for j in range(w):
            i0 = j * n // w
            i1 = (j + 1) * n // w
            if i1 <= i0:
                i1 = i0 + 1
            seg = outcomes[i0:i1]
            if any((x is None for x in seg)):
                parts.append('░')
            elif all((x is True for x in seg)):
                parts.append(get_colored_text('█', 'NOTVULN'))
            elif all((x is False for x in seg)):
                parts.append(get_colored_text('█', 'VULN'))
            else:
                parts.append(get_colored_text('▓', 'WARNING'))
        bar = ''.join(parts)
        line = prefix + bar + suffix
    sys.stdout.write('\x1b[2K\r' + line)
    sys.stdout.flush()


def test_bomb(e) -> BombResult:
    """
        Test mail flooding / rate limiting (PTL-SVC-SMTP-BOMB).
        Sends multiple messages and records delivered vs rate-limited vs blocked.
        Never raises – all errors are caught and recorded.
        """
    host = e.args.target.ip
    port = e.args.target.port
    rcpt = str(e.args.rcpt_to).strip()
    mail_from = e.args.mail_from or f'bombtest@{e.fqdn}'
    mail_from = str(mail_from).strip()
    from_name = getattr(e.args, 'from_name', None) or ''
    cc_raw = getattr(e.args, 'cc', None) or ''
    cc_list = [a.strip() for a in cc_raw.split(',') if a.strip()] if cc_raw else []
    requested_count = getattr(e.args, 'bomb_count', 100)
    bomb_count = max(1, int(requested_count))
    bomb_timeout = max(5.0, getattr(e.args, 'bomb_timeout', 60.0))
    bomb_delay = max(0.0, getattr(e.args, 'bomb_delay', 0.0))
    bomb_threads = max(1, min(getattr(e.args, 'bomb_threads', 1), 50))
    bomb_randomize = getattr(e.args, 'bomb_randomize', False)
    socket_timeout = 10.0
    _ssl_ctx = ssl._create_unverified_context()
    use_tls = e.args.tls or port == 465
    use_starttls = e.args.starttls and (not use_tls)
    if bomb_threads > 10 and (use_tls or use_starttls) and (not e.use_json):
        e.ptprint('[!] Warning: High thread count with TLS may cause client-side CPU bottlenecking. Results might be skewed.', Out.TEXT)
    counters = {'delivered': 0, 'rate_limited': 0, 'blocked': 0, 'connection_lost': 0}
    first_rejection_at: list[int | None] = [None]
    sample_test_id_ref: list[str] = ['']
    last_error_ref: list[str] = ['']
    last_error_type_ref: list[str] = ['']
    smtp_trace: list[str] = []
    response_times: list[float] = []
    tarpitting_detected = False
    lock = threading.Lock()
    start_time = time.perf_counter()
    outcomes: list[bool | None] = [None] * bomb_count
    abort_500 = threading.Event()
    abort_at_ref: list[int | None] = [None]
    e._bomb_rt_outcomes = outcomes
    e._bomb_rt_count = bomb_count
    e._mail_bomb_live_progress_completed = False
    auth_used_ref = [False]
    if not e.use_json:
        _bomb_progress_line_rt(e)

    def _connect_bomb() -> tuple[smtplib.SMTP | smtplib.SMTP_SSL | None, str]:
        """Returns (smtp, error). On success: (smtp, ""). On failure: (None, str(e))."""
        try:
            if use_tls:
                try:
                    ipaddress.ip_address(host)
                    _sni = None
                except ValueError:
                    _sni = host
                sock = socket.create_connection((host, port), timeout=socket_timeout)
                sock_ssl = _ssl_ctx.wrap_socket(sock, server_hostname=_sni)
                smtp = smtplib.SMTP(timeout=socket_timeout)
                smtp.sock = sock_ssl
                smtp.file = None
                status, _ = smtp.getreply()
                if status != 220:
                    return (None, f'Connect: {status}')
                return (smtp, '')
            smtp = smtplib.SMTP(timeout=socket_timeout)
            status, _ = smtp.connect(host, port)
            if status != 220:
                return (None, f'Connect: {status}')
            if use_starttls:
                st_status, _ = smtp.docmd('STARTTLS')
                if st_status != 220:
                    return (None, f'STARTTLS: {st_status}')
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
            return (None, str(ex))

    def _send_one(idx: int) -> tuple[str, int | str | None, str]:
        """Returns (reason, status_or_error, error_type). For connection_lost, error_type is classification."""
        msg_test_id = e._new_mail_test_id()
        rid = msg_test_id[:8] if bomb_randomize else ''
        subject = e._outbound_subject()
        if rid:
            subject = f'{subject} [{rid[:4]}]'
        elif bomb_count > 1:
            subject = f'{subject} {idx}'
        body = e._outbound_data() + (f' Id:{rid[:4]}' if rid else '')
        from_hdr = f'"{from_name}" <{mail_from}>' if from_name else f'<{mail_from}>'
        to_hdr = f'<{rcpt}>'
        cc_hdr = ', '.join((f'<{c}>' for c in cc_list)) if cc_list else ''
        headers = [f'From: {from_hdr}', f'To: {to_hdr}']
        if cc_hdr:
            headers.append(f'Cc: {cc_hdr}')
        headers.extend([f'Subject: {subject}', f'{EMAIL_HDR_TEST_ID}: {msg_test_id}', 'Date: ' + time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime())])
        msg = '\r\n'.join(headers) + '\r\n\r\n' + body + '\r\n'
        recipients = [rcpt] + cc_list
        smtp, conn_err = _connect_bomb()
        if smtp is None:
            err_type, err_msg = _classify_connection_error(Exception(conn_err or 'Connection failed'))
            return ('connection_lost', err_msg, err_type)
        try:
            ehlo_s, _ = smtp.docmd('EHLO', e.fqdn or 'bomb-test.local')
            if ehlo_s == 500:
                return ('fatal_500', 500, '')
            used_auth, auth_err = e._mail_test_auth_login(smtp, smtp_trace)
            if auth_err:
                return ('not_tested', auth_err, 'auth_failed')
            if used_auth:
                with lock:
                    auth_used_ref[0] = True
            mail_s, mail_reply = smtp.docmd('MAIL', f'FROM:<{mail_from}>')
            if mail_s == 500:
                return ('fatal_500', 500, '')
            if mail_s not in (250, 251):
                return ('not_tested', e._smtp_trace_reply(mail_s, mail_reply), 'before_data')
            status, reply = smtp.docmd('RCPT', f'TO:<{rcpt}>')
            if status == 500:
                return ('fatal_500', 500, '')
            if status not in (250, 251):
                return ('not_tested', e._smtp_trace_reply(status, reply), 'before_data')
            for c in cc_list:
                s, cc_reply = smtp.docmd('RCPT', f'TO:<{c}>')
                if s == 500:
                    return ('fatal_500', 500, '')
                if s not in (250, 251):
                    return ('not_tested', e._smtp_trace_reply(s, cc_reply), 'before_data')
            data_status, data_reply = smtp.data(msg)
            if data_status == 500:
                return ('fatal_500', 500, '')
            if data_status == 250:
                if e.args.debug and (not e.use_json):
                    if not any((x.startswith('DATA:') for x in smtp_trace)):
                        e._mail_test_trace_append(smtp_trace, e._data_trace_entry(msg, data_status, data_reply))
                with lock:
                    if not sample_test_id_ref[0]:
                        sample_test_id_ref[0] = msg_test_id
                return ('delivered', 250, '')
            if 400 <= data_status < 500:
                return ('rate_limited', data_status, '')
            return ('blocked', data_status, '')
        except smtplib.SMTPResponseException as ex:
            if ex.smtp_code == 500:
                return ('fatal_500', 500, '')
            if 400 <= ex.smtp_code < 500:
                return ('rate_limited', ex.smtp_code, '')
            return ('blocked', ex.smtp_code, '')
        except (smtplib.SMTPServerDisconnected, ConnectionResetError, BrokenPipeError, OSError, socket.timeout) as ex:
            err_type, err_msg = _classify_connection_error(ex)
            return ('connection_lost', err_msg, err_type)
        except Exception as ex:
            err_type, err_msg = _classify_connection_error(ex)
            return ('connection_lost', err_msg, err_type)
        finally:
            try:
                smtp.quit()
            except Exception:
                pass

    def _bomb_drain_queue(queue_in: queue.Queue) -> None:
        while True:
            try:
                queue_in.get_nowait()
            except queue.Empty:
                return
            queue_in.task_done()

    def _worker(queue_in: queue.Queue) -> None:
        while True:
            if abort_500.is_set():
                _bomb_drain_queue(queue_in)
                return
            try:
                idx = queue_in.get_nowait()
            except queue.Empty:
                return
            if time.perf_counter() - start_time > bomb_timeout:
                queue_in.task_done()
                return
            if abort_500.is_set():
                queue_in.task_done()
                return
            if bomb_delay > 0:
                time.sleep(bomb_delay)
            if abort_500.is_set():
                queue_in.task_done()
                return
            t0 = time.perf_counter()
            reason, status_or_err, err_type = _send_one(idx)
            elapsed_msg = time.perf_counter() - t0
            with lock:
                response_times.append(elapsed_msg)
                ok = reason == 'delivered'
                outcomes[idx - 1] = ok
                if reason == 'delivered':
                    counters['delivered'] += 1
                elif reason == 'rate_limited':
                    counters['rate_limited'] += 1
                    if first_rejection_at[0] is None:
                        first_rejection_at[0] = idx
                elif reason == 'blocked':
                    counters['blocked'] += 1
                    if first_rejection_at[0] is None:
                        first_rejection_at[0] = idx
                elif reason == 'fatal_500':
                    counters['blocked'] += 1
                    if first_rejection_at[0] is None:
                        first_rejection_at[0] = idx
                    abort_at_ref[0] = idx
                    smtp_trace.append(f'SMTP 500 at msg {idx} — test stopped (no further messages)')
                    abort_500.set()
                elif reason == 'not_tested':
                    counters['connection_lost'] += 1
                    if first_rejection_at[0] is None:
                        first_rejection_at[0] = idx
                    last_error_ref[0] = str(status_or_err) if status_or_err else 'rejected before DATA'
                    last_error_type_ref[0] = err_type or 'before_data'
                else:
                    counters['connection_lost'] += 1
                    if first_rejection_at[0] is None:
                        first_rejection_at[0] = idx
                    err_str = str(status_or_err) if status_or_err else 'connection lost'
                    last_error_ref[0] = err_str
                    last_error_type_ref[0] = err_type or 'other'
                if not e.use_json:
                    _bomb_progress_line_rt(e)
            queue_in.task_done()
            if reason == 'fatal_500':
                return
    msg_queue: queue.Queue = queue.Queue()
    for i in range(1, bomb_count + 1):
        msg_queue.put(i)
    workers: list[threading.Thread] = []
    for _ in range(bomb_threads):
        t = threading.Thread(target=_worker, args=(msg_queue,))
        t.daemon = True
        t.start()
        workers.append(t)
    try:
        for t in workers:
            t.join(timeout=bomb_timeout + 5)
    finally:
        if not e.use_json:
            try:
                _bomb_progress_line_rt(e)
            except Exception:
                pass
            sys.stdout.write('\n')
            sys.stdout.flush()
            e._mail_bomb_live_progress_completed = True
    elapsed = time.perf_counter() - start_time
    delivered = counters['delivered']
    rate_limited = counters['rate_limited']
    blocked = counters['blocked']
    connection_lost = counters['connection_lost']
    sent = sum((1 for o in outcomes if o is not None))
    first_rej = first_rejection_at[0]
    per_message_delivered = tuple((o for o in outcomes if o is not None))
    aborted_500 = abort_at_ref[0] is not None
    avg_rtt_ms: float | None = None
    if len(response_times) >= 8:
        n = len(response_times)
        quarter = max(1, n // 4)
        first_avg = statistics.mean(response_times[:quarter])
        last_avg = statistics.mean(response_times[-quarter:])
        avg_rtt_ms = statistics.mean(response_times) * 1000.0
        if last_avg > 5.0 * first_avg and last_avg > 1.0 and (first_avg > 0.001):
            tarpitting_detected = True
    ratio = delivered / sent if sent > 0 else 0.0
    rate_or_blocked = rate_limited > 0 or blocked > 0
    # Connection loss or a reject before DATA means the volume was not tested.
    # Those runs stay indeterminate even when some other attempts were blocked.
    indeterminate = delivered == 0 and (connection_lost > 0 or (rate_limited == 0 and blocked == 0))
    vulnerable = ratio > 0.95 and sent >= 100
    partial_protection = not vulnerable and (0.1 < ratio <= 0.95 and sent >= 50 or (rate_or_blocked and first_rej is not None and (first_rej > 50)))
    detail_parts = [f'{delivered}/{sent} delivered']
    if rate_limited:
        detail_parts.append(f'{rate_limited} rate-limited (4xx)')
    if blocked:
        detail_parts.append(f'{blocked} blocked (5xx)')
    if connection_lost:
        detail_parts.append(f'{connection_lost} connection_lost')
    if partial_protection:
        detail_parts.append(f'partial protection (first rejection at msg {first_rej})')
    if aborted_500 and abort_at_ref[0] is not None:
        detail_parts.append(f'stopped early (SMTP 500 at msg {abort_at_ref[0]})')
    bomb_detail = '; '.join(detail_parts)
    return BombResult(vulnerable=vulnerable, indeterminate=indeterminate, partial_protection=partial_protection, sent=sent, delivered=delivered, rate_limited=rate_limited, blocked=blocked, connection_lost=connection_lost, first_rejection_at=first_rej, elapsed_sec=elapsed, tarpitting_detected=tarpitting_detected, last_error=last_error_ref[0] or '', last_error_type=last_error_type_ref[0] or '', avg_rtt_ms=avg_rtt_ms, smtp_trace=tuple(smtp_trace[-50:]), per_message_delivered=per_message_delivered, aborted_on_smtp_500=aborted_500, abort_at_message=abort_at_ref[0], auth_used=auth_used_ref[0], detail=bomb_detail, sample_test_id=sample_test_id_ref[0])


def _stream_mail_bomb_result(e) -> None:
    pp = e._ptprint_raw
    show = not e.use_json
    if (err := e.results.mail_bomb_error) is not None:
        pp(f'Mail bomb test failed: {err}', bullet_type='VULN', condition=show, indent=4)
        return
    mb = e.results.mail_bomb
    if mb is None or not show:
        return
    extra_lines: list[str] = [f'sent={mb.sent} delivered={mb.delivered} rate_limited={mb.rate_limited} blocked={mb.blocked}']
    if mb.avg_rtt_ms is not None:
        extra_lines.append(f'Avg response time: {mb.avg_rtt_ms:.0f} ms')
    if mb.last_error:
        type_hint = f' [{mb.last_error_type}]' if mb.last_error_type else ''
        extra_lines.append(f'Last connection error{type_hint}: {mb.last_error}')
    if mb.vulnerable:
        extra_lines.append('Server accepted large volume without rate limiting.')
    verdict: tuple[str, str] | None
    if mb.indeterminate:
        verdict = ('WARNING', 'Indeterminate')
    elif mb.vulnerable:
        verdict = ('VULN', 'No rate limiting')
    elif mb.partial_protection:
        verdict = ('WARNING', 'Partial protection')
    else:
        verdict = ('NOTVULN', 'Mail bomb not confirmed')
    e._pp_av_summary_block(pp, show=show, detail=mb.detail, elapsed_sec=mb.elapsed_sec, extra_lines=tuple(extra_lines), verdict=verdict)


def run(ctx):
    e = eng(ctx)
    e.args.bomb = True
    try:
        e.results.mail_bomb = test_bomb(e)
    except Exception as ex:
        e.results.mail_bomb_error = str(ex)
        ctx.out(f"BOMB failed: {ex}", "ERROR", indent=4)
        return
    _stream_mail_bomb_result(e)
