"""BOUNCE — bounce / backscatter replay."""
import ipaddress, random, smtplib, socket, ssl, time
from email.mime.text import MIMEText

from ..utils.helpers import *
from ..utils.results import *
from ..utils.registry import *

from ._common import eng


__MODULELABEL__ = "Bounce Replay Test"
__MODULECODE__ = "BOUNCE"
__ORDER__ = 140


def test_bounce_replay(e) -> BounceReplayResult:
    """
        Bounce / backscatter test (PTL-SVC-SMTP-REPLAY).
        Two probes on one connection: (1) MAIL FROM + DATA with From header only;
        (2) MAIL FROM + DATA including Return-Path header — to observe whether the MTA
        mishandles envelope vs header paths for NDRs. Uses 30s timeout per command.
        When -u/-p (or first line of -U/-P) are set, performs AUTH LOGIN after EHLO before probes.
        """
    host = e.args.target.ip
    port = e.args.target.port
    timeout = 30.0
    _ssl_ctx = ssl._create_unverified_context()
    use_tls = e.args.tls or port == 465
    use_starttls = e.args.starttls and (not use_tls)
    bounce_addr = _bounce_replay_from_addr(e.args)
    if not bounce_addr:
        return BounceReplayResult(vulnerable=False, indeterminate=True, message_accepted=False, rcpt_rejected_in_session=False, bounce_addr='', recipient_used='', test_id='', smtp_trace=(), tarpitting_or_timeout=False, detail='-br requires -m/--mail-from (controlled address for MAIL FROM / bounce checks)', message_accepted_return_path=False, test_id_return_path='')
    bounce_addr = str(bounce_addr).strip()
    test_id = f'{random.getrandbits(32):08x}'
    test_id_rp = f'{random.getrandbits(32):08x}'
    rcpt_raw = getattr(e.args, 'rcpt_to', None) or ''
    recipient = str(rcpt_raw).strip()
    if not recipient:
        return BounceReplayResult(vulnerable=False, indeterminate=True, message_accepted=False, rcpt_rejected_in_session=False, bounce_addr=bounce_addr, recipient_used='', test_id=test_id, smtp_trace=(), tarpitting_or_timeout=False, detail='-br requires -r/--rcpt-to (recipient)', message_accepted_return_path=False, test_id_return_path='')
    msg_id_domain = 'example.com'
    if '@' in bounce_addr:
        msg_id_domain = bounce_addr.split('@', 1)[1].strip()
    if not msg_id_domain or '.' not in msg_id_domain:
        msg_id_domain = 'example.com'

    def _build_body(include_return_path: bool, tid: str) -> str:
        rp = f'Return-Path: <{bounce_addr}>\r\n' if include_return_path else ''
        return f"{rp}From: <{bounce_addr}>\r\nTo: <{recipient}>\r\nSubject: {e._outbound_subject()}\r\n{EMAIL_HDR_TEST_ID}: {tid}\r\nDate: {time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime())}\r\nMessage-ID: <{tid}.{int(time.time())}@{msg_id_domain}>\r\n\r\n{e._outbound_data()}\r\n"

    def _connect_br() -> tuple[smtplib.SMTP | smtplib.SMTP_SSL, int]:
        if use_tls:
            try:
                ipaddress.ip_address(host)
                _sni = None
            except ValueError:
                _sni = host
            sock = socket.create_connection((host, port), timeout=timeout)
            sock_ssl = _ssl_ctx.wrap_socket(sock, server_hostname=_sni)
            smtp = smtplib.SMTP(timeout=timeout)
            smtp.sock = sock_ssl
            smtp.file = None
            status, _ = smtp.getreply()
            return (smtp, status)
        smtp = smtplib.SMTP(timeout=timeout)
        status, _ = smtp.connect(host, port)
        if status != 220:
            return (smtp, status)
        if use_starttls:
            stls_status, _ = smtp.docmd('STARTTLS')
            if stls_status != 220:
                return (smtp, stls_status)
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
        return (smtp, 220)
    smtp_trace: list[str] = []
    e._bounce_replay_streamed_live = False

    def _br_trace_append(line: str) -> None:
        """Store SMTP trace for -br; live -vv lines under probe title (indent 8)."""
        smtp_trace.append(line)
        if e.args.debug and (not e.use_json):
            e._bounce_replay_streamed_live = True
            _br_stream_trace_line(e, line)

    def _br_smtp_reply(status: int, reply) -> str:
        text = e.bytes_to_str(reply).strip().replace('\r\n', ' ').replace('\n', ' ')
        return f'{status} {text}' if text else str(status)

    def _phase(smtp: smtplib.SMTP | smtplib.SMTP_SSL, label: str, body: str) -> tuple[bool, bool, bool, bool, str | None]:
        """Returns (data_accepted_250, rcpt_rejected_5xx, mail_rejected, indeterminate, detail)."""
        _br_trace_append(f'--- {label} ---')
        try:
            mail_status, mail_reply = smtp.docmd('MAIL', f'FROM:<{bounce_addr}>')
            mail_line = _br_smtp_reply(mail_status, mail_reply)
            _br_trace_append(f'MAIL FROM: {mail_line}')
        except socket.timeout:
            _br_trace_append('MAIL FROM: timeout')
            return (False, False, True, True, 'Timeout (30s) on MAIL FROM')
        if mail_status not in (250, 251):
            return (False, False, True, True, f'MAIL FROM rejected before DATA: {mail_line}')
        try:
            rcpt_status, rcpt_reply = smtp.docmd('RCPT', f'TO:<{recipient}>')
            rcpt_line = _br_smtp_reply(rcpt_status, rcpt_reply)
            _br_trace_append(f'RCPT TO: {rcpt_line}')
        except socket.timeout:
            _br_trace_append('RCPT TO: timeout')
            return (False, False, False, True, 'Timeout (30s) on RCPT TO')
        if rcpt_status not in (250, 251):
            return (False, True, False, True, f'RCPT rejected before DATA: {rcpt_line}')
        try:
            data_status, data_reply = smtp.data(body)
            data_line = _br_smtp_reply(data_status, data_reply)
            _br_trace_append(e._data_trace_entry(body, reply=data_line))
        except socket.timeout:
            _br_trace_append('DATA: timeout')
            return (False, False, False, True, 'Timeout (30s) on DATA')
        except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError) as ex:
            _br_trace_append(f'DATA: {ex}')
            return (False, False, False, True, f'Connection closed during DATA: {ex}')
        if data_status == 250:
            return (True, False, False, False, None)
        return (False, False, True, False, f'DATA rejected: {data_line}')
    try:
        smtp, conn_status = _connect_br()
        if conn_status != 220:
            _br_trace_append(f'Connect: {conn_status}')
            try:
                smtp.quit()
            except Exception:
                pass
            return BounceReplayResult(vulnerable=False, indeterminate=True, message_accepted=False, rcpt_rejected_in_session=False, bounce_addr=bounce_addr, recipient_used=recipient, test_id=test_id, smtp_trace=tuple(smtp_trace), tarpitting_or_timeout=False, detail=f'Connection failed: {conn_status}', message_accepted_return_path=False, test_id_return_path='')
        _br_stream_probe_section_title(e, 'Test From header without Return-Path')
        auth_used = False
        try:
            ehlo_status, _ = smtp.docmd('EHLO', e.fqdn or 'bounce-test.local')
            _br_trace_append(f'EHLO: {ehlo_status}')
        except socket.timeout:
            _br_trace_append('EHLO: timeout')
            try:
                smtp.quit()
            except Exception:
                pass
            _br_stream_probe_verdict(e, accepted=False, indeterminate=True, detail='Timeout (30s) on EHLO - possible greylisting or tarpitting (WARNING)', bounce_addr=bounce_addr)
            return BounceReplayResult(vulnerable=False, indeterminate=True, message_accepted=False, rcpt_rejected_in_session=False, bounce_addr=bounce_addr, recipient_used=recipient, test_id=test_id, smtp_trace=tuple(smtp_trace), tarpitting_or_timeout=True, detail='Timeout (30s) on EHLO - possible greylisting or tarpitting (WARNING)', message_accepted_return_path=False, test_id_return_path='')
        br_user, br_pass = e._rl_first_creds()
        if br_user and br_pass:
            try:
                smtp.login(br_user, br_pass)
                auth_used = True
                _br_trace_append(f'AUTH LOGIN: OK ({br_user})')
            except smtplib.SMTPAuthenticationError as ex:
                _br_trace_append(f'AUTH LOGIN: failed ({ex})')
                try:
                    smtp.quit()
                except Exception:
                    pass
                auth_detail = f'AUTH LOGIN failed for {br_user}: {ex}'
                _br_stream_probe_verdict(e, accepted=False, indeterminate=True, detail=auth_detail, bounce_addr=bounce_addr)
                return BounceReplayResult(vulnerable=False, indeterminate=True, message_accepted=False, rcpt_rejected_in_session=False, bounce_addr=bounce_addr, recipient_used=recipient, test_id=test_id, smtp_trace=tuple(smtp_trace), tarpitting_or_timeout=False, detail=auth_detail, message_accepted_return_path=False, test_id_return_path='')
            except (socket.timeout, smtplib.SMTPServerDisconnected, ConnectionResetError, OSError) as ex:
                _br_trace_append(f'AUTH LOGIN: error ({ex})')
                try:
                    smtp.quit()
                except Exception:
                    pass
                auth_detail = f'AUTH LOGIN error for {br_user}: {ex}'
                _br_stream_probe_verdict(e, accepted=False, indeterminate=True, detail=auth_detail, bounce_addr=bounce_addr)
                return BounceReplayResult(vulnerable=False, indeterminate=True, message_accepted=False, rcpt_rejected_in_session=False, bounce_addr=bounce_addr, recipient_used=recipient, test_id=test_id, smtp_trace=tuple(smtp_trace), tarpitting_or_timeout='timeout' in str(ex).lower(), detail=auth_detail, message_accepted_return_path=False, test_id_return_path='')
        body1 = _build_body(include_return_path=False, tid=test_id)
        acc1, rcpt_rej1, mail_rej1, indet1, det1 = _phase(smtp, 'Probe 1: MAIL FROM + DATA (From header; no Return-Path in body)', body1)
        _br_stream_probe_verdict(e, accepted=acc1, indeterminate=indet1, detail=det1, bounce_addr=bounce_addr, test_id=test_id)
        if indet1:
            try:
                smtp.quit()
            except Exception:
                pass
            return BounceReplayResult(vulnerable=False, indeterminate=True, message_accepted=False, rcpt_rejected_in_session=rcpt_rej1, bounce_addr=bounce_addr, recipient_used=recipient, test_id=test_id, smtp_trace=tuple(smtp_trace), tarpitting_or_timeout=True, detail=det1 or 'Probe 1 incomplete', message_accepted_return_path=False, test_id_return_path='', probe1_detail=det1, probe1_indeterminate=True, auth_used=auth_used)
        try:
            smtp.docmd('RSET')
            _br_trace_append('RSET')
        except Exception:
            pass
        _br_stream_probe_section_title(e, 'Test From headers and Return-Path')
        body2 = _build_body(include_return_path=True, tid=test_id_rp)
        acc2, rcpt_rej2, mail_rej2, indet2, det2 = _phase(smtp, 'Probe 2: MAIL FROM + DATA (Return-Path + From headers)', body2)
        _br_stream_probe_verdict(e, accepted=acc2, indeterminate=indet2, detail=det2, bounce_addr=bounce_addr, test_id=test_id_rp)
        try:
            smtp.quit()
        except Exception:
            pass
        rcpt_rejected_both = (rcpt_rej1 or rcpt_rej2) and (not (acc1 or acc2))
        parts: list[str] = []
        if acc1:
            parts.append(f'Probe 1: server accepted DATA (250) — possible backscatter. Check {bounce_addr} for NDR within 2–5 min. Test ID: {test_id}')
        elif det1 and (not acc1) and (not indet1):
            parts.append(f'Probe 1: {det1}')
        if indet2:
            parts.append(f"Probe 2: {det2 or 'timeout or connection lost'}")
        elif acc2:
            parts.append(f'Probe 2 (Return-Path in DATA): server accepted DATA (250). Check {bounce_addr} for NDR. Test ID: {test_id_rp}')
        elif det2:
            parts.append(f'Probe 2: {det2}')
        if not parts:
            detail = 'Test incomplete: no message reached a completed DATA result'
            overall_indet = True
        else:
            detail = ' '.join(parts)
            overall_indet = bool((indet1 or indet2) and (not (acc1 or acc2)))
        return BounceReplayResult(vulnerable=False, indeterminate=overall_indet, message_accepted=acc1, rcpt_rejected_in_session=rcpt_rejected_both, bounce_addr=bounce_addr, recipient_used=recipient, test_id=test_id, smtp_trace=tuple(smtp_trace), tarpitting_or_timeout=overall_indet, detail=detail, message_accepted_return_path=acc2, test_id_return_path=test_id_rp if acc2 else '', probe1_detail=det1, probe2_detail=det2, probe1_indeterminate=indet1, probe2_indeterminate=indet2, auth_used=auth_used)
    except (socket.timeout, ConnectionRefusedError, OSError) as ex:
        return BounceReplayResult(vulnerable=False, indeterminate=True, message_accepted=False, rcpt_rejected_in_session='timeout' in str(ex).lower(), bounce_addr=bounce_addr, recipient_used=recipient, test_id=test_id, smtp_trace=tuple(smtp_trace), tarpitting_or_timeout='timeout' in str(ex).lower(), detail=f'Connection error: {ex}', message_accepted_return_path=False, test_id_return_path='')


def _br_stream_probe_section_title(e, title: str) -> None:
    """Probe subsection heading for -br (printed as the probe starts)."""
    if e.use_json:
        return
    e._bounce_replay_streamed_live = True
    e._ptprint_raw(title, bullet_type='TITLE', condition=True, indent=4)


def _br_stream_probe_verdict(e, *, accepted: bool, indeterminate: bool, detail: str | None, bounce_addr: str, test_id: str='') -> None:
    """Mail probe verdict line for -br, printed when that probe finishes."""
    if e.use_json:
        return
    e._bounce_replay_streamed_live = True
    bt, msg = e._mail_probe_bullet_msg(accepted, indeterminate=indeterminate, detail=detail, sent_msg=e._mail_sent_inbox_msg(bounce_addr, test_id))
    e._ptprint_raw(msg, bullet_type=bt, condition=True, indent=8)


def _br_stream_trace_line(e, line: str) -> None:
    """-vv SMTP trace for -br (ADDITIONS, indent 8 under probe title)."""
    e._stream_smtp_trace_line(line, indent_override=8)


def _stream_bounce_replay_trace_line(e, line: str) -> None:
    """-vv SMTP trace for -br replay in streamer (ADDITIONS, same as live)."""
    _br_stream_trace_line(e, line)


def _stream_bounce_replay_result(e) -> None:
    pp = e._ptprint_raw
    show = not e.use_json
    if (err := e.results.bounce_replay_error) is not None:
        pp(f'Bounce replay test failed: {err}', bullet_type='VULN', condition=show, indent=4)
        return
    br = e.results.bounce_replay
    if br is None or not show:
        return
    if getattr(e, '_bounce_replay_streamed_live', False):
        return

    def _probe_bullet_msg(accepted: bool, indet: bool, detail: str | None, test_id: str) -> tuple[str, str]:
        return e._mail_probe_bullet_msg(accepted, indeterminate=indet, detail=detail, sent_msg=e._mail_sent_inbox_msg(br.bounce_addr, test_id))

    def _split_trace(trace: tuple[str, ...]):
        """Split smtp_trace into pre-probe lines, Probe 1 label/lines, Probe 2 label/lines."""
        pre: list[str] = []
        p1: list[str] = []
        p2: list[str] = []
        p1_label = ''
        p2_label = ''
        cur = pre
        for line in trace:
            if line.startswith('---'):
                if cur is pre:
                    p1_label = line.strip('- ').strip()
                    cur = p1
                else:
                    p2_label = line.strip('- ').strip()
                    cur = p2
            else:
                cur.append(line)
        return (pre, p1_label, p1, p2_label, p2)
    pre_lines, p1_label, p1_lines, p2_label, p2_lines = _split_trace(br.smtp_trace)
    has_probe1 = bool(p1_label or p1_lines)
    has_probe2 = bool(p2_label or p2_lines)

    def _emit_trace(line: str) -> None:
        if e.args.debug:
            _stream_bounce_replay_trace_line(e, line)
    if not has_probe1:
        for line in pre_lines:
            _emit_trace(line)
        bt, msg = _probe_bullet_msg(False, br.indeterminate, br.detail, br.test_id)
        pp(msg, bullet_type=bt, condition=show, indent=4)
        return
    pp('Test From header without Return-Path', bullet_type='TITLE', condition=show, indent=4)
    for line in pre_lines:
        _emit_trace(line)
    if p1_label:
        _emit_trace(f'--- {p1_label} ---')
    for line in p1_lines:
        _emit_trace(line)
    p1_bt, p1_msg = _probe_bullet_msg(br.message_accepted, br.probe1_indeterminate, br.probe1_detail, br.test_id)
    pp(p1_msg, bullet_type=p1_bt, condition=show, indent=8)
    if br.probe1_indeterminate and (not has_probe2):
        return
    pp('Test From headers and Return-Path', bullet_type='TITLE', condition=show, indent=4)
    if p2_label:
        _emit_trace(f'--- {p2_label} ---')
    for line in p2_lines:
        _emit_trace(line)
    p2_accepted = getattr(br, 'message_accepted_return_path', False)
    p2_bt, p2_msg = _probe_bullet_msg(p2_accepted, br.probe2_indeterminate, br.probe2_detail, getattr(br, 'test_id_return_path', '') or br.test_id)
    pp(p2_msg, bullet_type=p2_bt, condition=show, indent=8)


def run(ctx):
    e = eng(ctx)
    e.args.bounce_replay = True
    try:
        e.results.bounce_replay = test_bounce_replay(e)
    except Exception as ex:
        e.results.bounce_replay_error = str(ex)
        ctx.out(f"BOUNCE failed: {ex}", "ERROR", indent=4)
        return
    _stream_bounce_replay_result(e)
