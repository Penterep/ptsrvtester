"""BCC — BCC header disclosure."""
import ipaddress, random, smtplib, socket, ssl, time
from email.mime.text import MIMEText

from ..utils.helpers import *
from ..utils.results import *
from ..utils.registry import *

from ._common import eng


__MODULELABEL__ = "BCC Disclosure Test"
__MODULECODE__ = "BCC"
__ORDER__ = 120


def test_bcc(e) -> BccTestResult:
    """
        BCC disclosure test – sends message with To, Cc, Bcc; manual verification required.
        Envelope (RCPT TO) contains all recipients; Bcc header in DATA must be stripped by server.
        """
    host = e.args.target.ip
    port = e.args.target.port
    rcpt_to = str(e.args.rcpt_to).strip()
    cc_raw = getattr(e.args, 'cc', None) or ''
    bcc_raw = getattr(e.args, 'bcc_test', None) or ''
    cc_list = [a.strip() for a in cc_raw.split(',') if a.strip()]
    bcc_list = [a.strip() for a in bcc_raw.split(',') if a.strip()]
    mail_from = e.args.mail_from or f'bcctest@{e.fqdn}'
    mail_from = str(mail_from).strip()
    timeout = max(5.0, getattr(e.args, 'bcc_timeout', 30.0))
    auth_user = getattr(e.args, 'user', None) or ''
    auth_pass = getattr(e.args, 'password', None) or ''
    do_auth = bool(auth_user and auth_pass)
    _ssl_ctx = ssl._create_unverified_context()
    use_tls = e.args.tls or port == 465
    use_starttls = e.args.starttls and (not use_tls)
    to_addr = rcpt_to
    cc_addrs = cc_list
    bcc_addrs = bcc_list
    all_recipients = [to_addr] + cc_addrs + bcc_addrs
    VERIFICATION_INSTRUCTIONS = "Check all recipients' inboxes. View Message Source / Original Header. SEARCH for 'Bcc' or Bcc recipient addresses. If NOT FOUND: SECURE. If FOUND: VULNERABLE (BCC disclosure)."

    def _bcc_trace_append(trace: list[str], line: str) -> None:
        trace.append(line)

    def _connect_bcc(trace: list[str]) -> tuple[smtplib.SMTP | smtplib.SMTP_SSL | None, str]:
        try:
            if use_tls:
                try:
                    ipaddress.ip_address(host)
                    _sni = None
                except ValueError:
                    _sni = host
                sock = socket.create_connection((host, port), timeout=min(30.0, timeout))
                sock_ssl = _ssl_ctx.wrap_socket(sock, server_hostname=_sni)
                smtp = smtplib.SMTP(timeout=timeout)
                smtp.sock = sock_ssl
                smtp.file = None
                st, reply = smtp.getreply()
                if st != 220:
                    _bcc_trace_append(trace, f'Connect: {e._smtp_trace_reply(st, reply)}')
                    return (None, f'Connect: {st}')
                _bcc_trace_append(trace, f'Connect: {e._smtp_trace_reply(st, reply)}')
            else:
                smtp = smtplib.SMTP(timeout=timeout)
                st, reply = smtp.connect(host, port)
                if st != 220:
                    _bcc_trace_append(trace, f'Connect: {e._smtp_trace_reply(st, reply)}')
                    return (None, f'Connect: {st}')
                _bcc_trace_append(trace, f'Connect: {e._smtp_trace_reply(st, reply)}')
                if use_starttls:
                    st2, reply2 = smtp.docmd('STARTTLS')
                    _bcc_trace_append(trace, f'STARTTLS: {e._smtp_trace_reply(st2, reply2)}')
                    if st2 != 220:
                        return (None, f'STARTTLS: {st2}')
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
            ehlo_st, ehlo_reply = smtp.docmd('EHLO', e.fqdn or 'bcc-test.local')
            _bcc_trace_append(trace, f'EHLO: {e._smtp_trace_reply(ehlo_st, ehlo_reply)}')
            if do_auth:
                try:
                    smtp.login(auth_user, auth_pass)
                    _bcc_trace_append(trace, 'AUTH: ok')
                except smtplib.SMTPAuthenticationError as ex:
                    _bcc_trace_append(trace, f'AUTH failed: {ex}')
                    return (None, f'AUTH failed: {ex}')
            return (smtp, '')
        except Exception as ex:
            _bcc_trace_append(trace, f'Connect: {ex}')
            return (None, str(ex))
    start_time = time.perf_counter()
    e._bcc_streamed_live = False
    to_hdr = ', '.join((f'<{a}>' for a in [to_addr]))
    cc_hdr = ', '.join((f'<{a}>' for a in cc_addrs))
    bcc_hdr = ', '.join((f'<{a}>' for a in bcc_addrs))
    msg = MIMEText(f'{e._outbound_data()}\r\n', 'plain', 'utf-8')
    msg['From'] = f'<{mail_from}>'
    msg['To'] = to_hdr
    msg['Cc'] = cc_hdr
    msg['Bcc'] = bcc_hdr
    msg['Subject'] = e._outbound_subject()
    msg['Date'] = time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime())
    msg[EMAIL_HDR_TEST] = 'BCC'
    bcc_test_id = e._new_mail_test_id()
    msg[EMAIL_HDR_TEST_ID] = bcc_test_id
    raw_msg = msg.as_string()
    smtp_trace: list[str] = []
    smtp, conn_err = _connect_bcc(smtp_trace)
    message_accepted = False
    status_code = None
    reply_str = None
    detail = ''
    if smtp is None:
        detail = f'Connection failed: {conn_err}'
    else:
        try:
            mail_st, mail_reply = smtp.docmd('MAIL', f'FROM:<{mail_from}>')
            _bcc_trace_append(smtp_trace, f'MAIL FROM <{mail_from}>: {e._smtp_trace_reply(mail_st, mail_reply)}')
            if mail_st not in (250, 251):
                detail = f'MAIL FROM rejected before DATA: {e._smtp_trace_reply(mail_st, mail_reply)}'
            else:
                for recp in all_recipients:
                    status, reply = smtp.docmd('RCPT', f'TO:<{recp}>')
                    _bcc_trace_append(smtp_trace, f'RCPT TO <{recp}>: {e._smtp_trace_reply(status, reply)}')
                    if status not in (250, 251):
                        detail = f'RCPT rejected before DATA: {e._smtp_trace_reply(status, reply)}'
                        break
                else:
                    data_status, data_reply = smtp.data(raw_msg)
                    _bcc_trace_append(smtp_trace, e._data_trace_entry(raw_msg, data_status, data_reply))
                    status_code = data_status
                    reply_str = data_reply.decode() if isinstance(data_reply, bytes) else str(data_reply)
                    if data_status == 250:
                        message_accepted = True
                        detail = 'Message sent successfully. Manual verification required.'
                    else:
                        detail = f'Server rejected DATA: {data_status}'
        except Exception as ex:
            _bcc_trace_append(smtp_trace, f'error: {ex}')
            detail = str(ex)
        finally:
            try:
                smtp.quit()
            except Exception:
                pass
    elapsed = time.perf_counter() - start_time
    bcc_result = BccTestResult(message_accepted=message_accepted, smtp_status=status_code, smtp_reply=reply_str, recipients_to=tuple([to_addr]), recipients_cc=tuple(cc_addrs), recipients_bcc=tuple(bcc_addrs), elapsed_sec=elapsed, detail=detail or None, verification_instructions=VERIFICATION_INSTRUCTIONS, smtp_trace=tuple(smtp_trace), test_id=bcc_test_id)
    if not e.use_json and e.args.debug:
        e._bcc_streamed_live = True
        _bcc_stream_section(e, bcc_result, stream_trace=True)
    return bcc_result


def _bcc_stream_section(e, bc: BccTestResult, *, stream_trace: bool=False) -> None:
    """Verbose (-vv) SMTP trace for BCC: full dialog including the DATA payload.

        The DATA trace entry already embeds the message actually transmitted (headers +
        body), so the tester sees exactly what is sent. Nothing is printed without -vv.
        """
    if not stream_trace:
        return
    for line in bc.smtp_trace:
        if line.startswith('---'):
            continue
        e._stream_smtp_trace_line(line, indent_override=4)


def _bcc_stream_summary_block(e, bc: BccTestResult) -> None:
    """Result footer for BCC: single mail-sent verdict (or failure reason)."""
    pp = e._ptprint_raw
    show = not e.use_json
    if not show:
        return
    if bc.message_accepted and bc.test_id:
        inbox = bc.recipients_to[0] if bc.recipients_to else ''
        e._pp_mail_probe_line(pp, True, accepted=True, sent_msg=e._mail_sent_inbox_msg(inbox, bc.test_id), indent=4)
    else:
        reason = bc.detail or 'Message was not accepted by the server'
        pp(reason, bullet_type='WARNING', condition=True, indent=4)


def _stream_bcc_result(e) -> None:
    pp = e._ptprint_raw
    show = not e.use_json
    if (err := e.results.bcc_test_error) is not None:
        pp(f'BCC test failed: {err}', bullet_type='VULN', condition=show, indent=4)
        return
    bc = e.results.bcc_test
    if bc is None or not show:
        return
    if not (e.args.debug and getattr(e, '_bcc_streamed_live', False)):
        _bcc_stream_section(e, bc, stream_trace=False)
    _bcc_stream_summary_block(e, bc)


def run(ctx):
    e = eng(ctx)
    try:
        e.results.bcc_test = test_bcc(e)
    except Exception as ex:
        e.results.bcc_test_error = str(ex)
        ctx.out(f"BCC failed: {ex}", "ERROR", indent=4)
        return
    _stream_bcc_result(e)
