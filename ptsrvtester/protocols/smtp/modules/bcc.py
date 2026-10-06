"""BCC — BCC header disclosure."""
import ipaddress, random, smtplib, socket, ssl, time
from email.mime.text import MIMEText

from ..utils.helpers import *
from ..utils.results import *
from ..utils.results import BccProbeResult
from ..utils.registry import *

from ._common import eng


__MODULELABEL__ = "BCC Disclosure Test"
__MODULECODE__ = "BCC"
__ORDER__ = 120


def _bcc_split(raw) -> list[str]:
    return [a.strip() for a in str(raw or '').split(',') if a.strip()]


def _bcc_random() -> str:
    return f'probe{random.getrandbits(32):08x}@invalid.invalid'


def _bcc_plans(rcpt: str, cc_user: list[str], bcc_user: list[str]) -> list[dict]:
    """Header sets. Envelope is always ``rcpt`` and is applied by the sender."""
    if cc_user or bcc_user:
        return [{
            'role': 'headers',
            'title': 'Headers',
            'to': [rcpt],
            'cc': cc_user or [_bcc_random()],
            'bcc': bcc_user or [_bcc_random()],
        }]
    return [
        {'role': 'to', 'title': 'To', 'to': [rcpt], 'cc': [_bcc_random()], 'bcc': [_bcc_random()]},
        {'role': 'cc', 'title': 'Cc', 'to': [_bcc_random()], 'cc': [rcpt], 'bcc': [_bcc_random()]},
        {'role': 'bcc', 'title': 'Bcc', 'to': [_bcc_random()], 'cc': [_bcc_random()], 'bcc': [rcpt]},
    ]


def test_bcc(e) -> BccTestResult:
    """
        BCC disclosure test. RCPT TO is only ``-r``. Cc and Bcc stay in the headers.
        Without -cc and -bcc, three messages rotate -r through To, Cc and Bcc.
        """
    host = e.args.target.ip
    port = e.args.target.port
    rcpt_to = str(e.args.rcpt_to).strip()
    cc_user = _bcc_split(getattr(e.args, 'cc', None))
    bcc_user = _bcc_split(getattr(e.args, 'bcc_test', None))
    plans = _bcc_plans(rcpt_to, cc_user, bcc_user)
    mail_from = e.args.mail_from or f'bcctest@{e.fqdn}'
    mail_from = str(mail_from).strip()
    timeout = max(5.0, getattr(e.args, 'bcc_timeout', 30.0))
    auth_user = getattr(e.args, 'user', None) or ''
    auth_pass = first_cli_password(getattr(e.args, 'password', None)) or ''
    do_auth = bool(auth_user and auth_pass)
    _ssl_ctx = ssl._create_unverified_context()
    use_tls = e.args.tls or port == 465
    use_starttls = e.args.starttls and (not use_tls)
    VERIFICATION_INSTRUCTIONS = "Check the -r inbox source. SEARCH for a Bcc header or the Bcc addresses. If NOT FOUND: SECURE. If FOUND: VULNERABLE (BCC disclosure)."

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
    probes: list[BccProbeResult] = []
    for plan in plans:
        to_addrs = list(plan['to'])
        cc_addrs = list(plan['cc'])
        bcc_addrs = list(plan['bcc'])
        msg = MIMEText(f'{e._outbound_data()}\r\n', 'plain', 'utf-8')
        msg['From'] = f'<{mail_from}>'
        msg['To'] = ', '.join((f'<{a}>' for a in to_addrs))
        msg['Cc'] = ', '.join((f'<{a}>' for a in cc_addrs))
        msg['Bcc'] = ', '.join((f'<{a}>' for a in bcc_addrs))
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
                    status, reply = smtp.docmd('RCPT', f'TO:<{rcpt_to}>')
                    _bcc_trace_append(smtp_trace, f'RCPT TO <{rcpt_to}>: {e._smtp_trace_reply(status, reply)}')
                    if status not in (250, 251):
                        detail = f'RCPT rejected before DATA: {e._smtp_trace_reply(status, reply)}'
                    else:
                        data_status, data_reply = smtp.data(raw_msg)
                        _bcc_trace_append(smtp_trace, e._data_trace_entry(raw_msg, data_status, data_reply))
                        status_code = data_status
                        reply_str = data_reply.decode() if isinstance(data_reply, bytes) else str(data_reply)
                        if data_status == 250:
                            message_accepted = True
                            detail = 'Message sent. Check the inbox source for a Bcc header.'
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
        probes.append(BccProbeResult(role=plan['role'], test_id=bcc_test_id, message_accepted=message_accepted, smtp_status=status_code, smtp_reply=reply_str, recipients_to=tuple(to_addrs), recipients_cc=tuple(cc_addrs), recipients_bcc=tuple(bcc_addrs), detail=detail or None, smtp_trace=tuple(smtp_trace)))
    elapsed = time.perf_counter() - start_time
    first = probes[0]
    accepted_all = all((p.message_accepted for p in probes))
    detail_all = ' '.join((p.detail for p in probes if p.detail)) or None
    trace_all = tuple((line for p in probes for line in p.smtp_trace))
    bcc_result = BccTestResult(message_accepted=accepted_all, smtp_status=first.smtp_status, smtp_reply=first.smtp_reply, recipients_to=first.recipients_to, recipients_cc=first.recipients_cc, recipients_bcc=first.recipients_bcc, elapsed_sec=elapsed, detail=detail_all, verification_instructions=VERIFICATION_INSTRUCTIONS, smtp_trace=trace_all, test_id=first.test_id, probes=tuple(probes))
    return bcc_result


_BCC_TITLES = {'to': 'To', 'cc': 'Cc', 'bcc': 'Bcc', 'headers': 'Headers'}


def _stream_bcc_probe(e, probe: BccProbeResult, inbox: str) -> None:
    pp = e._ptprint_raw
    pp(_BCC_TITLES.get(probe.role, probe.role), bullet_type='TITLE', condition=True, indent=4)
    if e.args.debug:
        for line in probe.smtp_trace:
            if line.startswith('---'):
                continue
            e._stream_smtp_trace_line(line, indent_override=8)
    pp(f"To:  {', '.join(probe.recipients_to)}", bullet_type='TEXT', condition=True, indent=8)
    pp(f"Cc:  {', '.join(probe.recipients_cc)}", bullet_type='TEXT', condition=True, indent=8)
    pp(f"Bcc: {', '.join(probe.recipients_bcc)}", bullet_type='TEXT', condition=True, indent=8)
    if probe.message_accepted and probe.test_id:
        e._pp_mail_probe_line(pp, True, accepted=True, sent_msg=e._mail_sent_inbox_msg(inbox, probe.test_id), indent=8)
    else:
        pp(probe.detail or 'Message was not accepted by the server', bullet_type='WARNING', condition=True, indent=8)


def _stream_bcc_result(e) -> None:
    pp = e._ptprint_raw
    show = not e.use_json
    if (err := e.results.bcc_test_error) is not None:
        pp(f'BCC test failed: {err}', bullet_type='VULN', condition=show, indent=4)
        return
    bc = e.results.bcc_test
    if bc is None or not show:
        return
    inbox = str(e.args.rcpt_to).strip()
    for probe in bc.probes:
        _stream_bcc_probe(e, probe, inbox)


def run(ctx):
    e = eng(ctx)
    try:
        e.results.bcc_test = test_bcc(e)
    except Exception as ex:
        e.results.bcc_test_error = str(ex)
        ctx.out(f"BCC failed: {ex}", "ERROR", indent=4)
        return
    _stream_bcc_result(e)
