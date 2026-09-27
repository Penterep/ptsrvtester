"""SPOOF — From / Reply-To / Return-Path spoofing."""
import ipaddress, random, smtplib, socket, ssl, time
from email.mime.text import MIMEText

from ..utils.helpers import *
from ..utils.results import *
from ..utils.registry import *

from ._common import eng


__MODULELABEL__ = "Header Spoofing Test (From, Reply-To, Return-Path)"
__MODULECODE__ = "SPOOF"
__ORDER__ = 130


def test_spoof_headers(e) -> SpoofHeaderResult:
    """
        Test header spoofing (From, Reply-To, Return-Path).
        Sends messages with spoofed headers and records accepted vs rejected.
        Uses MIMEText/as_string() for proper CRLF separation (headers vs body).
        """
    host = e.args.target.ip
    port = e.args.target.port
    rcpt = str(e.args.rcpt_to).strip()
    mail_from = e.args.mail_from or f'spoofhdrtest@{e.fqdn}'
    mail_from = str(mail_from).strip()
    timeout = max(5.0, getattr(e.args, 'spoofhdr_timeout', 30.0))
    variants_arg = getattr(e.args, 'spoofhdr_variants', None)
    default_variants = ['from', 'reply_to', 'return_path']
    if variants_arg:
        variants = [v.strip().lower().replace('-', '_') for v in variants_arg.split(',') if v.strip()]
    else:
        variants = list(default_variants)
    _ssl_ctx = ssl._create_unverified_context()
    use_tls = e.args.tls or port == 465
    use_starttls = e.args.starttls and (not use_tls)
    auth_user = getattr(e.args, 'user', None) or ''
    auth_pass = getattr(e.args, 'password', None) or ''
    do_auth = bool(auth_user and auth_pass)
    start_time = time.perf_counter()
    var_results: list[SpoofHeaderVariantResult] = []
    e._spoof_header_streamed_live = False
    VULNERABLE_NOTE = "Message was accepted, but the ultimate impact depends on the target domain's SPF/DMARC policy and the recipient client's ability to detect spoofing."

    def _sh_trace_append(trace: list[str], line: str) -> None:
        """Store SMTP trace for -sh; printed once under variant title (-vv via _sh_stream_variant_section)."""
        trace.append(line)

    def _connect_sh(trace: list[str]) -> tuple[smtplib.SMTP | smtplib.SMTP_SSL | None, str]:
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
                    _sh_trace_append(trace, f'Connect: {e._smtp_trace_reply(st, reply)}')
                    return (None, f'Connect: {st}')
                _sh_trace_append(trace, f'Connect: {e._smtp_trace_reply(st, reply)}')
            else:
                smtp = smtplib.SMTP(timeout=timeout)
                st, reply = smtp.connect(host, port)
                if st != 220:
                    _sh_trace_append(trace, f'Connect: {e._smtp_trace_reply(st, reply)}')
                    return (None, f'Connect: {st}')
                _sh_trace_append(trace, f'Connect: {e._smtp_trace_reply(st, reply)}')
                if use_starttls:
                    st2, reply2 = smtp.docmd('STARTTLS')
                    _sh_trace_append(trace, f'STARTTLS: {e._smtp_trace_reply(st2, reply2)}')
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
            ehlo_st, ehlo_reply = smtp.docmd('EHLO', e.fqdn or 'spoofhdr-test.local')
            _sh_trace_append(trace, f'EHLO: {e._smtp_trace_reply(ehlo_st, ehlo_reply)}')
            if do_auth:
                try:
                    smtp.login(auth_user, auth_pass)
                    _sh_trace_append(trace, 'AUTH: ok')
                except smtplib.SMTPAuthenticationError as ex:
                    _sh_trace_append(trace, f'AUTH failed: {ex}')
                    return (None, f'AUTH failed: {ex}')
            return (smtp, '')
        except Exception as ex:
            _sh_trace_append(trace, f'Connect: {ex}')
            return (None, str(ex))

    def _build_sh_msg(test_id: str, **header_fields: str) -> str:
        msg = MIMEText(f'{e._outbound_data()}\r\n', 'plain', 'utf-8')
        for key, value in header_fields.items():
            msg[key] = value
        msg['To'] = f'<{rcpt}>'
        msg['Subject'] = e._outbound_subject()
        msg['Date'] = time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime())
        msg[EMAIL_HDR_TEST] = 'SPOOFHDR'
        msg[EMAIL_HDR_TEST_ID] = test_id
        return msg.as_string()

    def _run_sh_variant(variant: str, *, test_id: str, spoof_note: str, raw_msg: str, envelope_addr: str, envelope_header_mismatch: bool, accepted_detail: str) -> SpoofHeaderVariantResult:
        smtp_trace: list[str] = []
        _sh_trace_append(smtp_trace, spoof_note)
        accepted = rejected = err = False
        status_code: int | None = None
        reply_str: str | None = None
        detail = ''
        smtp, conn_err = _connect_sh(smtp_trace)
        if smtp is None:
            err = True
            detail = f'Connection failed: {conn_err}'
        else:
            try:
                mail_st, mail_reply = smtp.docmd('MAIL', f'FROM:<{envelope_addr}>')
                _sh_trace_append(smtp_trace, f'MAIL FROM <{envelope_addr}>: {e._smtp_trace_reply(mail_st, mail_reply)}')
                if mail_st not in (250, 251):
                    err = True
                    status_code = mail_st
                    reply_str = e._smtp_reply_text_one_line(mail_reply)
                    detail = f'MAIL FROM rejected before DATA: {e._smtp_trace_reply(mail_st, mail_reply)}'
                else:
                    status, reply = smtp.docmd('RCPT', f'TO:<{rcpt}>')
                    status_code = status
                    reply_str = e._smtp_reply_text_one_line(reply)
                    _sh_trace_append(smtp_trace, f'RCPT TO <{rcpt}>: {e._smtp_trace_reply(status, reply)}')
                    if status not in (250, 251):
                        err = True
                        detail = f'RCPT rejected before DATA: {e._smtp_trace_reply(status, reply)}'
                    else:
                        data_status, data_reply = smtp.data(raw_msg)
                        status_code = data_status
                        reply_str = e._smtp_reply_text_one_line(data_reply)
                        _sh_trace_append(smtp_trace, e._data_trace_entry(raw_msg, data_status, data_reply))
                        if data_status == 250:
                            accepted = True
                            detail = accepted_detail
                        else:
                            rejected = True
                            detail = f'Server rejected DATA: {data_status}'
                smtp.quit()
            except Exception as ex:
                err = True
                _sh_trace_append(smtp_trace, f'error: {ex}')
                detail = str(ex)
        result = SpoofHeaderVariantResult(variant=variant, test_id=test_id, accepted=accepted, rejected=rejected, error=err, smtp_status=status_code, smtp_reply=reply_str, detail=detail or None, envelope_header_mismatch=envelope_header_mismatch, smtp_trace=tuple(smtp_trace))
        if not e.use_json:
            e._spoof_header_streamed_live = True
            _sh_stream_variant_section(e, result, rcpt, stream_trace=True)
        return result
    if 'from' in variants:
        from_header = 'CEO <ceo@trusted-company.com>'
        from_test_id = e._new_mail_test_id()
        var_results.append(_run_sh_variant('from', test_id=from_test_id, spoof_note=f'Spoof: MAIL FROM=<{mail_from}>, From: {from_header}', raw_msg=_build_sh_msg(from_test_id, From=from_header), envelope_addr=mail_from, envelope_header_mismatch=True, accepted_detail=f'Server ACCEPTED message: MAIL FROM (envelope)={mail_from}, From (header)={from_header}'))
    if 'reply_to' in variants:
        from_header = 'support@trusted.com'
        reply_to_test_id = e._new_mail_test_id()
        var_results.append(_run_sh_variant('reply_to', test_id=reply_to_test_id, spoof_note=f'Spoof: From: {from_header}, Reply-To: attacker@evil.com', raw_msg=_build_sh_msg(reply_to_test_id, From=from_header, **{'Reply-To': 'attacker@evil.com'}), envelope_addr=mail_from, envelope_header_mismatch=False, accepted_detail='Server ACCEPTED message with spoofed Reply-To: attacker@evil.com'))
    if 'return_path' in variants:
        return_path_test_id = e._new_mail_test_id()
        var_results.append(_run_sh_variant('return_path', test_id=return_path_test_id, spoof_note='Spoof: Return-Path: <admin@trusted.com>, From: admin@trusted.com', raw_msg=_build_sh_msg(return_path_test_id, From='admin@trusted.com', **{'Return-Path': '<admin@trusted.com>'}), envelope_addr=mail_from, envelope_header_mismatch=False, accepted_detail='Server ACCEPTED message with client-set Return-Path (Backscatter risk)'))
    elapsed = time.perf_counter() - start_time
    any_accepted = any((v.accepted for v in var_results))
    any_error = any((v.error for v in var_results))
    any_data_rejected = any((v.rejected for v in var_results))
    indeterminate = len(var_results) == 0 or (not any_accepted and (any_error or not any_data_rejected))
    detail_parts = []
    if any_accepted:
        accepted_vars = [v.variant for v in var_results if v.accepted]
        detail_parts.append(f"Accepted: {', '.join(accepted_vars)}. Manual check of recipient inbox recommended.")
        from_mismatch = [v for v in var_results if v.variant == 'from' and v.accepted and v.envelope_header_mismatch]
        if from_mismatch:
            detail_parts.append('ENVELOPE vs HEADER MISMATCH: MAIL FROM (envelope) differed from From (header) — server accepted.')
        if any_error:
            detail_parts.append('Some variants failed before DATA and were not scored.')
    elif not indeterminate:
        detail_parts.append('All variants rejected – server blocks spoofed headers.')
    if indeterminate:
        if any_error and any_data_rejected:
            detail_parts.append('Test incomplete: some variants failed before DATA; spoofing was not confirmed for every variant.')
        else:
            detail_parts.append('Could not complete – connection, timeout, or recipient rejected before DATA.')
    return SpoofHeaderResult(vulnerable=any_accepted, indeterminate=indeterminate, variants=tuple(var_results), elapsed_sec=elapsed, detail=' '.join(detail_parts) if detail_parts else None, vulnerable_note=VULNERABLE_NOTE if any_accepted else None)


def _sh_variant_section_title(e, variant: str) -> str:
    return {'from': 'From header', 'reply_to': 'Reply-To header', 'return_path': 'Return-Path'}.get(variant, variant)


def _sh_stream_variant_section(e, v: SpoofHeaderVariantResult, rcpt: str, *, stream_trace: bool=False) -> None:
    """Per-variant terminal block for -sh (From / Reply-To / Return-Path)."""
    pp = e._ptprint_raw
    pp(_sh_variant_section_title(e, v.variant), bullet_type='TITLE', condition=True, indent=4)
    if stream_trace:
        for line in v.smtp_trace:
            if line.startswith('---'):
                continue
            e._stream_smtp_trace_line(line, indent_override=8)
    if v.accepted:
        pp(e._mail_sent_inbox_msg(rcpt, v.test_id), bullet_type='NOTVULN', condition=True, indent=8)
        if v.envelope_header_mismatch:
            pp('Envelope vs header mismatch: MAIL FROM (envelope) ≠ From (header) — server accepted', bullet_type='WARNING', condition=True, indent=8)
        pp('Spoofing possible', bullet_type='VULN', condition=True, indent=8)
    elif v.rejected:
        one_line = e._smtp_detail_one_line(v.detail) or v.detail or 'rejected'
        pp(f'Message rejected — {one_line}', bullet_type='WARNING', condition=True, indent=8)
        pp('Spoofing not accepted', bullet_type='NOTVULN', condition=True, indent=8)
    elif v.error:
        one_line = e._smtp_detail_one_line(v.detail) or v.detail or 'error'
        pp(f'Test failed — {one_line}', bullet_type='WARNING', condition=True, indent=8)
        pp('Indeterminate', bullet_type='WARNING', condition=True, indent=8)


def _stream_spoof_header_result(e) -> None:
    pp = e._ptprint_raw
    show = not e.use_json
    if (err := e.results.spoof_header_error) is not None:
        pp(f'Spoof header test failed: {err}', bullet_type='VULN', condition=show, indent=4)
        return
    sh = e.results.spoof_header
    if sh is None or not show:
        return
    if getattr(e, '_spoof_header_streamed_live', False):
        return
    rcpt = str(e.args.rcpt_to).strip()
    for v in sh.variants:
        _sh_stream_variant_section(e, v, rcpt, stream_trace=False)


def run(ctx):
    e = eng(ctx)
    e.args.spoof_headers = True
    try:
        e.results.spoof_header = test_spoof_headers(e)
    except Exception as ex:
        e.results.spoof_header_error = str(ex)
        ctx.out(f"SPOOF failed: {ex}", "ERROR", indent=4)
        return
    _stream_spoof_header_result(e)
