"""SSRF — server fetches links in messages."""
import ipaddress, smtplib, socket, ssl, time
from email.encoders import encode_base64
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from ..utils.content_payloads import EICAR_LINE, SSRF_VARIANTS, antivirus_catalog
from ..utils.helpers import *
from ..utils.results import *
from ..utils.registry import *

from ._common import eng


__MODULELABEL__ = "SSRF Test – server fetches links in messages"
__MODULECODE__ = "SSRF"
__ORDER__ = 260


def _ssrf_variant_title(e, variant: str) -> str:
    return SSRF_VARIANT_TITLES.get(variant, variant.replace('_', ' ').strip().title() + ' test')


def _ssrf_variant_payload_label(e, variant: str) -> str:
    return SSRF_VARIANT_PAYLOAD_LABELS.get(variant, variant.replace('_', ' '))


def _ssrf_variant_outcome_line(e, v: SsrfVariantResult) -> str:
    label = _ssrf_variant_payload_label(e, v.variant)
    if v.accepted > 0:
        for line in reversed(v.smtp_trace):
            if line.startswith('DATA:'):
                code = e._data_trace_status_code(line) or '250'
                return f'{label}: {code} (accepted)'
        return f'{label}: 250 (accepted)'
    if v.rejected > 0:
        for line in reversed(v.smtp_trace):
            if line.startswith('DATA:'):
                code = e._data_trace_status_code(line) or '?'
                return f'{label}: {code} (rejected)'
        return f'{label}: (rejected)'
    if v.error > 0:
        reason = e._smtp_detail_one_line(v.detail) or 'error'
        return f'{label}: error ({reason})'
    return f'{label}: (skipped)'


def _ssrf_stream_variant_section(e, v: SsrfVariantResult, rcpt: str, *, stream_trace: bool=False) -> None:
    """Per-variant terminal block for -ssrf."""
    pp = e._ptprint_raw
    pp(_ssrf_variant_title(e, v.variant), bullet_type='TITLE', condition=True, indent=4)
    if stream_trace:
        for line in v.smtp_trace:
            if line.startswith('---'):
                continue
            e._stream_smtp_trace_line(line, indent_override=8)
    pp(_ssrf_variant_outcome_line(e, v), bullet_type='TEXT', condition=True, indent=8)
    if v.detail:
        pp(f'Summary: {v.detail}', bullet_type='TEXT', condition=True, indent=8)
    if v.accepted > 0 and v.test_id:
        e._pp_mail_probe_line(pp, True, accepted=True, sent_msg=e._mail_sent_inbox_msg(rcpt, v.test_id), indent=8)


def test_ssrf(e) -> SsrfResult:
    """
        Test SSRF – server fetches links in messages (PTL-SVC-SMTP-SSRF).
        Sends test emails with canary URL; user must verify canary for incoming requests.
        """
    host = e.args.target.ip
    port = e.args.target.port
    rcpt = str(e.args.rcpt_to).strip()
    canary_url = str(getattr(e.args, 'ssrf_canary_url', '')).strip()
    mail_from = e.args.mail_from or f'ssrftest@{e.fqdn}'
    mail_from = str(mail_from).strip()
    from_name = getattr(e.args, 'from_name', None) or ''
    cc_raw = getattr(e.args, 'cc', None) or ''
    cc_list = [a.strip() for a in cc_raw.split(',') if a.strip()] if cc_raw else []
    timeout = max(5.0, getattr(e.args, 'ssrf_timeout', 30.0))
    incl_internal = getattr(e.args, 'ssrf_internal_urls', False)
    variants_arg = getattr(e.args, 'ssrf_variants', None)
    default_variants = ['plain', 'html_link', 'html_img', 'html_iframe', 'multipart', 'ssrf_malformed', 'ssrf_nested']
    if variants_arg:
        variants = [v.strip().lower() for v in variants_arg.split(',') if v.strip()]
    else:
        variants = list(default_variants)
    _ssl_ctx = ssl._create_unverified_context()
    use_tls = e.args.tls or port == 465
    use_starttls = e.args.starttls and (not use_tls)
    cc_hdr = ', '.join((f'<{c}>' for c in cc_list)) if cc_list else ''
    from_hdr = f'"{from_name}" <{mail_from}>' if from_name else f'<{mail_from}>'
    recipients = [rcpt] + cc_list
    start_time = time.perf_counter()
    auth_used = False
    var_results: list[SsrfVariantResult] = []
    e._ssrf_streamed_live = False
    e._ssrf_canary_streamed = False
    VERIFICATION_INSTRUCTIONS = 'Monitor your canary URL for 2–5 minutes. If HTTP/HTTPS request arrives from MTA IP, verdict is VULNERABLE (SSRF).'

    def _ssrf_trace_append(trace: list[str], line: str) -> None:
        trace.append(line)
    if not e.use_json and canary_url:
        pp = e._ptprint_raw
        pp('Canary URL', bullet_type='TITLE', condition=True, indent=4)
        pp(canary_url, bullet_type='TEXT', condition=True, indent=8)
        e._ssrf_canary_streamed = True

    def _connect_ssrf() -> tuple[smtplib.SMTP | smtplib.SMTP_SSL | None, str]:
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
                st, _ = smtp.getreply()
                if st != 220:
                    return (None, f'Connect: {st}')
                return (smtp, '')
            smtp = smtplib.SMTP(timeout=timeout)
            st, _ = smtp.connect(host, port)
            if st != 220:
                return (None, f'Connect: {st}')
            if use_starttls:
                st2, _ = smtp.docmd('STARTTLS')
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
            return (smtp, '')
        except Exception as ex:
            return (None, str(ex))

    def _build_ssrf_mime(subject: str, body: str, body_html: str | None, test_id: str) -> str:
        msg = MIMEMultipart('mixed')
        msg['Subject'] = subject
        msg['From'] = from_hdr
        msg['To'] = f'<{rcpt}>'
        if cc_hdr:
            msg['Cc'] = cc_hdr
        msg['Date'] = time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime())
        msg[EMAIL_HDR_TEST] = EMAIL_TEST_SSRF
        msg[EMAIL_HDR_TEST_ID] = test_id
        msg.attach(MIMEText(body, 'plain', 'utf-8'))
        if body_html:
            msg.attach(MIMEText(body_html, 'html', 'utf-8'))
        return msg.as_string()
    FALLBACK_VARIANTS: dict[str, dict] = SSRF_VARIANTS

    def _build_ssrf_malformed_mime(subject: str, test_id: str) -> str:
        """Malformed MIME – wrong boundary in nested part (parser differential test)."""
        bnd1, bnd_wrong = ('BND1', 'BND_WRONG')
        plain_body = e._outbound_data_with_url(canary_url)
        raw = f'From: {from_hdr}\r\nTo: <{rcpt}>\r\nSubject: {subject}\r\n{EMAIL_HDR_TEST_ID}: {test_id}\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="{bnd1}"\r\n\r\n--{bnd1}\r\nContent-Type: text/plain\r\n\r\n{plain_body}\r\n--{bnd1}\r\nContent-Type: multipart/alternative; boundary="BND2"\r\n\r\n--{bnd_wrong}\r\nContent-Type: text/plain\r\n\r\n{plain_body}\r\n--{bnd1}--\r\n'
        return raw

    def _build_ssrf_nested_mime(subject: str, test_id: str, layers: int=10) -> str:
        """Deeply nested multipart/alternative – canary URL in innermost part (parser differential)."""
        boundaries = [f'NEST{i}' for i in range(layers)]
        innermost = f'Content-Type: text/plain; charset=utf-8\r\n\r\n{e._outbound_data_with_url(canary_url)}\r\n'
        body_part = innermost
        for i in range(layers - 1, 0, -1):
            b = boundaries[i]
            body_part = f'Content-Type: multipart/alternative; boundary="{b}"\r\n\r\n--{b}\r\n{body_part}--{b}--\r\n'
        top_boundary = boundaries[0]
        body = f'--{top_boundary}\r\n{body_part}--{top_boundary}--\r\n'
        msg = f'''From: {from_hdr}\r\nTo: <{rcpt}>\r\nSubject: {subject}\r\nMIME-Version: 1.0\r\nDate: {time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime())}\r\n{EMAIL_HDR_TEST}: {EMAIL_TEST_SSRF}\r\n{EMAIL_HDR_TEST_ID}: {test_id}\r\nContent-Type: multipart/alternative; boundary="{top_boundary}"\r\n\r\n{body}'''
        return msg
    for var_name in variants:
        if var_name not in FALLBACK_VARIANTS:
            continue
        defs_to_use = FALLBACK_VARIANTS.get(var_name, {})
        subject = e._outbound_subject()
        ssrf_test_id = e._new_mail_test_id()
        if var_name == 'ssrf_malformed':
            raw_msg = _build_ssrf_malformed_mime(subject, ssrf_test_id)
        elif var_name == 'ssrf_nested':
            raw_msg = _build_ssrf_nested_mime(subject, ssrf_test_id)
        else:
            body = e._outbound_data_with_url(canary_url)
            body_html = defs_to_use.get('bodyHtml')
            if body_html:
                body_html = body_html.replace('{{CANARY_URL}}', canary_url)
            raw_msg = _build_ssrf_mime(subject, body, body_html, ssrf_test_id)
        smtp, conn_err = _connect_ssrf()
        sent, accepted, rejected, err_count = (0, 0, 0, 0)
        smtp_trace: list[str] = []
        gap_detail = ''
        if smtp is None:
            err_count = 1
            gap_detail = conn_err or 'connection failed'
            _ssrf_trace_append(smtp_trace, f'Connect: {gap_detail}')
        else:
            try:
                ehlo_st, ehlo_reply = smtp.docmd('EHLO', e.fqdn or 'ssrf-test.local')
                _ssrf_trace_append(smtp_trace, f'EHLO: {e._smtp_trace_reply(ehlo_st, ehlo_reply)}')
                used_auth, auth_err = e._mail_test_auth_login(smtp, smtp_trace, trace_append=lambda line: _ssrf_trace_append(smtp_trace, line))
                if auth_err:
                    err_count = 1
                    gap_detail = auth_err
                    _ssrf_trace_append(smtp_trace, auth_err)
                elif used_auth:
                    auth_used = True
                if not auth_err:
                    mail_st, mail_reply = smtp.docmd('MAIL', f'FROM:<{mail_from}>')
                    _ssrf_trace_append(smtp_trace, f'MAIL FROM <{mail_from}>: {e._smtp_trace_reply(mail_st, mail_reply)}')
                    if mail_st not in (250, 251):
                        err_count = 1
                        gap_detail = f'{e._smtp_trace_reply(mail_st, mail_reply)} (content not sent)'
                    else:
                        status, reply = smtp.docmd('RCPT', f'TO:<{rcpt}>')
                        _ssrf_trace_append(smtp_trace, f'RCPT TO <{rcpt}>: {e._smtp_trace_reply(status, reply)}')
                        if status not in (250, 251):
                            err_count = 1
                            gap_detail = f'{e._smtp_trace_reply(status, reply)} (content not sent)'
                        else:
                            for c in cc_list:
                                s, cc_reply = smtp.docmd('RCPT', f'TO:<{c}>')
                                _ssrf_trace_append(smtp_trace, f'RCPT TO <{c}>: {e._smtp_trace_reply(s, cc_reply)}')
                                if s not in (250, 251):
                                    break
                            data_status, data_reply = smtp.data(raw_msg)
                            sent = 1
                            _ssrf_trace_append(smtp_trace, e._data_trace_entry(raw_msg, data_status, data_reply))
                            if data_status == 250:
                                accepted = 1
                            else:
                                rejected = 1
                try:
                    smtp.quit()
                except Exception:
                    pass
            except (smtplib.SMTPResponseException, smtplib.SMTPServerDisconnected, ConnectionResetError, BrokenPipeError, OSError, socket.timeout) as ex:
                err_count = 1
                gap_detail = str(ex)
                _ssrf_trace_append(smtp_trace, f'error: {ex}')
                try:
                    smtp.quit()
                except Exception:
                    pass
        if gap_detail:
            detail = gap_detail
        elif sent or err_count:
            detail = f'{accepted} accepted, {rejected} rejected, {err_count} error'
        else:
            detail = 'skipped'
        variant_result = SsrfVariantResult(variant=var_name, sent=sent, accepted=accepted, rejected=rejected, error=err_count, smtp_trace=tuple(smtp_trace), detail=detail, message_summary=(), test_id=ssrf_test_id if accepted else '')
        var_results.append(variant_result)
        if not e.use_json:
            e._ssrf_streamed_live = True
            _ssrf_stream_variant_section(e, variant_result, rcpt, stream_trace=True)
    if incl_internal:
        for internal_url, label in [('http://127.0.0.1/ssrf-pt-test', 'internal_127'), ('http://localhost/ssrf-pt-test', 'internal_localhost'), ('http://10.0.0.1/ssrf-pt-test', 'internal_10')]:
            body = e._outbound_data_with_url(internal_url)
            internal_test_id = e._new_mail_test_id()
            raw_msg = _build_ssrf_mime(e._outbound_subject(), body, None, internal_test_id)
            smtp, conn_err = _connect_ssrf()
            sent, accepted, rejected, err_count = (0, 0, 0, 0)
            smtp_trace: list[str] = []
            gap_detail = ''
            if smtp is None:
                err_count = 1
                gap_detail = conn_err or 'connection failed'
                _ssrf_trace_append(smtp_trace, f'Connect: {gap_detail}')
            else:
                try:
                    ehlo_st, ehlo_reply = smtp.docmd('EHLO', e.fqdn or 'ssrf-test.local')
                    _ssrf_trace_append(smtp_trace, f'EHLO: {e._smtp_trace_reply(ehlo_st, ehlo_reply)}')
                    mail_st, mail_reply = smtp.docmd('MAIL', f'FROM:<{mail_from}>')
                    _ssrf_trace_append(smtp_trace, f'MAIL FROM <{mail_from}>: {e._smtp_trace_reply(mail_st, mail_reply)}')
                    if mail_st not in (250, 251):
                        err_count = 1
                        gap_detail = f'{e._smtp_trace_reply(mail_st, mail_reply)} (content not sent)'
                    else:
                        status, reply = smtp.docmd('RCPT', f'TO:<{rcpt}>')
                        _ssrf_trace_append(smtp_trace, f'RCPT TO <{rcpt}>: {e._smtp_trace_reply(status, reply)}')
                        if status not in (250, 251):
                            err_count = 1
                            gap_detail = f'{e._smtp_trace_reply(status, reply)} (content not sent)'
                        else:
                            data_status, data_reply = smtp.data(raw_msg)
                            sent = 1
                            _ssrf_trace_append(smtp_trace, e._data_trace_entry(raw_msg, data_status, data_reply))
                            if data_status == 250:
                                accepted = 1
                            else:
                                rejected = 1
                    try:
                        smtp.quit()
                    except Exception:
                        pass
                except Exception as ex:
                    err_count = 1
                    gap_detail = str(ex)
                    _ssrf_trace_append(smtp_trace, str(ex))
                    try:
                        smtp.quit()
                    except Exception:
                        pass
            int_detail = gap_detail or f'{accepted} accepted, {rejected} rejected, {err_count} error'
            internal_result = SsrfVariantResult(variant=label, sent=sent, accepted=accepted, rejected=rejected, error=err_count, smtp_trace=tuple(smtp_trace), detail=int_detail, message_summary=(), test_id=internal_test_id if accepted else '')
            var_results.append(internal_result)
            if not e.use_json:
                e._ssrf_streamed_live = True
                _ssrf_stream_variant_section(e, internal_result, rcpt, stream_trace=True)
    elapsed = time.perf_counter() - start_time
    total_accepted = sum((v.accepted for v in var_results))
    total_sent = sum((v.sent for v in var_results))
    any_error = any((v.error for v in var_results))
    if total_sent == 0:
        detail = 'Test incomplete: no variant reached DATA (connection error, timeout, rate limit, or recipient rejected before content was sent)' if any_error or var_results else 'No variants sent; check connection and definitions.'
    else:
        detail = f'{total_accepted}/{total_sent} variants sent successfully. Check canary for incoming HTTP requests.'
        if any_error:
            detail += ' Some variants failed before DATA and were not scored.'
    return SsrfResult(manual_verification_required=True, canary_url=canary_url, variants=tuple(var_results), elapsed_sec=elapsed, auth_used=auth_used, detail=detail, verification_instructions=VERIFICATION_INSTRUCTIONS)


def _stream_ssrf_result(e) -> None:
    pp = e._ptprint_raw
    show = not e.use_json
    if (err := e.results.ssrf_error) is not None:
        pp(f'SSRF test failed: {err}', bullet_type='VULN', condition=show, indent=4)
        return
    sr = e.results.ssrf
    if sr is None or not show:
        return
    rcpt = str(e.args.rcpt_to).strip()
    if sr.canary_url and (not getattr(e, '_ssrf_canary_streamed', False)):
        pp('Canary URL', bullet_type='TITLE', condition=show, indent=4)
        pp(sr.canary_url, bullet_type='TEXT', condition=show, indent=8)
    if not getattr(e, '_ssrf_streamed_live', False):
        for v in sr.variants:
            _ssrf_stream_variant_section(e, v, rcpt, stream_trace=False)
    mail_sent = any((v.accepted > 0 for v in sr.variants))
    extra = tuple((p.strip() for p in (sr.verification_instructions or '').split('\n') if p.strip())) if mail_sent else ()
    e._pp_av_summary_block(pp, show=show, detail=sr.detail, elapsed_sec=sr.elapsed_sec, extra_lines=extra)


def run(ctx):
    e = eng(ctx)
    e.args.ssrf = True
    try:
        e.results.ssrf = test_ssrf(e)
    except Exception as ex:
        e.results.ssrf_error = str(ex)
        ctx.out(f"SSRF failed: {ex}", "ERROR", indent=4)
        return
    _stream_ssrf_result(e)
