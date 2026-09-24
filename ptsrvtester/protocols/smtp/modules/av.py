"""AV — antivirus / antispam payloads."""
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


__MODULELABEL__ = "Antivirus / Antispam Test"
__MODULECODE__ = "AV"
__ORDER__ = 250


def _av_category_title(e, category: str) -> str:
    return AV_CATEGORY_TITLES.get(category, category.replace('_', ' ').strip().title() + ' test')


def _av_payload_label(msg_def: dict) -> str:
    attachments = msg_def.get('attachments') or []
    if attachments:
        return str(attachments[0])
    if msg_def.get('rawEml'):
        return 'msg_001.eml'
    if msg_def.get('bodyPlainEicar'):
        return 'body (plain EICAR)'
    if msg_def.get('bodyBase64') is not None:
        return 'body (base64)'
    if msg_def.get('bodyQuotedPrintable') is not None:
        return 'body (quoted-printable)'
    if msg_def.get('bodyHtml'):
        return 'body (HTML)'
    return 'message body'


def _av_expand_msg_defs(msg_def: dict) -> list[dict]:
    """One SMTP transaction per payload (industry AV testing practice)."""
    attachments = msg_def.get('attachments') or []
    if len(attachments) <= 1:
        return [msg_def]
    return [{**msg_def, 'attachments': [name]} for name in attachments]


def _av_payload_summary_line(e, msg_def: dict | None, fallback_name: str, status: int | None, outcome: str, reason: str='') -> str:
    label = _av_payload_label(msg_def) if msg_def else fallback_name
    why = ' '.join((reason or '').split())
    if outcome == 'error':
        return f'{label}: error ({why or "error"})'
    if outcome == 'incomplete':
        return f'{label}: {why or status or "rejected"} (content not sent)'
    if status is not None:
        return f'{label}: {status} ({outcome})'
    return f'{label}: ({outcome})'


def _av_record_payload_result(e, summaries: list[str], test_ids: list[str], msg_def: dict | None, fallback_name: str, status: int | None, outcome: str, *, test_id: str='', reason: str='') -> tuple[str, str]:
    summary = _av_payload_summary_line(e, msg_def, fallback_name, status, outcome, reason)
    summaries.append(summary)
    payload_test_id = test_id if outcome == 'accepted' and test_id else ''
    test_ids.append(payload_test_id)
    return (summary, payload_test_id)


def _av_summary_payload_label(summary_line: str) -> str:
    if ':' in summary_line:
        return summary_line.split(':', 1)[0].strip()
    return summary_line.strip()


def _av_stream_payload_block(e, payload_trace: tuple[str, ...] | list[str], summary_line: str, payload_test_id: str, rcpt: str) -> None:
    """Under -vv: payload label, indented SMTP trace, then mail-sent / outcome."""
    pp = e._ptprint_raw
    pp(_av_summary_payload_label(summary_line), bullet_type='TEXT', condition=True, indent=8)
    for line in payload_trace:
        if line.startswith('---'):
            continue
        e._stream_smtp_trace_line(line, indent_override=12)
    if '(accepted)' in summary_line and payload_test_id:
        e._pp_mail_probe_line(pp, True, accepted=True, sent_msg=e._mail_sent_inbox_msg(rcpt, payload_test_id), indent=12)
    elif ':' in summary_line:
        tail = summary_line.split(':', 1)[1].strip()
        if tail:
            pp(tail, bullet_type='TEXT', condition=True, indent=12)


def test_antivirus(e) -> AntivirusResult:
    """
        Test antivirus/antispam protection (PTL-SVC-SMTP-ANTIVIRUS).
        Sends prepared test messages and records accepted vs rejected vs error per category.
        """
    host = e.args.target.ip
    port = e.args.target.port
    rcpt = str(e.args.rcpt_to).strip()
    mail_from = e.args.mail_from or f'avtest@{e.fqdn}'
    mail_from = str(mail_from).strip()
    from_name = getattr(e.args, 'from_name', None) or ''
    cc_raw = getattr(e.args, 'cc', None) or ''
    cc_list = [a.strip() for a in cc_raw.split(',') if a.strip()] if cc_raw else []
    timeout = max(5.0, getattr(e.args, 'antivirus_timeout', 30.0))
    skip_absent = getattr(e.args, 'antivirus_skip_absent', False)
    incl_zip_bomb = getattr(e.args, 'antivirus_zip_bomb', False)
    cats_arg = getattr(e.args, 'antivirus_categories', None)
    default_cats = ['eicar', 'double_ext', 'executable', 'nested_archive', 'encoded_content', 'html_sanitization', 'xxe', 'mime_malformed']
    if cats_arg:
        categories = [c.strip().lower() for c in cats_arg.split(',') if c.strip()]
    else:
        categories = list(default_cats)
    if incl_zip_bomb and 'zip_bomb' not in categories:
        categories.append('zip_bomb')
    catalog = antivirus_catalog()
    _ssl_ctx = ssl._create_unverified_context()
    use_tls = e.args.tls or port == 465
    use_starttls = e.args.starttls and (not use_tls)
    cc_hdr = ', '.join((f'<{c}>' for c in cc_list)) if cc_list else ''
    from_hdr = f'"{from_name}" <{mail_from}>' if from_name else f'<{mail_from}>'
    recipients = [rcpt] + cc_list
    start_time = time.perf_counter()
    auth_used = False
    cat_results: list[AntivirusCategoryResult] = []
    e._antivirus_streamed_live = False
    RISKY_CATEGORIES = frozenset({'eicar', 'double_ext', 'executable', 'nested_archive', 'encoded_content', 'html_sanitization', 'xxe', 'mime_malformed'})

    def _av_smtp_reply(status: int, reply) -> str:
        text = e.bytes_to_str(reply).strip().replace('\r\n', ' ').replace('\n', ' ')
        return f'{status} {text}' if text else str(status)

    def _av_fail_line(trace: list[str], line: str) -> None:
        trace.append(line)

    def _connect_av() -> tuple[smtplib.SMTP | smtplib.SMTP_SSL | None, str]:
        """Connect to SMTP. Optional AUTH LOGIN after EHLO when -u/-p (or -U/-P) are set."""
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

    def _build_mime(msg_def: dict, att_map: dict[str, bytes], test_id: str) -> tuple[str, list[str]]:
        """
            Build MIME message. Returns (msg_str, missing_attachments).
            If any requested attachment is missing, list is non-empty – caller should not send
            (avoids false SECURE when message has no payload).
            Supports: bodyBase64, bodyQuotedPrintable (encoded_content), rawEml (mime_malformed).
            """
        subject = e._outbound_subject()
        body_base64 = msg_def.get('bodyBase64')
        body_qp = msg_def.get('bodyQuotedPrintable')
        raw_eml = msg_def.get('rawEml')
        attachments = msg_def.get('attachments') or []
        custom_headers = msg_def.get('headers') or {}
        missing: list[str] = []
        if raw_eml:
            raw = str(raw_eml)
            raw = raw.replace('{FROM}', from_hdr).replace('{TO}', f'<{rcpt}>').replace('{SUBJECT}', subject)
            if cc_hdr:
                raw = raw.replace('{CC}', cc_hdr)
            else:
                raw = raw.replace('Cc: {CC}\r\n', '')
            return (e._mime_add_test_id_header(raw, test_id), missing)
        msg = MIMEMultipart('mixed')
        msg['Subject'] = subject
        msg['From'] = from_hdr
        msg['To'] = f'<{rcpt}>'
        if cc_hdr:
            msg['Cc'] = cc_hdr
        msg['Date'] = time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime())
        msg[EMAIL_HDR_TEST] = EMAIL_TEST_ANTIVIRUS
        msg[EMAIL_HDR_TEST_ID] = test_id
        for k, v in custom_headers.items():
            msg[k] = str(v)
        if body_base64 is not None:
            part = MIMEText('', 'plain', 'utf-8')
            part.set_payload(body_base64)
            part['Content-Transfer-Encoding'] = 'base64'
            msg.attach(part)
        elif body_qp is not None:
            part = MIMEText('', 'plain', 'utf-8')
            part.set_payload(body_qp)
            part['Content-Transfer-Encoding'] = 'quoted-printable'
            msg.attach(part)
        else:
            if msg_def.get('bodyPlainEicar'):
                intro = str(msg_def.get('body') or '').strip()
                body = f'{EICAR_LINE}\n\n{intro}' if intro else EICAR_LINE
            elif 'body' in msg_def:
                body = str(msg_def['body'])
            else:
                body = e._outbound_data()
            msg.attach(MIMEText(body, 'plain', 'utf-8'))
        body_html = msg_def.get('bodyHtml')
        if body_html:
            msg.attach(MIMEText(body_html, 'html', 'utf-8'))
        for att_name in attachments:
            blob = att_map.get(att_name)
            if blob is None:
                missing.append(att_name)
                continue
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(blob)
            encode_base64(part)
            part.add_header('Content-Disposition', 'attachment', filename=att_name)
            msg.attach(part)
        return (msg.as_string(), missing)
    for cat in categories:
        entries = catalog.get(cat) or []
        if not entries and skip_absent:
            continue
        if not entries:
            _empty_detail = f'No payload definitions for category {cat}'
            cat_results.append(AntivirusCategoryResult(category=cat, sent=0, accepted=0, rejected=0, error=0, smtp_trace=(), detail=_empty_detail))
            if not e.use_json:
                e._antivirus_streamed_live = True
                e._ptprint_raw(f'{_av_category_title(e, cat)}: {_empty_detail}', bullet_type='TITLE', condition=True, indent=4)
            continue
        accepted, rejected, err_count = (0, 0, 0)
        smtp_trace: list[str] = []
        msg_summaries: list[str] = []
        payload_test_ids: list[str] = []
        last_accepted_test_id = ''
        sent = 0
        stream_av = not e.use_json
        if stream_av:
            e._antivirus_streamed_live = True
            e._ptprint_raw(_av_category_title(e, cat), bullet_type='TITLE', condition=True, indent=4)

        def _av_emit_payload(payload_trace: list[str], msg_def: dict | None, fallback_name: str, status: int | None, outcome: str, *, test_id: str='', reason: str='') -> None:
            summary, payload_test_id = _av_record_payload_result(e, msg_summaries, payload_test_ids, msg_def, fallback_name, status, outcome, test_id=test_id, reason=reason)
            if stream_av:
                _av_stream_payload_block(e, payload_trace, summary, payload_test_id, rcpt)
        for source_name, msg_def, att_map in entries:
            payload_defs = _av_expand_msg_defs(msg_def)
            for payload_def in payload_defs:
                payload_trace: list[str] = []
                payload_label = _av_payload_label(payload_def)
                trace_name = f'{source_name} ({payload_label})' if len(payload_defs) > 1 else source_name

                def _av_payload_trace_store(line: str) -> None:
                    smtp_trace.append(line)
                    payload_trace.append(line)

                def _av_payload_fail_line(line: str) -> None:
                    smtp_trace.append(line)
                    payload_trace.append(line)
                msg_test_id = e._new_mail_test_id()
                raw_msg, missing_att = _build_mime(payload_def, att_map, msg_test_id)
                if missing_att:
                    err_count += 1
                    warn_msg = f'missing attachments {missing_att}'
                    _av_payload_fail_line(f'{trace_name}: {warn_msg} – test incomplete (avoid false SECURE)')
                    _av_emit_payload(payload_trace, payload_def, trace_name, None, 'error', reason=warn_msg)
                    continue
                smtp, conn_err = _connect_av()
                if smtp is None:
                    err_count += 1
                    _av_payload_fail_line(f'{trace_name}: connection failed {conn_err}')
                    _av_emit_payload(payload_trace, payload_def, trace_name, None, 'error', reason=conn_err or 'connection failed')
                    continue
                try:
                    _av_payload_trace_store(f'--- {trace_name} ---')
                    ehlo_status, ehlo_reply = smtp.docmd('EHLO', e.fqdn or 'av-test.local')
                    _av_payload_trace_store(f'EHLO: {_av_smtp_reply(ehlo_status, ehlo_reply)}')
                    used_auth, auth_err = e._mail_test_auth_login(smtp, smtp_trace, trace_append=_av_payload_trace_store)
                    if auth_err:
                        err_count += 1
                        _av_payload_fail_line(f'{trace_name}: {auth_err}')
                        _av_emit_payload(payload_trace, payload_def, trace_name, None, 'error', reason=auth_err)
                        try:
                            smtp.quit()
                        except Exception:
                            pass
                        continue
                    if used_auth:
                        auth_used = True
                    mail_status, mail_reply = smtp.docmd('MAIL', f'FROM:<{mail_from}>')
                    _av_payload_trace_store(f'MAIL FROM <{mail_from}>: {_av_smtp_reply(mail_status, mail_reply)}')
                    if mail_status not in (250, 251):
                        err_count += 1
                        _av_emit_payload(payload_trace, payload_def, trace_name, mail_status, 'incomplete', reason=_av_smtp_reply(mail_status, mail_reply))
                        try:
                            smtp.quit()
                        except Exception:
                            pass
                        continue
                    rcpt_status, rcpt_reply = smtp.docmd('RCPT', f'TO:<{rcpt}>')
                    _av_payload_trace_store(f'RCPT TO <{rcpt}>: {_av_smtp_reply(rcpt_status, rcpt_reply)}')
                    if rcpt_status not in (250, 251):
                        err_count += 1
                        _av_emit_payload(payload_trace, payload_def, trace_name, rcpt_status, 'incomplete', reason=_av_smtp_reply(rcpt_status, rcpt_reply))
                        try:
                            smtp.quit()
                        except Exception:
                            pass
                        continue
                    cc_failed = False
                    for c in cc_list:
                        cc_status, cc_reply = smtp.docmd('RCPT', f'TO:<{c}>')
                        _av_payload_trace_store(f'RCPT TO <{c}>: {_av_smtp_reply(cc_status, cc_reply)}')
                        if cc_status not in (250, 251):
                            err_count += 1
                            _av_emit_payload(payload_trace, payload_def, trace_name, cc_status, 'incomplete', reason=_av_smtp_reply(cc_status, cc_reply))
                            cc_failed = True
                            try:
                                smtp.quit()
                            except Exception:
                                pass
                            break
                    if not cc_failed:
                        data_status, data_reply = smtp.data(raw_msg)
                        _av_payload_trace_store(e._data_trace_entry(raw_msg, reply=_av_smtp_reply(data_status, data_reply)))
                        sent += 1
                        if data_status == 250:
                            accepted += 1
                            last_accepted_test_id = msg_test_id
                            _av_emit_payload(payload_trace, payload_def, trace_name, data_status, 'accepted', test_id=msg_test_id)
                        else:
                            rejected += 1
                            _av_emit_payload(payload_trace, payload_def, trace_name, data_status, 'rejected')
                    try:
                        smtp.quit()
                    except Exception:
                        pass
                except (smtplib.SMTPResponseException, smtplib.SMTPServerDisconnected, ConnectionResetError, BrokenPipeError, OSError, socket.timeout) as ex:
                    err_count += 1
                    _av_payload_fail_line(f'{trace_name}: error {ex}')
                    _av_emit_payload(payload_trace, payload_def, trace_name, None, 'error', reason=str(ex))
                    try:
                        smtp.quit()
                    except Exception:
                        pass
        detail = f'{accepted} accepted, {rejected} rejected, {err_count} error'
        cat_result = AntivirusCategoryResult(category=cat, sent=sent, accepted=accepted, rejected=rejected, error=err_count, smtp_trace=tuple(smtp_trace), detail=detail, message_summary=tuple(msg_summaries), test_id=last_accepted_test_id, payload_test_ids=tuple(payload_test_ids))
        cat_results.append(cat_result)
    elapsed = time.perf_counter() - start_time
    total_accepted = sum((c.accepted for c in cat_results))
    total_rejected = sum((c.rejected for c in cat_results))
    total_sent = sum((c.sent for c in cat_results))
    total_error = sum((c.error for c in cat_results))
    risky_accepted = sum((c.accepted for c in cat_results if c.category in RISKY_CATEGORIES))
    risky_sent = sum((c.sent for c in cat_results if c.category in RISKY_CATEGORIES))
    no_payloads = len(cat_results) > 0 and total_sent == 0 and (total_error == 0)
    vulnerable = risky_accepted > 0 and risky_sent > 0
    no_decision = total_accepted == 0 and total_rejected == 0
    any_gap = total_error > 0
    # A content decision exists only after DATA. Connect, timeout, and MAIL/RCPT
    # rejection never reached the filter, so they cannot support NOT VULNERABLE.
    indeterminate = len(cat_results) == 0 or no_payloads or (not vulnerable and (no_decision or any_gap))
    partial_protection = (not vulnerable) and (not indeterminate) and total_accepted > 0 and (total_rejected > 0)
    if indeterminate:
        if len(cat_results) == 0:
            detail = 'No test categories available'
        elif no_payloads:
            detail = 'No payload definitions for the selected antivirus categories'
        elif no_decision:
            detail = 'Test incomplete: no message reached DATA (connection error, timeout, rate limit, or recipient rejected before content was sent)'
        else:
            detail = 'Test incomplete: some samples failed before a content decision; antivirus result is not confirmed'
    elif not vulnerable:
        detail = 'All risky content blocked'
    else:
        detail = f'Risky content passed: {risky_accepted}/{risky_sent} in risky categories'
        if total_error:
            detail += f'; {total_error} sample(s) did not reach a content decision'
    return AntivirusResult(vulnerable=vulnerable, indeterminate=indeterminate, partial_protection=partial_protection, categories=tuple(cat_results), elapsed_sec=elapsed, auth_used=auth_used, detail=detail)


def _av_print_payload_summary(e, pp, summary_line: str, payload_test_id: str, rcpt: str) -> None:
    """Terminal summary for one AV payload (normal mode, no SMTP trace)."""
    pp(_av_summary_payload_label(summary_line), bullet_type='TEXT', condition=True, indent=8)
    if '(accepted)' in summary_line and payload_test_id:
        e._pp_mail_probe_line(pp, True, accepted=True, sent_msg=e._mail_sent_inbox_msg(rcpt, payload_test_id), indent=12)
    elif ':' in summary_line:
        tail = summary_line.split(':', 1)[1].strip()
        if tail:
            pp(tail, bullet_type='TEXT', condition=True, indent=12)


def _av_stream_category_section(e, cat: AntivirusCategoryResult, rcpt: str, *, stream_trace: bool=False) -> None:
    """Per-category terminal block for -av."""
    pp = e._ptprint_raw
    pp(_av_category_title(e, cat.category), bullet_type='TITLE', condition=True, indent=4)
    payload_test_ids = cat.payload_test_ids or tuple(('' for _ in cat.message_summary))
    if stream_trace:
        summary_iter = iter(zip(cat.message_summary, payload_test_ids))
        section_lines: list[str] = []
        orphan_lines: list[str] = []

        def _flush_section(lines: list[str]) -> None:
            if not lines:
                return
            try:
                summary_line, payload_test_id = next(summary_iter)
            except StopIteration:
                return
            _av_stream_payload_block(e, lines, summary_line, payload_test_id, rcpt)
        for line in cat.smtp_trace:
            if line.startswith('---') and line.endswith('---'):
                if section_lines:
                    _flush_section(section_lines)
                    section_lines = []
                elif orphan_lines:
                    _flush_section(orphan_lines)
                    orphan_lines = []
                continue
            if section_lines:
                section_lines.append(line)
            else:
                orphan_lines.append(line)
        if section_lines:
            _flush_section(section_lines)
        elif orphan_lines:
            _flush_section(orphan_lines)
        for summary_line, payload_test_id in summary_iter:
            _av_print_payload_summary(e, pp, summary_line, payload_test_id, rcpt)
        return
    for line, payload_test_id in zip(cat.message_summary, payload_test_ids):
        _av_print_payload_summary(e, pp, line, payload_test_id, rcpt)


def _stream_antivirus_result(e) -> None:
    pp = e._ptprint_raw
    show = not e.use_json
    if (err := e.results.antivirus_error) is not None:
        pp(f'Antivirus test failed: {err}', bullet_type='VULN', condition=show, indent=4)
        return
    av = e.results.antivirus
    if av is None:
        return
    if not show:
        return
    if not getattr(e, '_antivirus_streamed_live', False):
        rcpt = str(e.args.rcpt_to).strip()
        for cat in av.categories:
            _av_stream_category_section(e, cat, rcpt, stream_trace=False)
    if av.indeterminate:
        pp('Summary', bullet_type='TITLE', condition=show, indent=4)
        pp(av.detail or 'Could not complete', bullet_type='TEXT', condition=show, indent=8)
        pp(f'Elapsed: {av.elapsed_sec:.1f} s', bullet_type='TEXT', condition=show, indent=8)
        pp('Indeterminate', bullet_type='WARNING', condition=show, indent=4)
    elif av.vulnerable:
        pp('Summary', bullet_type='TITLE', condition=show, indent=4)
        pp(av.detail, bullet_type='TEXT', condition=show, indent=8)
        pp('Risky content was accepted at MTA.', bullet_type='TEXT', condition=show, indent=8)
        pp(f'Elapsed: {av.elapsed_sec:.1f} s', bullet_type='TEXT', condition=show, indent=8)
        pp('VULNERABLE', bullet_type='VULN', condition=show, indent=4)
    elif av.partial_protection:
        pp('Summary', bullet_type='TITLE', condition=show, indent=4)
        pp(av.detail, bullet_type='TEXT', condition=show, indent=8)
        pp(f'Elapsed: {av.elapsed_sec:.1f} s', bullet_type='TEXT', condition=show, indent=8)
        pp('PARTIAL PROTECTION', bullet_type='WARNING', condition=show, indent=4)
    else:
        pp('Summary', bullet_type='TITLE', condition=show, indent=4)
        pp(av.detail, bullet_type='TEXT', condition=show, indent=8)
        pp(f'Elapsed: {av.elapsed_sec:.1f} s', bullet_type='TEXT', condition=show, indent=8)
        pp('NOT VULNERABLE', bullet_type='NOTVULN', condition=show, indent=4)


def run(ctx):
    e = eng(ctx)
    e.args.antivirus = True
    try:
        e.results.antivirus = test_antivirus(e)
    except Exception as ex:
        e.results.antivirus_error = str(ex)
        ctx.out(f"AV failed: {ex}", "ERROR", indent=4)
        return
    _stream_antivirus_result(e)
