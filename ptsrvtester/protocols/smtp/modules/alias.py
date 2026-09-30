"""ALIAS — alias and addressing bypass."""
import ipaddress, random, smtplib, socket, ssl, time
from email.mime.text import MIMEText

from ..utils.helpers import *
from ..utils.results import *
from ..utils.registry import *

from ._common import eng


__MODULELABEL__ = "Alias & Addressing Bypass Test"
__MODULECODE__ = "ALIAS"
__ORDER__ = 110


def _alias_variant_title(e, variant: str) -> str:
    return ALIAS_VARIANT_TITLES.get(variant, variant.replace('_', ' ').strip().title() + ' test')


def _al_variant_mail_accepted(v: AliasVariantResult) -> bool:
    return v.accepted and (not (v.detail and 'DATA rejected' in v.detail))


def _al_variant_outcome_line(e, v: AliasVariantResult) -> str:
    if _al_variant_mail_accepted(v):
        for line in reversed(v.smtp_trace):
            if line.startswith('DATA:'):
                code = e._data_trace_status_code(line) or '250'
                return f'{v.address}: {code} (accepted)'
        return f'{v.address}: 250 (accepted)'
    if v.rejected:
        reason = e._smtp_detail_one_line(v.detail) or ''
        code = v.smtp_status if v.smtp_status is not None else '?'
        if reason:
            return f'{v.address}: {reason}' if str(code) in reason else f'{v.address}: {code} ({reason})'
        return f'{v.address}: {code} (rejected)'
    if v.error:
        reason = e._smtp_detail_one_line(v.detail) or 'error'
        return f'{v.address}: error ({reason})'
    return f'{v.address}: (skipped)'


def _al_variant_outcome_tail(e, v: AliasVariantResult) -> str | None:
    """Status tail for variant output (without the address prefix)."""
    if _al_variant_mail_accepted(v):
        return None
    line = _al_variant_outcome_line(e, v)
    prefix = f'{v.address}:'
    if line.startswith(prefix):
        tail = line[len(prefix):].strip()
        return tail or None
    return line


def _al_stream_variant_section(e, v: AliasVariantResult, base_address: str, *, stream_trace: bool=False) -> None:
    """Per-variant terminal block for -al."""
    pp = e._ptprint_raw
    pp(_alias_variant_title(e, v.variant), bullet_type='TITLE', condition=True, indent=4)
    pp(v.address, bullet_type='TEXT', condition=True, indent=8)
    if stream_trace:
        for line in v.smtp_trace:
            if line.startswith('---'):
                continue
            e._stream_smtp_trace_line(line, indent_override=12)
    mail_accepted = _al_variant_mail_accepted(v)
    if mail_accepted and v.test_id:
        e._pp_mail_probe_line(pp, True, accepted=True, sent_msg=e._mail_sent_inbox_msg(base_address, v.test_id), indent=12)
        if v.uucp_warning:
            pp('Warning: UUCP syntax accepted', bullet_type='WARNING', condition=True, indent=12)
    else:
        tail = _al_variant_outcome_tail(e, v)
        if tail:
            pp(tail, bullet_type='TEXT', condition=True, indent=12)


def _al_stream_base_section(e, base_address: str, *, base_mail_sent: bool=False, base_test_id: str='', base_smtp_trace: tuple[str, ...]=(), stream_trace: bool=False) -> None:
    """Terminal block for the base recipient control send."""
    pp = e._ptprint_raw
    pp('Base recipient', bullet_type='TITLE', condition=True, indent=4)
    pp(base_address, bullet_type='TEXT', condition=True, indent=8)
    if stream_trace and base_smtp_trace:
        for line in base_smtp_trace:
            if line.startswith('---'):
                continue
            e._stream_smtp_trace_line(line, indent_override=12)
    if base_mail_sent and base_test_id:
        e._pp_mail_probe_line(pp, True, accepted=True, sent_msg=e._mail_sent_inbox_msg(base_address, base_test_id), indent=12)


def _generate_alias_variants(e, recipient: str) -> dict[str, str]:
    """Generate alias variant addresses from base recipient (e.g. admin@example.com)."""
    if '@' not in recipient:
        return {}
    user, domain = recipient.rsplit('@', 1)
    user = user.strip()
    domain = domain.strip()
    if not user or not domain:
        return {}
    return {'case': f'{user.upper()}@{domain}', 'case_domain': f'{user}@{domain.upper()}', 'dotted': f"{'.'.join(list(user))}@{domain}", 'plus': f'{user}+test@{domain}', 'percent': f'user%{user}@{domain}', 'bang_simple': f'{user}!{domain}', 'bang_nested': f'{user}!internal.{domain}@{domain}'}


def test_alias(e) -> AliasTestResult:
    """
        Alias & Addressing bypass test (PTL-SVC-SMTP-ALIAS).
        Sends messages to variant addresses (case, dotted, plus, percent, bang); manual verification required.
        """
    host = e.args.target.ip
    port = e.args.target.port
    base_address = str(e.args.rcpt_to).strip()
    mail_from = e.args.mail_from or f'aliastest@{e.fqdn}'
    mail_from = str(mail_from).strip()
    timeout = max(5.0, getattr(e.args, 'alias_timeout', 30.0))
    auth_user = getattr(e.args, 'user', None) or ''
    auth_pass = getattr(e.args, 'password', None) or ''
    do_auth = bool(auth_user and auth_pass)
    variants_arg = getattr(e.args, 'alias_variants', None)
    default_variants = ['case', 'case_domain', 'dotted', 'plus', 'percent', 'bang_simple', 'bang_nested']
    if variants_arg:
        requested = [v.strip().lower() for v in variants_arg.split(',') if v.strip()]
        variant_names = [v for v in default_variants if v in requested] or default_variants
    else:
        variant_names = default_variants
    all_variants = _generate_alias_variants(e, base_address)
    variants_to_test = [(k, all_variants[k]) for k in variant_names if k in all_variants]
    VERIFICATION_INSTRUCTIONS = "Verify if messages sent to '250 OK' addresses bypassed any security policies (rate limits, attachment filtering, content scanning)."
    _ssl_ctx = ssl._create_unverified_context()
    use_tls = e.args.tls or port == 465
    use_starttls = e.args.starttls and (not use_tls)

    def _al_trace_append(trace: list[str], line: str) -> None:
        trace.append(line)

    def _connect_alias(trace: list[str]) -> tuple[smtplib.SMTP | smtplib.SMTP_SSL | None, str]:
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
                    _al_trace_append(trace, f'Connect: {e._smtp_trace_reply(st, reply)}')
                    return (None, f'Connect: {st}')
                _al_trace_append(trace, f'Connect: {e._smtp_trace_reply(st, reply)}')
            else:
                smtp = smtplib.SMTP(timeout=timeout)
                st, reply = smtp.connect(host, port)
                if st != 220:
                    _al_trace_append(trace, f'Connect: {e._smtp_trace_reply(st, reply)}')
                    return (None, f'Connect: {st}')
                _al_trace_append(trace, f'Connect: {e._smtp_trace_reply(st, reply)}')
                if use_starttls:
                    st2, reply2 = smtp.docmd('STARTTLS')
                    _al_trace_append(trace, f'STARTTLS: {e._smtp_trace_reply(st2, reply2)}')
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
            ehlo_st, ehlo_reply = smtp.docmd('EHLO', e.fqdn or 'alias-test.local')
            _al_trace_append(trace, f'EHLO: {e._smtp_trace_reply(ehlo_st, ehlo_reply)}')
            if do_auth:
                try:
                    smtp.login(auth_user, auth_pass)
                    _al_trace_append(trace, 'AUTH: ok')
                except smtplib.SMTPAuthenticationError as ex:
                    _al_trace_append(trace, f'AUTH failed: {ex}')
                    return (None, f'AUTH failed: {ex}')
            return (smtp, '')
        except Exception as ex:
            _al_trace_append(trace, f'Connect: {ex}')
            return (None, str(ex))
    start_time = time.perf_counter()
    var_results: list[AliasVariantResult] = []
    e._alias_streamed_live = False
    base_mail_sent = False
    base_test_id = ''
    base_smtp_trace: tuple[str, ...] = ()

    def _run_alias_probe(variant_name: str, addr: str, *, is_bang_simple: bool=False) -> AliasVariantResult:
        detail_str = None
        accepted = rejected = error = False
        status_code = None
        reply_str = None
        smtp_trace: list[str] = []
        alias_test_id = ''
        smtp, conn_err = _connect_alias(smtp_trace)
        if smtp is None:
            error = True
            detail_str = f'Connection failed: {conn_err}'
        else:
            try:
                msg = MIMEText(f'{e._outbound_data()}\r\n', 'plain', 'utf-8')
                msg['From'] = f'<{mail_from}>'
                msg['To'] = f'<{addr}>'
                msg['Subject'] = e._outbound_subject()
                msg['Date'] = time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime())
                msg[EMAIL_HDR_TEST] = EMAIL_TEST_ALIAS
                alias_test_id = e._new_mail_test_id()
                msg[EMAIL_HDR_TEST_ID] = alias_test_id
                raw_msg = msg.as_string()
                mail_st, mail_reply = smtp.docmd('MAIL', f'FROM:<{mail_from}>')
                _al_trace_append(smtp_trace, f'MAIL FROM <{mail_from}>: {e._smtp_trace_reply(mail_st, mail_reply)}')
                if mail_st not in (250, 251):
                    error = True
                    detail_str = f'MAIL FROM rejected before DATA: {e._smtp_trace_reply(mail_st, mail_reply)}'
                else:
                    rcpt_targets = [addr]
                    if addr.lower() != base_address.lower():
                        rcpt_targets.append(base_address)
                    rcpt_ok = True
                    for rcpt_addr in rcpt_targets:
                        status, reply = smtp.docmd('RCPT', f'TO:<{rcpt_addr}>')
                        status_code = status
                        reply_str = e._smtp_reply_text_one_line(reply)
                        _al_trace_append(smtp_trace, f'RCPT TO <{rcpt_addr}>: {e._smtp_trace_reply(status, reply)}')
                        if status not in (250, 251):
                            rcpt_ok = False
                            rejected = True
                            detail_str = f'[{status}] {reply_str}'
                            break
                    if rcpt_ok:
                        accepted = True
                        data_status, data_reply = smtp.data(raw_msg)
                        _al_trace_append(smtp_trace, e._data_trace_entry(raw_msg, data_status, data_reply))
                        if data_status != 250:
                            detail_str = f'RCPT OK but DATA rejected: {data_status}'
            except Exception as ex:
                error = True
                _al_trace_append(smtp_trace, f'error: {ex}')
                detail_str = str(ex)
            finally:
                try:
                    smtp.quit()
                except Exception:
                    pass
        mail_accepted = accepted and (not (detail_str and 'DATA rejected' in detail_str))
        uucp_warning = is_bang_simple and mail_accepted
        return AliasVariantResult(variant=variant_name, address=addr, accepted=accepted, rejected=rejected, error=error, smtp_status=status_code, smtp_reply=reply_str, detail=detail_str, uucp_warning=uucp_warning, smtp_trace=tuple(smtp_trace), test_id=alias_test_id if mail_accepted else '')
    base_probe = _run_alias_probe('base', base_address)
    base_mail_sent = _al_variant_mail_accepted(base_probe)
    base_test_id = base_probe.test_id
    base_smtp_trace = base_probe.smtp_trace
    if not e.use_json:
        e._alias_streamed_live = True
        _al_stream_base_section(e, base_address, base_mail_sent=base_mail_sent, base_test_id=base_test_id, base_smtp_trace=base_smtp_trace, stream_trace=True)
    for variant_name, addr in variants_to_test:
        is_bang_simple = variant_name == 'bang_simple'
        variant_result = _run_alias_probe(variant_name, addr, is_bang_simple=is_bang_simple)
        var_results.append(variant_result)
        if not e.use_json:
            e._alias_streamed_live = True
            _al_stream_variant_section(e, variant_result, base_address, stream_trace=True)
    elapsed = time.perf_counter() - start_time
    accepted_count = sum((1 for v in var_results if _al_variant_mail_accepted(v)))
    probes_failed = base_probe.error or any((v.error for v in var_results))
    if probes_failed and accepted_count == 0 and (not base_mail_sent):
        detail = 'Test incomplete: probes failed before a result (connection, timeout, or envelope rejected before DATA)'
    else:
        detail = f'{accepted_count} variant(s) accepted; manual verification required' if var_results else None
    return AliasTestResult(base_address=base_address, variants=tuple(var_results), elapsed_sec=elapsed, detail=detail, verification_instructions=VERIFICATION_INSTRUCTIONS, base_mail_sent=base_mail_sent, base_test_id=base_test_id, base_smtp_trace=base_smtp_trace)


def _stream_alias_result(e) -> None:
    pp = e._ptprint_raw
    show = not e.use_json
    if (err := e.results.alias_test_error) is not None:
        pp(f'Alias test failed: {err}', bullet_type='VULN', condition=show, indent=4)
        return
    al = e.results.alias_test
    if al is None or not show:
        return
    if not getattr(e, '_alias_streamed_live', False):
        _al_stream_base_section(e, al.base_address, base_mail_sent=al.base_mail_sent, base_test_id=al.base_test_id, base_smtp_trace=al.base_smtp_trace, stream_trace=False)
        for v in al.variants:
            _al_stream_variant_section(e, v, al.base_address, stream_trace=False)
    mail_sent = any((_al_variant_mail_accepted(v) for v in al.variants))
    extra = tuple((p.strip() for p in (al.verification_instructions or '').split('\n') if p.strip())) if mail_sent else ()
    e._pp_av_summary_block(pp, show=show, detail=al.detail, elapsed_sec=al.elapsed_sec, extra_lines=extra)


def run(ctx):
    e = eng(ctx)
    e.args.alias_test = True
    try:
        e.results.alias_test = test_alias(e)
    except Exception as ex:
        e.results.alias_test_error = str(ex)
        ctx.out(f"ALIAS failed: {ex}", "ERROR", indent=4)
        return
    _stream_alias_result(e)
