"""SIZE — message size limit (MAIL FROM SIZE=, no message body)."""
import ipaddress, smtplib, socket, ssl, time

from ..utils.helpers import *
from ..utils.results import *

from ._common import eng


__MODULELABEL__ = "Message size"
__MODULECODE__ = "SIZE"
__ORDER__ = 240

# Largest first. Stop at the first size the server accepts.
_SIZE_STEPS: tuple[tuple[int, str], ...] = (
    (1024 ** 4, "1 TB"),
    (1024 ** 3, "1 GB"),
    (500 * 1024 ** 2, "500 MB"),
    (200 * 1024 ** 2, "200 MB"),
    (100 * 1024 ** 2, "100 MB"),
    (50 * 1024 ** 2, "50 MB"),
    (20 * 1024 ** 2, "20 MB"),
    (10 * 1024 ** 2, "10 MB"),
    (5 * 1024 ** 2, "5 MB"),
    (1 * 1024 ** 2, "1 MB"),
)
# One real message, and never the large steps. 1 TB is only declared.
_SEND_CAP = 1024 ** 2


def _note(kind: str, text: str) -> str:
    return f"{kind}|{text}"


def _clean(text: str) -> str:
    return (text or "").strip().rstrip(".")


def _is_size_refusal(status: int | None, text: str) -> bool:
    if status == 552:
        return True
    if status is None or status < 500:
        return False
    up = (text or "").upper()
    return any(word in up for word in ("SIZE", "EXCEED", "TOO LARGE", "TOO BIG", "MAXIMUM"))


def _result(
    e,
    *,
    notes: list[str],
    trace: list[str],
    start: float,
    advertised: bool = False,
    limit: int | None = None,
    enforced: bool | None = None,
    auth: bool = False,
    detail: str | None = None,
    indeterminate: bool = False,
) -> FloodResult:
    vulnerable = any(item.startswith("BAD|") for item in notes)
    partial = (not vulnerable) and any(item.startswith("WARN|") for item in notes)
    return FloodResult(
        vulnerable=vulnerable,
        indeterminate=indeterminate,
        partial_protection=partial,
        size_advertised=advertised,
        size_limit_bytes=limit if advertised else None,
        size_enforced=enforced,
        messages_sent=0,
        messages_accepted=0,
        messages_rejected=0,
        first_rejection_at=None,
        tarpitting_detected=False,
        elapsed_sec=time.perf_counter() - start,
        smtp_trace=tuple(trace),
        queue_attempts=0,
        flood_notes=tuple(notes),
        auth_used=auth,
        detail=detail,
        test_id="",
    )


def test_flood(e) -> FloodResult:
    """Declare sizes from 1 TB down to 1 MB. Stop when one is allowed. No DATA."""
    host = e.args.target.ip
    port = e.args.target.port
    mail_from = str(e.args.mail_from or f"sizetest@{e.fqdn}").strip()
    start = time.perf_counter()
    trace: list[str] = []
    auth_used = False
    ssl_ctx = ssl._create_unverified_context()
    use_tls = e.args.tls or port == 465
    use_starttls = e.args.starttls and not use_tls
    ehlo_name = e.fqdn or "size-test.local"

    def connect() -> tuple[smtplib.SMTP | None, str]:
        try:
            if use_tls:
                sock = socket.create_connection((host, port), timeout=15)
                try:
                    ipaddress.ip_address(host)
                    sni = None
                except ValueError:
                    sni = host
                sock_ssl = ssl_ctx.wrap_socket(sock, server_hostname=sni)
                smtp = smtplib.SMTP(timeout=15)
                smtp.sock = sock_ssl
                smtp.file = None
                st, reply = smtp.getreply()
                e._mail_test_trace_append(trace, f"Connect: {e._smtp_trace_reply(st, reply)}")
                if st != 220:
                    return None, e._smtp_trace_reply(st, reply)
                return smtp, ""
            smtp = smtplib.SMTP(timeout=15)
            st, reply = smtp.connect(host, port)
            e._mail_test_trace_append(trace, f"Connect: {e._smtp_trace_reply(st, reply)}")
            if st != 220:
                return None, e._smtp_trace_reply(st, reply)
            if use_starttls:
                st2, reply2 = smtp.docmd("STARTTLS")
                e._mail_test_trace_append(trace, f"STARTTLS: {e._smtp_trace_reply(st2, reply2)}")
                if st2 != 220:
                    return None, e._smtp_trace_reply(st2, reply2)
                try:
                    ipaddress.ip_address(host)
                    sni = None
                except ValueError:
                    sni = host
                sock_ssl = ssl_ctx.wrap_socket(smtp.sock, server_hostname=sni)
                smtp.sock = sock_ssl
                smtp.file = None
                smtp.helo_resp = None
                smtp.ehlo_resp = None
                smtp.esmtp_features = {}
                smtp.does_esmtp = False
            return smtp, ""
        except Exception as ex:
            e._mail_test_trace_append(trace, f"Connect: {ex}")
            return None, str(ex)

    def session() -> tuple[smtplib.SMTP | None, str, str]:
        nonlocal auth_used
        smtp, err = connect()
        if smtp is None:
            return None, err, ""
        try:
            st, raw = smtp.ehlo(ehlo_name)
        except Exception as ex:
            e._smtp_vv_io(f"EHLO {ehlo_name}", str(ex))
            trace.append(f"EHLO: {ex}")
            try:
                smtp.quit()
            except Exception:
                pass
            return None, str(ex), ""
        text = e._smtp_trace_reply(st, raw)
        e._smtp_vv_io(f"EHLO {ehlo_name}", text)
        trace.append(f"EHLO: {text}")
        if st != 250:
            try:
                smtp.quit()
            except Exception:
                pass
            return None, text, ""
        used, auth_err = e._mail_test_auth_login(smtp, trace)
        if auth_err:
            try:
                smtp.quit()
            except Exception:
                pass
            return None, auth_err, ""
        if used:
            auth_used = True
        ehlo = raw.decode(errors="replace") if isinstance(raw, bytes) else str(raw or "")
        return smtp, "", ehlo

    smtp, err, ehlo = session()
    if smtp is None:
        detail = f"Could not connect. Size was not tested. {err}".strip()
        return _result(
            e,
            notes=[_note("WARN", "Could not connect. Size was not tested.")],
            trace=trace,
            start=start,
            auth=auth_used,
            detail=detail,
            indeterminate=True,
        )
    keyword, raw_limit = _size_offer_from_ehlo(ehlo)
    advertised = isinstance(raw_limit, int) and raw_limit > 0
    if advertised:
        ehlo_fact = f"SIZE {raw_limit}"
    elif keyword:
        ehlo_fact = "SIZE, no byte limit"
    else:
        ehlo_fact = "SIZE is not offered"
    e._mail_test_live_done("EHLO", ehlo_fact)
    if not keyword:
        try:
            smtp.quit()
        except Exception:
            pass
        return _result(
            e,
            notes=[_note("WARN", "EHLO does not offer SIZE.")],
            trace=trace,
            start=start,
            auth=auth_used,
            detail=f"EHLO {ehlo_fact}.",
        )

    refused: str | None = None
    allowed: str | None = None
    allowed_n: int | None = None
    stopped: str | None = None
    for nbytes, label in _SIZE_STEPS:
        cmd = f"MAIL FROM:<{mail_from}> SIZE={nbytes}"
        try:
            status, reply = smtp.docmd("MAIL", f"FROM:<{mail_from}> SIZE={nbytes}")
            text = e._smtp_trace_reply(status, reply)
        except Exception as ex:
            text = str(ex)
            status = None
            try:
                smtp.quit()
            except Exception:
                pass
            smtp, recon_err, _ehlo = session()
            if smtp is None:
                e._smtp_vv_io(cmd, text)
                e._mail_test_live_done(label, f"stopped ({_clean(text)})")
                stopped = recon_err or text
                break
            try:
                status, reply = smtp.docmd("MAIL", f"FROM:<{mail_from}> SIZE={nbytes}")
                text = e._smtp_trace_reply(status, reply)
            except Exception as ex2:
                text = str(ex2)
                status = None
        e._smtp_vv_io(cmd, text)
        trace.append(f"MAIL SIZE={nbytes}: {text}")
        if status in (250, 251):
            e._mail_test_live_done(label, f"allowed ({_clean(text)})")
            allowed = label
            allowed_n = nbytes
            try:
                smtp.docmd("RSET")
            except Exception:
                pass
            break
        if status == 421:
            e._mail_test_live_done(label, f"stopped ({_clean(text)})")
            stopped = text
            break
        if _is_size_refusal(status, text):
            e._mail_test_live_done(label, f"refused ({_clean(text)})")
            refused = label
            try:
                smtp.docmd("RSET")
            except Exception:
                try:
                    smtp.quit()
                except Exception:
                    pass
                smtp, recon_err, _ehlo = session()
                if smtp is None:
                    stopped = recon_err
                    break
            continue
        e._mail_test_live_done(label, f"refused ({_clean(text)})")
        stopped = text
        break

    msg_note: str | None = None
    want_send = bool(getattr(e.args, "send", False))
    rcpt = str(getattr(e.args, "rcpt_to", None) or "").strip()
    if want_send and not rcpt:
        e._mail_test_live_done("Message", "not sent. No recipient (-r)")
    elif want_send and not allowed_n:
        e._mail_test_live_done("Message", "not sent. No size was allowed")
    elif want_send and allowed_n:
        send_n = min(allowed_n, _SEND_CAP)
        head = f"From: <{mail_from}>\r\nTo: <{rcpt}>\r\nSubject: size check\r\n\r\n"
        payload = head + ("X" * max(0, send_n - len(head.encode())))
        size = len(payload.encode())

        def deliver(client: smtplib.SMTP) -> tuple[int | None, str]:
            mail_cmd = f"MAIL FROM:<{mail_from}> SIZE={size}"
            try:
                st, reply = client.docmd("MAIL", f"FROM:<{mail_from}> SIZE={size}")
                text = e._smtp_trace_reply(st, reply)
                e._smtp_vv_io(mail_cmd, text)
                trace.append(f"MAIL SIZE={size}: {text}")
                if st not in (250, 251):
                    return st, text
                st, reply = client.docmd("RCPT", f"TO:<{rcpt}>")
                text = e._smtp_trace_reply(st, reply)
                e._smtp_vv_io(f"RCPT TO:<{rcpt}>", text)
                trace.append(f"RCPT TO: {text}")
                if st not in (250, 251):
                    return st, text
                st, reply = client.data(payload)
                text = e._smtp_trace_reply(st, reply)
                e._smtp_vv_io("DATA", text)
                trace.append(f"DATA: {text}")
                return st, text
            except smtplib.SMTPResponseException as ex:
                text = e._smtp_trace_reply(ex.smtp_code, ex.smtp_error)
                e._smtp_vv_io("DATA", text)
                return ex.smtp_code, text
            except Exception as ex:
                e._smtp_vv_io("DATA", str(ex))
                return None, str(ex)

        if smtp is None:
            smtp, recon_err, _ehlo = session()
            if smtp is None:
                e._mail_test_live_done("Message", f"not sent ({_clean(recon_err)})")
                msg_note = _note("WARN", f"Message was not sent ({_clean(recon_err)}).")
        if smtp is not None and msg_note is None:
            data_status, data_text = deliver(smtp)
            if data_status is None:
                try:
                    smtp.quit()
                except Exception:
                    pass
                smtp, recon_err, _ehlo = session()
                if smtp is None:
                    data_status, data_text = None, recon_err
                else:
                    data_status, data_text = deliver(smtp)
            sent_label = "1 MB" if send_n == _SEND_CAP else allowed
            if data_status in (250, 251):
                if allowed_n > send_n:
                    e._mail_test_live_done(
                        "Message",
                        f"accepted ({_clean(data_text)}). Sent {sent_label}, {allowed} was not uploaded",
                    )
                else:
                    e._mail_test_live_done("Message", f"accepted ({_clean(data_text)}). Sent {sent_label}")
            else:
                e._mail_test_live_done("Message", f"refused ({_clean(data_text)}). Sent {sent_label}")
                msg_note = _note("WARN", f"The message was refused ({_clean(data_text)}).")
    try:
        if smtp is not None:
            smtp.quit()
    except Exception:
        pass

    if allowed and refused:
        verdict = _note("OK", f"Size limit is enforced. {allowed} is allowed, {refused} is not.")
        enforced: bool | None = True
    elif allowed:
        verdict = _note("BAD", f"No size limit. {allowed} was allowed.")
        enforced = False
    elif stopped and refused:
        verdict = _note("WARN", f"Size check stopped after {refused} was refused ({_clean(stopped)}).")
        enforced = True
    elif stopped:
        verdict = _note("WARN", f"Could not check size ({_clean(stopped)}).")
        enforced = None
    elif refused:
        verdict = _note("OK", f"Size limit is under {refused}.")
        enforced = True
    else:
        verdict = _note("WARN", "Size check did not finish.")
        enforced = None
    detail = f"EHLO {ehlo_fact}. {verdict.split('|', 1)[1]}"
    notes = [verdict]
    if msg_note:
        notes.append(msg_note)
    return _result(
        e,
        notes=notes,
        trace=trace,
        start=start,
        advertised=advertised,
        limit=raw_limit if isinstance(raw_limit, int) else None,
        enforced=enforced,
        auth=auth_used,
        detail=detail,
    )


def _stream_flood_result(e) -> None:
    pp = e._ptprint_raw
    show = not e.use_json
    if (err := e.results.flood_error) is not None:
        pp(f"SIZE failed: {err}", bullet_type="VULN", condition=show, indent=4)
        return
    fr = e.results.flood
    if fr is None or not show:
        return
    bullets = {"OK": "NOTVULN", "BAD": "VULN", "WARN": "WARNING"}
    for note in fr.flood_notes:
        kind, sep, text = note.partition("|")
        if sep and kind in bullets and text.strip():
            pp(text.strip(), bullet_type=bullets[kind], condition=show, indent=4)


def run(ctx):
    e = eng(ctx)
    e.args.flood = True
    try:
        e.results.flood = test_flood(e)
    except Exception as ex:
        e.results.flood_error = str(ex)
        ctx.out(f"SIZE failed: {ex}", "ERROR", indent=4)
        return
    _stream_flood_result(e)
