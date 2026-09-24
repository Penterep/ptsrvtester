"""RCPTDUP — duplicate RCPT TO."""
import secrets, smtplib, socket, sys, threading, time

from ..._base import Out

from ..utils.helpers import *
from ..utils.results import *
from ..utils.registry import *

from ._common import eng


__MODULELABEL__ = ""
__MODULECODE__ = "RCPTDUP"
__ORDER__ = 220


def test_rcpt_duplicate(e) -> RcptDuplicateResult:
    """Many RCPT TO for the same address in one MAIL transaction (-rdd / --rcpt-duplicate)."""
    e._ensure_initial_info(fail_label='-rdd')
    raw = (e.args.rcpt_to or '').strip()
    if not raw or '@' not in raw:
        raise ValueError('-rdd requires -r/--rcpt-to as a full address (user@domain)')
    dom = raw.split('@', 1)[1].strip().lower().rstrip('.')
    display_to = raw.strip('<>').strip()
    rcpt_bracket = raw if raw.startswith('<') and raw.endswith('>') else f'<{display_to}>'
    n = int(e.args.rcpt_duplicate or RCPT_DUP_DEFAULT)
    send_data = bool(getattr(e.args, 'send', False))
    probe_uuid = e._new_mail_test_id() if send_data else None
    smtp: smtplib.SMTP | None = None
    try:
        smtp = e.get_smtp_handler(timeout=45.0)
        code, reply = smtp.docmd('EHLO', e.fqdn)
        if code != 250:
            raise RuntimeError(f'EHLO failed: [{code}] {e.bytes_to_str(reply).strip()[:400]}')
        try:
            smtp.docmd('RSET')
        except Exception:
            pass
        ok_mail, mail_used = e._try_mail_from_for_rcpt_probe(smtp, dom)
        if not ok_mail:
            raise RuntimeError('MAIL FROM rejected for all candidates (cannot probe RCPT)')
        replies: list[tuple[int, str]] = []
        for i in range(n):
            st, rp = smtp.docmd('RCPT TO:', rcpt_bracket)
            rps = e.bytes_to_str(rp).strip()[:500]
            replies.append((st, rps))
            e._smtp_vv_io(f'RCPT TO:{rcpt_bracket}', e._smtp_trace_reply(st, rp))
        rcpt_ok = tuple(replies)
        first_fail: int | None = None
        for i, (st, _) in enumerate(rcpt_ok):
            if st not in (250, 251, 252):
                first_fail = i
                break
        all_2xx = first_fail is None
        data_sent = False
        dcode: int | None = None
        drep: str | None = None
        if send_data and all_2xx:
            raw_msg = e._outbound_minimal_probe(from_addr=f'rdd@{dom}', message_id_tag='rdd', domain=dom, probe_uuid=probe_uuid, to_addr=display_to)
            try:
                dcode, drp = smtp.data(raw_msg)
                drep = e.bytes_to_str(drp).strip()[:500]
                data_sent = dcode == 250
                if send_data and e.args.debug and (not e.use_json):
                    e._stream_smtp_trace_line(e._data_trace_entry(raw_msg, dcode, drp))
            except Exception as ex:
                drep = str(ex).strip()[:500]
                data_sent = False
        else:
            try:
                smtp.docmd('RSET')
            except Exception:
                pass
        return RcptDuplicateResult(recipient=display_to, duplicate_count=n, rcpt_replies=rcpt_ok, all_rcpt_2xx=all_2xx, first_failure_index=first_fail, data_sent=data_sent, data_code=dcode, data_reply_snippet=drep, mail_from_used=mail_used, probe_uuid=probe_uuid)
    finally:
        if smtp is not None:
            try:
                smtp.quit()
            except Exception:
                try:
                    smtp.close()
                except Exception:
                    pass


def _stream_rcpt_duplicate_result(e) -> None:
    pp = e._ptprint_raw
    show = not e.use_json
    if (err := e.results.rcpt_duplicate_error) is not None:
        if _rcpt_duplicate_error_is_environmental(err):
            pp(f'Duplicate RCPT probe could not run: {err}', bullet_type='TITLE', condition=show, indent=4)
        else:
            pp(f'Duplicate RCPT probe failed: {err}', bullet_type='VULN', condition=show, indent=4)
        return
    r = e.results.rcpt_duplicate
    if r is None:
        return
    if r.all_rcpt_2xx:
        bullet = 'VULN' if r.duplicate_count >= 3 else 'TITLE'
        pp(f'All {r.duplicate_count} duplicate RCPT TO accepted for {r.recipient}', bullet_type=bullet, condition=show, indent=4)
    else:
        fi = r.first_failure_index
        c = r.rcpt_replies[fi][0] if fi is not None and fi < len(r.rcpt_replies) else '?'
        pp(f"Duplicate RCPT not fully accepted (first non-2xx at #{(fi + 1 if fi is not None else '?')}: {c})", bullet_type='NOTVULN', condition=show, indent=4)
    if r.data_sent and r.probe_uuid:
        e._pp_mail_probe_line(pp, show, accepted=True, sent_msg=e._mail_sent_inbox_msg(r.recipient, r.probe_uuid), indent=4)
    elif getattr(e.args, 'send', False) and (not r.data_sent):
        extra = f': {r.data_reply_snippet}' if r.data_reply_snippet else ''
        pp(f'DATA not completed{extra}', bullet_type='TITLE', condition=show, indent=4)


def run(ctx):
    e = eng(ctx)
    try:
        e.results.rcpt_duplicate = test_rcpt_duplicate(e)
    except Exception as ex:
        e.results.rcpt_duplicate_error = str(ex)
        ctx.out(f"RCPTDUP failed: {ex}", "ERROR", indent=4)
        return
    _stream_rcpt_duplicate_result(e)
