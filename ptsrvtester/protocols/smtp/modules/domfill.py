"""DOMFILL — MAIL FROM local-part autofills the sender domain."""
import re

from ..utils.helpers import *
from ..utils.results import *
from ..utils.registry import *

from ._common import ensure_info


__MODULELABEL__ = "Domain autofill"
__MODULECODE__ = "DOMFILL"
__ORDER__ = 42

_LOCAL = "test"
_MAIL = f"<{_LOCAL}>"
_FILLED = re.compile(
    rf"(?i)<?{_LOCAL}@([a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?)*)"
)


def _filled_domain(reply: str) -> str | None:
    """Domain the server appended after ``test@``, if the reply echoes one."""
    match = _FILLED.search(reply or "")
    if not match:
        return None
    domain = match.group(1).strip(".")
    if not domain or domain.lower() == _LOCAL:
        return None
    return domain


def test_domfill(e) -> DomfillResult:
    """Send ``MAIL FROM:<test>`` and see whether the reply names ``test@domain``."""
    smtp = e.smtp
    if smtp is None:
        smtp = e.get_smtp_handler()
        e.smtp = smtp
    try:
        smtp.docmd("RSET")
    except Exception:
        pass
    try:
        status, reply = smtp.docmd("MAIL FROM:", _MAIL)
    except Exception as ex:
        e._smtp_vv_io(f"MAIL FROM:{_MAIL}", str(ex))
        raise
    text = " ".join(e.bytes_to_str(reply).split()) if reply else ""
    e._smtp_vv_io(f"MAIL FROM:{_MAIL}", f"{status} {text}".strip())
    e.end_if_blocked(status, reply)
    try:
        smtp.docmd("RSET")
    except Exception:
        pass
    domain = _filled_domain(text)
    return DomfillResult(
        vulnerable=domain is not None,
        domain=domain,
        status=int(status) if status is not None else None,
        reply=text,
    )


def _stream_domfill_result(e) -> None:
    pp = e._ptprint_raw
    show = not e.use_json
    if (err := e.results.domfill_error) is not None:
        pp(f"Sender domain autofill failed: {err}", bullet_type="VULN", condition=show, indent=4)
        return
    result = e.results.domfill
    if result is None:
        return
    if result.vulnerable and result.domain:
        pp(f"Domain name was disclosed: {result.domain}", bullet_type="VULN", condition=show, indent=4)
    else:
        pp("Domain name was not disclosed", bullet_type="NOTVULN", condition=show, indent=4)


def run(ctx):
    e = ensure_info(ctx, get_commands=True)
    if getattr(e.results, "info_error", None):
        return
    try:
        e.results.domfill = test_domfill(e)
    except Exception as ex:
        e.results.domfill_error = str(ex)
        ctx.out(f"Sender domain autofill failed: {ex}", "ERROR", indent=4)
        return
    _stream_domfill_result(e)
