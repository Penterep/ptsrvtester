"""Bounded SRVS share inventory using a caller-owned SMB session."""
from __future__ import annotations

from impacket.dcerpc.v5 import srvs, transport
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.nt_errors import STATUS_ACCESS_DENIED
from impacket.system_errors import ERROR_ACCESS_DENIED, ERROR_MORE_DATA


MAX_SHARE_PAGES = 256
MAX_SHARES = 10000
SHARE_PAGE_BYTES = 16384


def _u32(value, label):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError(f"Invalid SRVS {label}")
    return value


def _error_code(exc):
    code = getattr(exc, "error_code", None)
    if code is not None:
        return code
    for name in ("get_error_code", "getErrorCode"):
        getter = getattr(exc, name, None)
        if callable(getter):
            return getter()
    return None


def _access_denied(exc):
    return _error_code(exc) in (ERROR_ACCESS_DENIED, STATUS_ACCESS_DENIED) or (
        isinstance(exc, DCERPCException)
        and getattr(exc, "error_string", None) == "rpc_s_access_denied"
    )


def _page(response):
    status = _u32(response["ErrorCode"], "enumeration status")
    if status not in (0, ERROR_MORE_DATA):
        raise srvs.DCERPCSessionError(error_code=status)
    info = response["InfoStruct"]
    if _u32(info["Level"], "information level") != 1:
        raise ValueError("Unexpected SRVS share information level")
    if _u32(info["ShareInfo"]["tag"], "information tag") != 1:
        raise ValueError("Unexpected SRVS share information tag")
    container = info["ShareInfo"]["Level1"]
    count = _u32(container["EntriesRead"], "share count")
    entries = container["Buffer"]
    if count == 0 and (entries is None or entries == 0 or entries == b""):
        entries = []
    if not isinstance(entries, (list, tuple)) or len(entries) != count:
        raise ValueError("Inconsistent SRVS share count")
    # TotalEntries is only an estimate and does not determine completion.
    _u32(response["TotalEntries"], "total share count")
    more = status == ERROR_MORE_DATA
    context = 0
    if more:
        if not entries:
            raise ValueError("SRVS returned an empty continuation page")
        context = response["ResumeHandle"]
        # Impacket models this handle as a signed LONG pointer. Preserve its
        # signed representation when passing a high-bit handle back to SRVS.
        if (isinstance(context, bool) or not isinstance(context, int)
                or not -0x80000000 <= context <= 0x7FFFFFFF):
            raise ValueError("Invalid SRVS resume handle")
    return entries, context, more


def _share(entry):
    name = entry["shi1_netname"]
    remark = entry["shi1_remark"]
    if not isinstance(name, str) or not name.rstrip("\x00"):
        raise ValueError("SRVS share response contains an invalid name")
    if remark is None or remark == 0 or remark == b"":
        remark = None
    elif isinstance(remark, str):
        remark = remark.rstrip("\x00")
    else:
        raise ValueError("SRVS share response contains an invalid remark")
    return {
        "name": name.rstrip("\x00"),
        "type": _u32(entry["shi1_type"], "share type"),
        "remark": remark,
    }


def enumerate_shares(smb, *, limit=MAX_SHARES, max_pages=MAX_SHARE_PAGES):
    """Read level-1 shares without logging in again or closing ``smb``.

    ``error`` holds an exception only for operational failures; callers must
    sanitize it and omit it from JSON. All other fields are JSON-compatible.
    Earlier shares remain available after denied, malformed, or failed pages.
    """
    if (isinstance(limit, bool) or not isinstance(limit, int)
            or not 1 <= limit <= MAX_SHARES):
        raise ValueError(f"Share limit must be between 1 and {MAX_SHARES}")
    if (isinstance(max_pages, bool) or not isinstance(max_pages, int)
            or not 1 <= max_pages <= MAX_SHARE_PAGES):
        raise ValueError(f"Share page limit must be between 1 and {MAX_SHARE_PAGES}")
    result = {
        "status": "error", "reason": None, "shares": [], "returned": 0,
        "limit": limit, "truncated": False, "pages": 0, "error": None,
    }
    dce = None
    context = 0
    seen_contexts = {context}
    seen_names = set()
    try:
        rpc_transport = transport.SMBTransport(
            smb.getRemoteName(), remote_host=smb.getRemoteHost(),
            filename=r"\srvsvc", smb_connection=smb,
        )
        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(srvs.MSRPC_UUID_SRVS)
        for _ in range(max_pages):
            result["pages"] += 1
            try:
                response = srvs.hNetrShareEnum(
                    dce, 1, resumeHandle=context,
                    preferedMaximumLength=SHARE_PAGE_BYTES,
                    serverName="\\\\" + smb.getRemoteHost(),
                )
            except srvs.DCERPCSessionError as exc:
                if _error_code(exc) != ERROR_MORE_DATA or exc.get_packet() is None:
                    raise
                response = exc.get_packet()
            entries, next_context, more = _page(response)
            for entry in entries:
                if len(result["shares"]) >= limit:
                    result.update(status="partial", reason="share_limit_reached", truncated=True)
                    return result
                item = _share(entry)
                folded = item["name"].casefold()
                if folded in seen_names:
                    raise ValueError("SRVS enumeration repeated a share")
                seen_names.add(folded)
                result["shares"].append(item)
                result["returned"] += 1
            if not more:
                result.update(status="complete")
                return result
            if next_context in seen_contexts:
                raise ValueError("SRVS enumeration resume handle did not advance")
            if len(result["shares"]) >= limit:
                result.update(status="partial", reason="share_limit_reached", truncated=True)
                return result
            seen_contexts.add(next_context)
            context = next_context
        result.update(status="partial", reason="share_page_limit_reached", truncated=True)
    except Exception as exc:
        if _access_denied(exc):
            result.update(
                status="partial" if result["shares"] else "denied",
                reason="share_enumeration_denied",
            )
        else:
            result.update(
                status="partial" if result["shares"] else "error",
                reason="operational_error", error=exc,
            )
    finally:
        if dce is not None:
            try:
                dce.disconnect()
            except Exception:
                pass
    return result
