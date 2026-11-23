from impacket.smbconnection import SMBConnection

from impacket.dcerpc.v5 import srvs, transport
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.nt_errors import STATUS_ACCESS_DENIED
from impacket.system_errors import ERROR_ACCESS_DENIED, ERROR_MORE_DATA


MAX_SHARE_PAGES = 256
MAX_SHARES = 10000
SHARE_PAGE_BYTES = 16384


def rpc_error_code(exc: Exception) -> int | None:
    code = getattr(exc, "error_code", None)
    if code is not None:
        return code
    for name in ("get_error_code", "getErrorCode"):
        getter = getattr(exc, name, None)
        if callable(getter):
            return getter()
    return None


def is_rpc_access_denied(exc: Exception) -> bool:
    return rpc_error_code(exc) in (ERROR_ACCESS_DENIED, STATUS_ACCESS_DENIED) or (
        isinstance(exc, DCERPCException)
        and getattr(exc, "error_string", None) == "rpc_s_access_denied"
    )


def parse_share_page(response) -> tuple[list, int, bool]:
    status = response["ErrorCode"]
    if status not in (0, ERROR_MORE_DATA):
        raise srvs.DCERPCSessionError(error_code=status)

    info = response["InfoStruct"]
    if info["Level"] != 1:
        raise ValueError("Unexpected SRVS share information level")
    share_info = info["ShareInfo"]
    if share_info["tag"] != 1:
        raise ValueError("Unexpected SRVS share information tag")

    container = share_info["Level1"]
    count = container["EntriesRead"]
    entries = container["Buffer"]
    if count == 0 and entries in (None, 0, b""):
        entries = []
    if not isinstance(entries, (list, tuple)) or len(entries) != count:
        raise ValueError("Inconsistent SRVS share count")

    more = status == ERROR_MORE_DATA
    if not more:
        return list(entries), 0, False
    if not entries:
        raise ValueError("SRVS returned an empty continuation page")

    context = response["ResumeHandle"]
    if (
        isinstance(context, bool)
        or not isinstance(context, int)
        or not -0x80000000 <= context <= 0x7FFFFFFF
    ):
        raise ValueError("Invalid SRVS resume handle")
    return list(entries), context, True


def decode_share_type(share_type: int) -> str:
    base_type = share_type & srvs.STYPE_MASK
    names = {
        srvs.STYPE_DISKTREE: "Disk tree",
        srvs.STYPE_PRINTQ: "Print queue",
        srvs.STYPE_DEVICE: "Device",
        srvs.STYPE_IPC: "IPC",
    }
    description = names.get(base_type, f"Unknown type ({base_type})")
    flags = (
        (srvs.STYPE_SPECIAL, "special"),
        (srvs.STYPE_TEMPORARY, "temporary"),
        (srvs.STYPE_CLUSTER_FS, "cluster filesystem"),
        (srvs.STYPE_CLUSTER_SOFS, "Scale-Out File Server"),
        (srvs.STYPE_CLUSTER_DFS, "cluster DFS"),
    )
    for flag, label in flags:
        if share_type & flag:
            description += f", {label}"

    known_bits = srvs.STYPE_MASK | sum(flag for flag, _ in flags)
    unknown_bits = share_type & ~known_bits
    if unknown_bits:
        description += f", unknown flags 0x{unknown_bits:08x}"
    return description


def parse_share(entry) -> dict:
    name = entry["shi1_netname"]
    share_type = entry["shi1_type"]
    return {
        "name": name.rstrip("\x00"),
        "type_code": share_type,
        "type_name": decode_share_type(share_type),
        "remark": entry["shi1_remark"].rstrip("\x00"),
    }


def enumerate_shares(smb_client: SMBConnection) -> dict:
    """Enumerate SRVS shares over an existing SMB session without closing it."""
    result = {
        "status": "error",
        "reason": None,
        "shares": [],
        "pages": 0,
        "error": None,
    }
    dce = None
    context = 0
    seen_contexts = {context}
    seen_names = set()

    try:
        rpc_transport = transport.SMBTransport(
            smb_client.getRemoteName(),
            remote_host=smb_client.getRemoteHost(),
            filename=r"\srvsvc",
            smb_connection=smb_client,
        )
        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(srvs.MSRPC_UUID_SRVS)

        for _ in range(MAX_SHARE_PAGES):
            result["pages"] += 1
            try:
                response = srvs.hNetrShareEnum(
                    dce,
                    1,
                    resumeHandle=context,
                    preferedMaximumLength=SHARE_PAGE_BYTES,
                    serverName="\\\\" + smb_client.getRemoteHost(),
                )
            except srvs.DCERPCSessionError as exc:
                if (
                    rpc_error_code(exc) != ERROR_MORE_DATA
                    or exc.get_packet() is None
                ):
                    raise
                response = exc.get_packet()

            entries, next_context, more = parse_share_page(response)
            for entry in entries:
                if len(result["shares"]) >= MAX_SHARES:
                    result.update(
                        status="partial",
                        reason="share_limit_reached",
                    )
                    return result

                share = parse_share(entry)
                folded_name = share["name"].casefold()
                if folded_name in seen_names:
                    raise ValueError("SRVS enumeration repeated a share")
                seen_names.add(folded_name)
                result["shares"].append(share)

            if not more:
                result.update(status="complete")
                return result
            if next_context in seen_contexts:
                raise ValueError("SRVS enumeration resume handle did not advance")
            if len(result["shares"]) >= MAX_SHARES:
                result.update(
                    status="partial",
                    reason="share_limit_reached",
                )
                return result
            seen_contexts.add(next_context)
            context = next_context

        result.update(
            status="partial",
            reason="share_page_limit_reached",
        )
    except Exception as exc:
        if is_rpc_access_denied(exc):
            result.update(
                status="partial" if result["shares"] else "denied",
                reason="share_enumeration_denied",
            )
        else:
            result.update(
                status="partial" if result["shares"] else "error",
                reason="operational_error",
                error=exc,
            )
    finally:
        if dce is not None:
            try:
                dce.disconnect()
            except Exception:
                pass
    return result
