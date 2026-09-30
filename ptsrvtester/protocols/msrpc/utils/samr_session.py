"""Read-only SAMR connection and bounded enumeration helpers."""
from __future__ import annotations

from contextlib import contextmanager

from impacket import nt_errors
from impacket.dcerpc.v5 import samr, transport
from impacket.smbconnection import SMBConnection, SessionError


_AUTH_DENIED = frozenset(
    getattr(nt_errors, name)
    for name in (
        "STATUS_ACCESS_DENIED", "STATUS_LOGON_FAILURE", "STATUS_NO_SUCH_USER",
        "STATUS_WRONG_PASSWORD", "STATUS_WRONG_PASSWORD_CORE",
        "STATUS_ACCOUNT_RESTRICTION", "STATUS_INVALID_LOGON_HOURS",
        "STATUS_INVALID_WORKSTATION", "STATUS_PASSWORD_EXPIRED",
        "STATUS_ACCOUNT_DISABLED", "STATUS_ACCOUNT_EXPIRED",
        "STATUS_PASSWORD_MUST_CHANGE", "STATUS_ACCOUNT_LOCKED_OUT",
        "STATUS_LOGON_TYPE_NOT_GRANTED",
    )
)
MAX_ENUMERATION_PAGES = 256
MAX_SAM_DOMAINS = 1024
ENUMERATION_PAGE_BYTES = 16384


class SamrDenied(Exception):
    """A known access/authentication refusal, with a credential-free reason."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def samr_u32(value, label: str) -> int:
    """Accept plain and NDR unsigned values without accepting invalid ranges."""
    if not isinstance(value, int):
        try:
            value = value["Data"]
        except (KeyError, TypeError):
            pass
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"Invalid SAMR {label}")
    if not 0 <= value <= 0xFFFFFFFF:
        raise ValueError(f"Invalid SAMR {label}")
    return value


def samr_array(value, count: int, label: str):
    """Validate an NDR array and its declared length (including NULL/empty)."""
    if count == 0 and (value is None or value == 0 or value == b""):
        return []
    if not isinstance(value, (list, tuple)) or len(value) != count:
        raise ValueError(f"Inconsistent SAMR {label} count")
    return value


def enumeration_page(response):
    """Return a validated SAMR enumeration page and its continuation state."""
    status = samr_u32(response["ErrorCode"], "enumeration status")
    if status not in (0, nt_errors.STATUS_MORE_ENTRIES, nt_errors.STATUS_NO_MORE_ENTRIES):
        raise samr.DCERPCSessionError(error_code=status)
    count = samr_u32(response["CountReturned"], "enumeration count")
    context = samr_u32(response["EnumerationContext"], "enumeration context")
    buffer = response["Buffer"]
    if count == 0 and (buffer is None or buffer == 0 or buffer == b""):
        entries = []
    else:
        if samr_u32(buffer["EntriesRead"], "entries read") != count:
            raise ValueError("Inconsistent SAMR enumeration counts")
        entries = samr_array(buffer["Buffer"], count, "enumeration entries")
    if status == nt_errors.STATUS_MORE_ENTRIES and not entries:
        raise ValueError("SAMR enumeration returned an empty continuation page")
    if status == nt_errors.STATUS_NO_MORE_ENTRIES and entries:
        raise ValueError("SAMR enumeration returned entries after its terminal status")
    return entries, context, status == nt_errors.STATUS_MORE_ENTRIES


def iter_samr_domains(engine, dce, server_handle):
    """Yield domain names, bounding requests even for a malformed RPC server."""
    context = 0
    seen_contexts = {context}
    seen_names = set()
    for _ in range(MAX_ENUMERATION_PAGES):
        try:
            response = samr.hSamrEnumerateDomainsInSamServer(
                dce, server_handle, enumerationContext=context,
                preferedMaximumLength=ENUMERATION_PAGE_BYTES,
            )
        except samr.DCERPCSessionError as exc:
            if engine._samr_error_code(exc) not in (
                nt_errors.STATUS_MORE_ENTRIES, nt_errors.STATUS_NO_MORE_ENTRIES
            ) or exc.get_packet() is None:
                raise
            response = exc.get_packet()
        entries, next_context, more = enumeration_page(response)
        for entry in entries:
            name = str(entry["Name"]).rstrip("\x00")
            if not name:
                raise ValueError("SAMR domain name is empty")
            folded = name.casefold()
            if folded in seen_names:
                raise ValueError("SAMR enumeration repeated a domain")
            if len(seen_names) >= MAX_SAM_DOMAINS:
                raise RuntimeError("SAMR domain enumeration safety limit reached")
            seen_names.add(folded)
            yield name
        if not more:
            return
        if next_context in seen_contexts:
            raise RuntimeError("SAMR domain enumeration did not advance")
        seen_contexts.add(next_context)
        context = next_context
    raise RuntimeError("SAMR domain enumeration page limit reached")


@contextmanager
def samr_session(engine):
    """Authenticate once, open a minimal SAM server handle, and always close it."""
    smb = dce = server_handle = None
    logged_in = False
    try:
        smb = SMBConnection(
            engine.args.ip, engine.args.ip, sess_port=engine.smb_port,
            timeout=engine.connect_timeout,
        )
        try:
            smb.login(
                engine.args.username, engine.args.password,
                getattr(engine.args, "domain", "") or "", ntlmFallback=False,
            )
            logged_in = True
        except SessionError as exc:
            if engine._samr_error_code(exc) in _AUTH_DENIED:
                raise SamrDenied("authentication_denied") from exc
            raise
        if smb.isGuestSession():
            raise SamrDenied("guest_session")
        rpc_transport = transport.DCERPCTransportFactory(
            f"ncacn_np:{engine.args.ip}[\\pipe\\samr]"
        )
        rpc_transport.set_dport(engine.smb_port)
        rpc_transport.set_connect_timeout(engine.connect_timeout)
        rpc_transport.setRemoteHost(engine.args.ip)
        rpc_transport.set_smb_connection(smb)
        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        connected = samr.hSamrConnect5(
            dce, desiredAccess=(
                samr.SAM_SERVER_ENUMERATE_DOMAINS | samr.SAM_SERVER_LOOKUP_DOMAIN
            ),
        )
        server_handle = connected["ServerHandle"]
        yield dce, server_handle
    except Exception as exc:
        if engine._samr_access_denied(exc):
            raise SamrDenied("samr_access_denied") from exc
        raise
    finally:
        engine._close_samr_handle(dce, server_handle)
        engine._disconnect(dce)
        if smb is not None and logged_in:
            engine._close_smb(smb)
        elif smb is not None:
            try:
                smb.close()
            except Exception:
                pass
