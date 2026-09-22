"""Bounded Endpoint Mapper inventory on an existing, bound DCE connection."""
from __future__ import annotations

from impacket.dcerpc.v5 import epm
from impacket.dcerpc.v5.ndr import NULL
from impacket.dcerpc.v5.rpcrt import DCERPCException

from .rpc_auth import ept_lookup_handle_free


MAX_EPM_ENTRIES = 10000
MAX_EPM_PAGES = 256
EPM_PAGE_ENTRIES = 500
MAX_TOWER_BYTES = 65536


class EpmEnumerationLimit(RuntimeError):
    """Inventory stopped at a local safety limit, rather than an RPC failure."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def _unsigned(value, label):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError(f"Invalid Endpoint Mapper {label}")
    return value


def _octets(value):
    if isinstance(value, bytes):
        return value
    return b"".join(value)


def _decode_entry(entry):
    tower = entry["tower"]
    length = _unsigned(tower["tower_length"], "tower length")
    raw_tower = _octets(tower["tower_octet_string"])
    if not 2 <= length <= MAX_TOWER_BYTES or len(raw_tower) != length:
        raise ValueError("Invalid Endpoint Mapper tower length")
    parsed_tower = epm.EPMTower(raw_tower)
    if not parsed_tower["Floors"]:
        raise ValueError("Endpoint Mapper tower contains no floors")
    object_id = entry["object"]
    if not isinstance(object_id, bytes) or len(object_id) != 16:
        raise ValueError("Invalid Endpoint Mapper object UUID")
    return (object_id, raw_tower), {
        "object": object_id,
        "annotation": _octets(entry["annotation"]),
        "tower": parsed_tower,
    }


def iter_epm_entries(
    dce, *, max_entries=MAX_EPM_ENTRIES, max_pages=MAX_EPM_PAGES,
    page_size=EPM_PAGE_ENTRIES,
):
    """Yield Impacket-compatible entries and preserve earlier pages on failure.

    The caller connects/binds and disconnects, and should close this generator
    if processing an entry fails. EPM handles are opaque server contexts: their
    UUID may remain unchanged while the server advances through its database.
    A continuing page must therefore add an entry, not change its handle UUID.
    """
    for label, limit in (("entry limit", max_entries), ("page limit", max_pages), ("page size", page_size)):
        if _unsigned(limit, label) == 0:
            raise ValueError(f"Endpoint Mapper {label} must be positive")
    handle = epm.ept_lookup_handle_t()
    seen_entries = set()
    try:
        for _ in range(max_pages):
            requested = min(page_size, max_entries - len(seen_entries))
            request = epm.ept_lookup()
            request["inquiry_type"] = epm.RPC_C_EP_ALL_ELTS
            request["object"] = NULL
            request["Ifid"] = NULL
            request["vers_option"] = epm.RPC_C_VERS_ALL
            request["entry_handle"] = handle
            request["max_ents"] = requested
            response = dce.request(request, checkError=False)
            handle = response["entry_handle"]
            status = _unsigned(response["status"], "status")
            if status not in (0, epm.RPC_NO_MORE_ELEMENTS):
                raise DCERPCException(error_code=status)
            count = _unsigned(response["num_ents"], "entry count")
            entries = response["entries"]
            if not isinstance(entries, (list, tuple)) or len(entries) != count or count > requested:
                raise ValueError("Inconsistent Endpoint Mapper entry count")
            if status == epm.RPC_NO_MORE_ELEMENTS and count:
                raise ValueError("Endpoint Mapper returned entries after its terminal status")
            previous_count = len(seen_entries)
            for entry in entries:
                identity, decoded = _decode_entry(entry)
                if identity not in seen_entries:
                    seen_entries.add(identity)
                    yield decoded
            if handle.isNull() or status == epm.RPC_NO_MORE_ELEMENTS:
                return
            if len(seen_entries) == previous_count:
                raise RuntimeError("Endpoint Mapper enumeration did not advance")
            if len(seen_entries) >= max_entries:
                raise EpmEnumerationLimit("endpoint_limit_reached")
        raise EpmEnumerationLimit("page_limit_reached")
    finally:
        if not handle.isNull():
            try:
                close = ept_lookup_handle_free()
                close["entry_handle"] = handle
                dce.request(close, checkError=False)
            except Exception:
                # The caller also disconnects; cleanup must not hide the cause
                # of an incomplete inventory or discard already yielded data.
                pass
