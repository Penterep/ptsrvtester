"""Bounded, read-only SAM user details from the queried server.

UserAllInformation is queried with separate USER_READ_ACCOUNT and
USER_READ_LOGON handles. MS-SAMR 3.1.5.5.5.2 requires clients to honor
WhichFields: an unreturned zero-filled field is not a measured zero.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from impacket.dcerpc.v5 import samr
from impacket.nt_errors import (
    STATUS_INVALID_INFO_CLASS,
    STATUS_MORE_ENTRIES,
    STATUS_NONE_MAPPED,
    STATUS_NO_MORE_ENTRIES,
    STATUS_NO_SUCH_USER,
    STATUS_NOT_SUPPORTED,
)

from .samr_policy import old_large_integer_value
from .samr_session import (
    ENUMERATION_PAGE_BYTES,
    MAX_ENUMERATION_PAGES,
    SamrDenied,
    enumeration_page,
    iter_samr_domains,
    samr_array,
    samr_session,
    samr_u32,
)


_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_ACCOUNT_FIELDS = (
    ("passwordLastSet", "PasswordLastSet", samr.USER_ALL_PASSWORDLASTSET, "not_set"),
    ("accountExpires", "AccountExpires", samr.USER_ALL_ACCOUNTEXPIRES, "never"),
    ("accountControl", "UserAccountControl", samr.USER_ALL_USERACCOUNTCONTROL, None),
)
_LOGON_FIELDS = (
    ("lastLogon", "LastLogon", samr.USER_ALL_LASTLOGON, "unknown"),
    ("lastLogoff", "LastLogoff", samr.USER_ALL_LASTLOGOFF, "not_set"),
    ("badPasswordCount", "BadPasswordCount", samr.USER_ALL_BADPASSWORDCOUNT, None),
    ("logonCount", "LogonCount", samr.USER_ALL_LOGONCOUNT, None),
)


def parse_samr_timestamp(value, *, zero_meaning: str, expiry: bool = False) -> dict:
    """Preserve exact FILETIME ticks, sentinel meaning and a UTC rendering.

    Decimal strings keep 100 ns values exact for JSON/JavaScript consumers.
    A returned zero lastLogon means the time is unknown. It remains a
    complete measurement with raw100ns="0", distinct from an unreturned
    field, and does not establish whether the account has logged on.
    """
    raw = old_large_integer_value(value)
    result = {
        "status": "complete", "reason": None, "raw100ns": str(raw),
        "utc": None, "meaning": "timestamp",
    }
    if raw == 0:
        result["meaning"] = zero_meaning
    elif expiry and raw == (1 << 63) - 1:
        result["meaning"] = "never"
    elif raw < 0:
        result.update(status="error", reason="invalid_timestamp", meaning="unknown")
    else:
        seconds, remainder = divmod(raw, 10_000_000)
        try:
            stamp = _EPOCH + timedelta(seconds=seconds)
            # Keep all seven fractional digits rather than rounding to microseconds.
            result["utc"] = stamp.strftime("%Y-%m-%dT%H:%M:%S") + f".{remainder:07d}Z"
        except (OverflowError, ValueError):
            result.update(status="error", reason="timestamp_out_of_range", meaning="unknown")
    return result


def _unavailable_field(status: str, reason: str, timestamp: bool) -> dict:
    value = {"status": status, "reason": reason}
    if timestamp:
        value.update(raw100ns=None, utc=None, meaning="unknown")
    else:
        value["value"] = None
    return value


def _unavailable_section(fields, status: str, reason: str) -> dict:
    return {
        "status": status,
        "reason": reason,
        **{
            key: _unavailable_field(status, reason, zero is not None)
            for key, _, _, zero in fields
        },
    }


def parse_user_information(information, fields) -> dict:
    """Extract only explicitly returned, nonsensitive fields from UserAll."""
    mask = samr_u32(information["WhichFields"], "WhichFields mask")
    section = {"status": "complete", "reason": None}
    for key, wire_key, bit, zero_meaning in fields:
        if not mask & bit:
            section[key] = _unavailable_field("unknown", "not_returned", zero_meaning is not None)
            continue
        try:
            raw = information[wire_key]
            if zero_meaning is not None:
                value = parse_samr_timestamp(raw, zero_meaning=zero_meaning, expiry=key == "accountExpires")
            else:
                number = samr_u32(raw, wire_key)
                maximum = 0xFFFFFFFF if key == "accountControl" else 0xFFFF
                if not 0 <= number <= maximum:
                    raise ValueError("invalid SAMR unsigned value")
                value = {"status": "complete", "reason": None, "value": number}
            section[key] = value
        except (KeyError, TypeError, ValueError, OverflowError):
            section[key] = _unavailable_field("error", "malformed_value", zero_meaning is not None)
    if any(section[key]["status"] != "complete" for key, *_ in fields):
        section.update(status="partial", reason="incomplete_fields")
    return section


def _error_status(engine, exc: Exception) -> tuple[str, str]:
    if engine._samr_access_denied(exc):
        return "denied", "access_denied"
    if engine._samr_error_code(exc) in {STATUS_INVALID_INFO_CLASS, STATUS_NOT_SUPPORTED}:
        return "unsupported", "information_not_supported"
    if engine._samr_error_code(exc) == STATUS_NO_SUCH_USER:
        return "unavailable", "user_no_longer_exists"
    return "error", "operational_error"


def _record_error(engine, exc: Exception) -> None:
    engine.record_module_error("SAMRUSERINFO", engine._sanitized_samr_error(exc))


def _query_section(engine, dce, domain_handle, rid: int, access: int, fields) -> dict:
    handle = None
    try:
        handle = samr.hSamrOpenUser(dce, domain_handle, desiredAccess=access, userId=rid)["UserHandle"]
        response = samr.hSamrQueryInformationUser(
            dce, handle,
            userInformationClass=samr.USER_INFORMATION_CLASS.UserAllInformation,
        )
        result = parse_user_information(response["Buffer"]["All"], fields)
        if any(result[key]["status"] == "error" for key, *_ in fields):
            engine.record_module_error("SAMRUSERINFO", "Malformed SAMR user information field")
        return result
    except Exception as exc:
        status, reason = _error_status(engine, exc)
        if status == "error":
            _record_error(engine, exc)
        return _unavailable_section(fields, status, reason)
    finally:
        engine._close_samr_handle(dce, handle)


def _query_user(engine, dce, domain_handle, domain: dict, name: str, rid: int) -> dict:
    user = {
        "name": name, "rid": rid, "sid": f"{domain['sid']}-{rid}",
        "sourceHost": engine.args.ip, "sourceDomain": domain["name"],
        "status": "complete", "reason": None,
    }
    user["account"] = _query_section(engine, dce, domain_handle, rid, samr.USER_READ_ACCOUNT, _ACCOUNT_FIELDS)
    user["logon"] = _query_section(engine, dce, domain_handle, rid, samr.USER_READ_LOGON, _LOGON_FIELDS)
    statuses = {user[section]["status"] for section in ("account", "logon")}
    if statuses != {"complete"}:
        status = next(iter(statuses)) if len(statuses) == 1 and "partial" not in statuses else "partial"
        user.update(status=status, reason="incomplete_user_information")
    return user


def _entry(entry) -> tuple[str, int]:
    name = str(entry["Name"]).rstrip("\x00")
    rid = samr_u32(entry["RelativeId"], "user RID")
    if not name:
        raise ValueError("malformed SAMR user identity")
    return name, rid


def _enumerate_users(engine, dce, handle, domain: dict, limit: int) -> bool:
    """Append records as pages arrive, so a later failure preserves evidence."""
    context = 0
    contexts: set[int] = set()
    seen: dict[int, str] = {}
    for _ in range(MAX_ENUMERATION_PAGES):
        try:
            response = samr.hSamrEnumerateUsersInDomain(
                dce, handle, userAccountControl=samr.USER_NORMAL_ACCOUNT,
                enumerationContext=context, preferedMaximumLength=ENUMERATION_PAGE_BYTES,
            )
        except samr.DCERPCSessionError as exc:
            status = engine._samr_error_code(exc)
            if status == STATUS_NO_MORE_ENTRIES:
                return False
            if status != STATUS_MORE_ENTRIES or exc.get_packet() is None:
                raise
            response = exc.get_packet()
        entries, next_context, more = enumeration_page(response)
        added = 0
        for item in entries:
            name, rid = _entry(item)
            if rid in seen:
                if seen[rid] != name:
                    raise ValueError("SAMR returned conflicting names for one RID")
                continue
            if len(domain["users"]) >= limit:
                return True
            domain["users"].append(_query_user(engine, dce, handle, domain, name, rid))
            seen[rid] = name
            added += 1
        if not more:
            return False
        if len(domain["users"]) >= limit:
            return True
        if not added or next_context == context or next_context in contexts:
            raise RuntimeError("SAMR user enumeration did not advance")
        contexts.add(context)
        context = next_context
    raise RuntimeError("SAMR user enumeration exceeded its page limit")


def _lookup_user(engine, dce, handle, domain: dict, name: str) -> None:
    try:
        response = samr.hSamrLookupNamesInDomain(dce, handle, [name])
    except samr.DCERPCSessionError as exc:
        if engine._samr_error_code(exc) in {STATUS_NONE_MAPPED, STATUS_NO_SUCH_USER}:
            domain["reason"] = "user_not_found"
            return
        raise
    status = samr_u32(response["ErrorCode"], "lookup status")
    if status in {STATUS_NONE_MAPPED, STATUS_NO_SUCH_USER}:
        domain["reason"] = "user_not_found"
        return
    if status:
        raise samr.DCERPCSessionError(error_code=status)
    rids = response["RelativeIds"]
    uses = response["Use"]
    if samr_u32(rids["Count"], "lookup RID count") != 1 or samr_u32(uses["Count"], "lookup type count") != 1:
        raise ValueError("SAMR name lookup returned an unexpected count")
    ids = samr_array(rids["Element"], 1, "lookup RIDs")
    types = samr_array(uses["Element"], 1, "lookup types")
    rid = samr_u32(ids[0], "lookup RID")
    kind = samr_u32(types[0], "lookup type")
    if kind != samr.SID_NAME_USE.SidTypeUser:
        domain["reason"] = "selected_name_is_not_user"
        return
    domain["users"].append(_query_user(engine, dce, handle, domain, name, rid))


def query_samr_user_info(engine) -> dict:
    limit = int(getattr(engine.args, "samr_max_users", 1000))
    selected_user = getattr(engine.args, "samr_user", None)
    selected_domain = getattr(engine.args, "samr_domain", None)
    result = {
        "status": "error", "reason": None,
        "sourceHost": engine.args.ip, "logonScope": "queried_server",
        "limit": limit, "returned": 0, "truncated": False,
        "selectedUser": selected_user, "selectedDomain": selected_domain,
        "domains": [],
    }
    if limit <= 0:
        result["reason"] = "invalid_user_limit"
        engine.record_module_error("SAMRUSERINFO", "SAMR user limit must be positive")
        return result
    try:
        with samr_session(engine) as (dce, server_handle):
            for name in iter_samr_domains(engine, dce, server_handle):
                if selected_domain and name.casefold() != selected_domain.casefold():
                    continue
                handle = None
                domain = {
                    "name": name, "sid": None, "status": "complete", "reason": None,
                    "returned": 0, "truncated": False, "users": [],
                }
                try:
                    sid = samr.hSamrLookupDomainInSamServer(dce, server_handle, name)["DomainId"]
                    domain["sid"] = sid.formatCanonical()
                    if domain["sid"] == "S-1-5-32":
                        continue
                    if result["returned"] >= limit:
                        result.update(status="partial", reason="limit_reached", truncated=True)
                        break
                    result["domains"].append(domain)
                    access = samr.DOMAIN_LOOKUP
                    if not selected_user:
                        access |= samr.DOMAIN_LIST_ACCOUNTS
                    handle = samr.hSamrOpenDomain(dce, server_handle, desiredAccess=access, domainId=sid)["DomainHandle"]
                    if selected_user:
                        _lookup_user(engine, dce, handle, domain, selected_user)
                    else:
                        domain["truncated"] = _enumerate_users(engine, dce, handle, domain, limit - result["returned"])
                    if domain["truncated"]:
                        domain.update(status="partial", reason="limit_reached")
                        result.update(status="partial", reason="limit_reached", truncated=True)
                    elif any(user["status"] != "complete" for user in domain["users"]):
                        domain.update(status="partial", reason="incomplete_user_information")
                except Exception as exc:
                    if not any(item is domain for item in result["domains"]):
                        result["domains"].append(domain)
                    status, reason = _error_status(engine, exc)
                    domain.update(status="partial" if domain["users"] else status, reason=reason)
                    if status == "error":
                        _record_error(engine, exc)
                finally:
                    engine._close_samr_handle(dce, handle)
                    domain["returned"] = len(domain["users"])
                    result["returned"] += domain["returned"]
                if result["truncated"]:
                    break
        if not result["truncated"]:
            statuses = {domain["status"] for domain in result["domains"]}
            if not statuses:
                result.update(status="complete", reason="domain_not_found" if selected_domain else "no_account_domains")
            elif statuses == {"complete"}:
                reason = "user_not_found" if selected_user and not result["returned"] else None
                if selected_user and any(domain["reason"] == "selected_name_is_not_user" for domain in result["domains"]):
                    reason = "selected_name_is_not_user" if not result["returned"] else None
                result.update(status="complete", reason=reason)
            elif len(statuses) == 1 and statuses <= {"denied", "unsupported", "error", "unavailable"}:
                result.update(status=next(iter(statuses)), reason="user_information_unavailable")
            else:
                result.update(status="partial", reason="incomplete_user_information")
    except SamrDenied as exc:
        result.update(status="partial" if result["domains"] else "denied", reason=exc.reason)
    except Exception as exc:
        status, reason = _error_status(engine, exc)
        result.update(status="partial" if result["domains"] else status, reason=reason)
        if status == "error":
            _record_error(engine, exc)
    lines = [f"SAMR user details status: {result['status']}; users returned: {result['returned']}"]
    if result["reason"]:
        lines.append(f"Reason: {result['reason']}")
    lines.append(f"Logon statistics source: {engine.args.ip} (queried server only)")
    for domain in result["domains"]:
        lines.append(f"Domain: {domain['name']} ({domain['sid']}): {domain['status']}")
        if domain["reason"]:
            lines.append(f"Reason: {domain['reason']}")
        for user in domain["users"]:
            lines.append(f"{domain['name']}\\{user['name']} ({user['sid']}): {user['status']}")
            for section, fields in (("account", _ACCOUNT_FIELDS), ("logon", _LOGON_FIELDS)):
                for key, _, _, zero in fields:
                    value = user[section][key]
                    rendered = (value.get("utc") or value.get("meaning")) if zero is not None else value["value"]
                    if value["status"] != "complete":
                        rendered = f"{value['status']} ({value['reason']})"
                    lines.append(f"  {key}: {rendered}")
    for line in lines:
        engine.ptprint(line)
    if getattr(engine.args, "output", None):
        engine.write_to_file(lines)
    return result


__all__ = ["parse_samr_timestamp", "query_samr_user_info"]
