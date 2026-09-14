"""Read-only SAM group/alias inventory, retaining direct member identifiers."""
from __future__ import annotations

import re

from impacket.dcerpc.v5 import samr
from impacket.nt_errors import (
    STATUS_INVALID_INFO_CLASS, STATUS_MORE_ENTRIES, STATUS_NO_MORE_ENTRIES,
    STATUS_NOT_IMPLEMENTED, STATUS_NOT_SUPPORTED,
)

from .samr_session import (
    ENUMERATION_PAGE_BYTES, MAX_ENUMERATION_PAGES, SamrDenied,
    enumeration_page, iter_samr_domains, samr_array, samr_session, samr_u32,
)


def _sid_text(sid) -> str:
    text = sid.formatCanonical()
    if not isinstance(text, str) or not re.fullmatch(r"S-1-\d+(?:-\d+){1,15}", text):
        raise ValueError("Invalid SAMR SID")
    return text


def _failure(engine, exc: Exception) -> tuple[str, str]:
    if isinstance(exc, SamrDenied):
        return "denied", exc.reason
    if engine._samr_access_denied(exc):
        return "denied", "access_denied"
    if engine._samr_error_code(exc) in (
        STATUS_NOT_SUPPORTED, STATUS_NOT_IMPLEMENTED, STATUS_INVALID_INFO_CLASS,
        1745, 0x1C010002,  # RPC procnum out of range / nca_s_op_rng_error
    ):
        return "unsupported", "operation_not_supported"
    engine.record_module_error("SAMRGROUPS", engine._sanitized_samr_error(exc))
    return "error", "operational_error"


def _require_success(response):
    status = samr_u32(response["ErrorCode"], "operation status")
    if status:
        raise samr.DCERPCSessionError(error_code=status)


def _read_members(engine, dce, domain_handle, domain_sid, group, limit):
    handle = None
    try:
        if group["kind"] == "group":
            opened = samr.hSamrOpenGroup(
                dce, domain_handle, desiredAccess=samr.GROUP_LIST_MEMBERS,
                groupId=group["rid"],
            )
            handle = opened["GroupHandle"]
            response = samr.hSamrGetMembersInGroup(dce, handle)
            _require_success(response)
            buffer = response["Members"]
            count = samr_u32(buffer["MemberCount"], "group member count")
            members = samr_array(buffer["Members"], count, "group members")
            attributes = samr_array(buffer["Attributes"], count, "member attributes")
            group["memberCount"] = count
            for index in range(min(count, limit)):
                rid = samr_u32(members[index], "member RID")
                group["members"].append({
                    "rid": rid, "sid": f"{domain_sid}-{rid}",
                    "attributes": samr_u32(attributes[index], "member attributes"),
                })
        else:
            opened = samr.hSamrOpenAlias(
                dce, domain_handle, desiredAccess=samr.ALIAS_LIST_MEMBERS,
                aliasId=group["rid"],
            )
            handle = opened["AliasHandle"]
            response = samr.hSamrGetMembersInAlias(dce, handle)
            _require_success(response)
            buffer = response["Members"]
            count = samr_u32(buffer["Count"], "alias member count")
            members = samr_array(buffer["Sids"], count, "alias members")
            group["memberCount"] = count
            for member in members[:limit]:
                group["members"].append({"sid": _sid_text(member["SidPointer"])})
        # SAMR GetMembers calls have no pagination or server-side count bound.
        # This cap bounds retained output, not the RPC response's wire size.
        group["membersTruncated"] = count > limit
        group.update(
            membersStatus="partial" if count > limit else "complete",
            membersReason="member_limit_reached" if count > limit else None,
        )
    except Exception as exc:
        status, reason = _failure(engine, exc)
        group.update(
            membersStatus="partial" if group["members"] else status,
            membersReason=reason,
        )
    finally:
        group["membersReturned"] = len(group["members"])
        engine._close_samr_handle(dce, handle)


def _enumerate_kind(engine, dce, handle, domain, kind, remaining, member_limit):
    """Append bounded records and return the section's enumeration status."""
    enumerate_rpc = (
        samr.hSamrEnumerateGroupsInDomain if kind == "group"
        else samr.hSamrEnumerateAliasesInDomain
    )
    context = 0
    seen_contexts = {context}
    seen_rids = set()
    start = len(domain["groups"])
    try:
        for _ in range(MAX_ENUMERATION_PAGES):
            try:
                response = enumerate_rpc(
                    dce, handle, enumerationContext=context,
                    preferedMaximumLength=ENUMERATION_PAGE_BYTES,
                )
            except samr.DCERPCSessionError as exc:
                if engine._samr_error_code(exc) not in (
                    STATUS_MORE_ENTRIES, STATUS_NO_MORE_ENTRIES
                ) or exc.get_packet() is None:
                    raise
                response = exc.get_packet()
            entries, next_context, more = enumeration_page(response)
            for entry in entries:
                rid = samr_u32(entry["RelativeId"], "group RID")
                name = str(entry["Name"]).rstrip("\x00")
                if not name:
                    raise ValueError("SAMR group name is empty")
                if rid in seen_rids:
                    raise ValueError("SAMR enumeration repeated a group RID")
                seen_rids.add(rid)
                if len(domain["groups"]) - start >= remaining:
                    return {"status": "partial", "reason": "group_limit_reached"}
                group = {
                    "kind": kind, "name": name, "rid": rid,
                    "sid": f"{domain['sid']}-{rid}", "membersStatus": "error",
                    "membersReason": None, "memberCount": None,
                    "membersReturned": 0, "membersTruncated": False, "members": [],
                }
                domain["groups"].append(group)
                _read_members(engine, dce, handle, domain["sid"], group, member_limit)
            if not more:
                return {"status": "complete", "reason": None}
            if len(domain["groups"]) - start >= remaining:
                return {"status": "partial", "reason": "group_limit_reached"}
            if next_context in seen_contexts:
                raise RuntimeError("SAMR group enumeration did not advance")
            seen_contexts.add(next_context)
            context = next_context
        raise RuntimeError("SAMR group enumeration page limit reached")
    except Exception as exc:
        status, reason = _failure(engine, exc)
        return {
            "status": "partial" if len(domain["groups"]) > start else status,
            "reason": reason,
        }


def _summarize(statuses, has_data=False):
    statuses = set(statuses)
    if not statuses or statuses == {"complete"}:
        return "complete"
    if has_data or len(statuses) != 1 or "partial" in statuses:
        return "partial"
    return next(iter(statuses))


def _print_result(engine, result):
    lines = [
        f"SAMR group enumeration status: {result['status']}",
        f"Groups and aliases returned: {result['returned']}",
        "Direct members only; member limit bounds retained output per group.",
    ]
    if result["reason"]:
        lines.append(f"Reason: {result['reason']}")
    for domain in result["domains"]:
        lines.append(f"Domain: {domain['name']} ({domain['sid'] or 'SID unavailable'})")
        if domain["status"] != "complete":
            lines.append(f"  Status: {domain['status']} ({domain['reason']})")
        for group in domain["groups"]:
            lines.append(f"  {group['kind']}: {group['name']} ({group['sid']})")
            lines.append(
                f"    Direct members: {group['membersReturned']} of "
                f"{group['memberCount'] if group['memberCount'] is not None else 'unknown'}; "
                f"status: {group['membersStatus']}"
                + (f" ({group['membersReason']})" if group["membersReason"] else "")
            )
            for member in group["members"]:
                attributes = member.get("attributes")
                lines.append(
                    f"    {member['sid']}"
                    + (f"; attributes: 0x{attributes:08x}" if attributes is not None else "")
                )
    for line in lines:
        engine.ptprint(line)
    if getattr(engine.args, "output", None):
        engine.write_to_file(lines)


def enumerate_samr_groups(engine) -> dict:
    limit = int(getattr(engine.args, "samr_max_groups", 1000))
    member_limit = int(getattr(engine.args, "samr_max_members", 1000))
    if limit <= 0 or member_limit <= 0:
        raise ValueError("SAMR group and member limits must be positive")
    result = {
        "status": "error", "reason": None, "limit": limit,
        "memberLimit": member_limit, "memberLimitScope": "per_group_output",
        "returned": 0, "truncated": False, "domains": [],
    }
    try:
        with samr_session(engine) as (dce, server_handle):
            for name in iter_samr_domains(engine, dce, server_handle):
                domain = {
                    "name": name, "sid": None, "status": "error", "reason": None,
                    "returned": 0, "truncated": False, "groups": [],
                    "enumerations": {
                        "groups": {"status": "not_tested", "reason": "domain_unavailable"},
                        "aliases": {"status": "not_tested", "reason": "domain_unavailable"},
                    },
                }
                result["domains"].append(domain)
                handle = None
                try:
                    lookup = samr.hSamrLookupDomainInSamServer(dce, server_handle, name)
                    sid = lookup["DomainId"]
                    domain["sid"] = _sid_text(sid)
                    opened = samr.hSamrOpenDomain(
                        dce, server_handle,
                        desiredAccess=samr.DOMAIN_LIST_ACCOUNTS | samr.DOMAIN_LOOKUP,
                        domainId=sid,
                    )
                    handle = opened["DomainHandle"]
                    for kind, section in (("group", "groups"), ("alias", "aliases")):
                        remaining = limit - result["returned"] - len(domain["groups"])
                        summary = _enumerate_kind(
                            engine, dce, handle, domain, kind, remaining, member_limit,
                        )
                        domain["enumerations"][section] = summary
                        if summary["reason"] == "group_limit_reached":
                            domain["truncated"] = True
                            if kind == "group":
                                domain["enumerations"]["aliases"] = {
                                    "status": "not_tested", "reason": "group_limit_reached",
                                }
                            break
                    statuses = [v["status"] for v in domain["enumerations"].values()]
                    statuses.extend(g["membersStatus"] for g in domain["groups"])
                    domain["status"] = _summarize(statuses, bool(domain["groups"]))
                    if domain["truncated"]:
                        domain["reason"] = "group_limit_reached"
                    elif domain["status"] != "complete":
                        domain["reason"] = "some_group_data_unavailable"
                except Exception as exc:
                    status, reason = _failure(engine, exc)
                    domain.update(status="partial" if domain["groups"] else status, reason=reason)
                finally:
                    domain["returned"] = len(domain["groups"])
                    result["returned"] += domain["returned"]
                    engine._close_samr_handle(dce, handle)
                if domain["truncated"]:
                    result.update(truncated=True, reason="group_limit_reached")
                    break
        result["status"] = _summarize(
            (domain["status"] for domain in result["domains"]), bool(result["returned"]),
        )
        if result["status"] != "complete" and result["reason"] is None:
            result["reason"] = "some_group_data_unavailable"
    except Exception as exc:
        status, reason = _failure(engine, exc)
        result.update(status="partial" if result["domains"] else status, reason=reason)
    _print_result(engine, result)
    return result
