from __future__ import annotations

import json


_EVIDENCE_LIMIT = 20
_POLICY_FIELDS = {
    "passwordPolicy": (
        "minimumPasswordLength", "passwordHistoryLength",
        "passwordComplexityRequired", "reversibleEncryptionEnabled",
        "minimumPasswordAge", "maximumPasswordAge",
    ),
    "lockoutPolicy": (
        "lockoutEnabled", "lockoutThreshold", "lockoutDuration",
        "lockoutObservationWindow",
    ),
}
_USER_FIELDS = {
    "account": ("passwordLastSet", "accountExpires", "accountControl"),
    "logon": ("lastLogon", "lastLogoff", "badPasswordCount", "logonCount"),
}
_OPERATIONS = {
    "SAMRPOLICY": "SAMR domain password/account-lockout policy queries",
    "SAMRUSERS": "SAMR user enumeration",
    "SAMRGROUPS": "SAMR group/alias enumeration and direct-member queries",
    "SAMRUSERINFO": "SAMR account and logon information queries",
}


def _quoted(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _identity(domain: dict, item: dict) -> str | None:
    name, rid = item.get("name"), item.get("rid")
    if not isinstance(name, str) or not name or isinstance(rid, bool) or not isinstance(rid, int):
        return None
    if not 0 <= rid <= 0xFFFFFFFF:
        return None
    label = f"{domain.get('name', '')}\\{name}"
    return f"{_quoted(label)}; RID: {rid}; SID: {_quoted(item.get('sid'))}"


def _records(code: str, result: dict) -> list[str]:
    records = []
    for domain in result.get("domains", []):
        if not isinstance(domain, dict):
            continue
        if code == "SAMRPOLICY":
            for section, fields in _POLICY_FIELDS.items():
                policy = domain.get(section)
                if not isinstance(policy, dict):
                    continue
                values = {key: policy[key] for key in fields if policy.get(key) is not None}
                if values:
                    records.append(
                        f"Domain {_quoted(domain.get('name'))}; SID: {_quoted(domain.get('sid'))}\n"
                        f"  {section}: {_quoted(values)}"
                    )
        elif code == "SAMRUSERS":
            for user in domain.get("users", []):
                if isinstance(user, dict) and (identity := _identity(domain, user)):
                    records.append(f"User: {identity}")
        elif code == "SAMRGROUPS":
            for group in domain.get("groups", []):
                if not isinstance(group, dict) or not (identity := _identity(domain, group)):
                    continue
                members = [
                    member["sid"] for member in group.get("members", [])
                    if isinstance(member, dict) and isinstance(member.get("sid"), str) and member["sid"]
                ]
                lines = [
                    f"{group.get('kind', 'group/alias')}: {identity}",
                    f"  Direct member identifiers returned: {len(members)}; "
                    f"query status: {group.get('membersStatus', 'unknown')}",
                ]
                lines.extend(f"    {_quoted(sid)}" for sid in members[:_EVIDENCE_LIMIT])
                if len(members) > _EVIDENCE_LIMIT:
                    lines.append(f"    Showing the first {_EVIDENCE_LIMIT} returned member identifiers.")
                records.append("\n".join(lines))
        elif code == "SAMRUSERINFO":
            for user in domain.get("users", []):
                if not isinstance(user, dict) or not (identity := _identity(domain, user)):
                    continue
                values = {}
                for section, fields in _USER_FIELDS.items():
                    data = user.get(section)
                    if not isinstance(data, dict):
                        continue
                    for key in fields:
                        value = data.get(key)
                        if not isinstance(value, dict) or value.get("status") != "complete":
                            continue
                        if value.get("value") is not None:
                            values[key] = value["value"]
                        elif value.get("raw100ns") is not None:
                            values[key] = {
                                "raw100ns": value["raw100ns"],
                                "value": value.get("utc") or value.get("meaning"),
                            }
                if values:
                    records.append(f"User: {identity}\n  Returned fields: {_quoted(values)}")
    return records


def samr_disclosure_finding(code: str, result: dict | None, endpoint: str, vuln_code: str) -> dict | None:
    if (
        code not in _OPERATIONS
        or not isinstance(result, dict)
        or result.get("accessMode") != "anonymous"
        or result.get("anonymousLoginAccepted") is not True
        or result.get("sessionType") not in {"null", "guest", "anonymous"}
        or result.get("status") not in {"complete", "partial"}
    ):
        return None
    records = _records(code, result)
    if not records:
        return None
    response = "\n".join(records[:_EVIDENCE_LIMIT])
    if len(records) > _EVIDENCE_LIMIT:
        response += f"\nShowing the first {_EVIDENCE_LIMIT} of {len(records)} returned evidence records."
    operation = _OPERATIONS[code]
    poc = (
        f"A new SMB connection to {endpoint} accepted an empty username, password "
        f"and domain; session type: {result['sessionType']}. No user credentials were supplied.\n"
        f"{operation} returned the following data before user authentication:\n"
        f"{response}\nQuery status: {result['status']}. "
        "The finding covers only the data actually returned by these queries."
    )
    if code == "SAMRPOLICY":
        poc += " The queried SAM domain policy is not a measurement of every user's effective password policy."
    return {
        "vuln_code": vuln_code,
        "vuln_request": f"Empty-credential SMB session followed by {operation}",
        "vuln_response": response.replace("\n", "\r\n"),
        "poc": poc.replace("\n", "\r\n"),
    }
