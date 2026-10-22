from __future__ import annotations

from copy import copy
import re

from impacket.dcerpc.v5 import samr

from .samr_userinfo import query_samr_user_info


def normalize_guess_identity(username, domain="") -> tuple[str, str] | None:
    if not isinstance(username, str) or not username or "\x00" in username:
        return None
    if not isinstance(domain, str) or "\x00" in domain:
        return None
    if "\\" in username:
        if username.count("\\") != 1:
            return None
        explicit_domain, account = username.split("\\", 1)
        if not account or not explicit_domain or "@" in account:
            return None
        return account, explicit_domain
    if "@" in username:
        if username.count("@") != 1:
            return None
        account, explicit_domain = username.split("@", 1)
        if not account or not explicit_domain:
            return None
        return account, explicit_domain
    return username, domain


def _returned_number(user: dict, section: str, field: str, maximum: int) -> int | None:
    section_value = user.get(section)
    if not isinstance(section_value, dict):
        return None
    value = section_value.get(field, {})
    if not isinstance(value, dict) or value.get("status") != "complete":
        return None
    number = value.get("value")
    if isinstance(number, bool) or not isinstance(number, int) or not 0 <= number <= maximum:
        return None
    return number


def observe_guess_account(engine, credential) -> dict:
    """Use a separate account to avoid resetting the tested account's counters.

    Same-named accounts are refused even across domains: NTLM domain aliases
    cannot prove they are distinct. The target domain must match SAMR exactly.
    """
    result = {
        "status": "partial", "reason": None,
        "sourceHost": engine.args.ip, "sourcePort": 445,
        "identitySource": "SAMR", "identityVerified": False,
        "requestedAccount": None, "requestedDomain": None,
        "account": None, "domain": None, "sid": None,
        "lockedOut": None, "badPasswordCount": None,
    }
    tested = normalize_guess_identity(getattr(credential, "username", None), getattr(engine.args, "domain", "") or "")
    observer_domain = getattr(engine.args, "observer_domain", None)
    if observer_domain is None:
        observer_domain = getattr(engine.args, "domain", "")
    observer = normalize_guess_identity(getattr(engine.args, "observer_user", None), observer_domain or "")
    password = getattr(engine.args, "observer_password", None)
    if tested is None:
        result.update(status="error", reason="invalid_tested_identity")
        return result
    result.update(requestedAccount=tested[0], requestedDomain=tested[1] or None)
    if observer is None or password is None:
        result["reason"] = "observer_not_configured"
        return result
    if observer[0].casefold() == tested[0].casefold():
        result.update(status="error", reason="observer_must_be_different_account")
        return result
    if not tested[1]:
        result["reason"] = "tested_domain_required_for_observer"
        return result

    cloned = copy(engine)
    cloned.args = copy(engine.args)
    cloned.args.username, cloned.args.domain = observer
    cloned.args.usernames = [observer[0]]
    cloned.args.password = password
    cloned.args.smb_port = 445
    cloned.args.samr_user = tested[0]
    cloned.args.samr_domain = tested[1] or None
    cloned.args.samr_max_users = 2
    cloned.args.output = None
    cloned.args.debug = False
    cloned.ptprint = lambda *args, **kwargs: None
    cloned.ptdebug = lambda *args, **kwargs: None
    cloned.write_to_file = lambda *args, **kwargs: None
    cloned.record_module_error = lambda *args, **kwargs: None
    try:
        observed = query_samr_user_info(cloned)
    except Exception:
        # Backend error messages may contain either password.
        result.update(status="error", reason="observer_query_failed")
        return result
    if not isinstance(observed, dict):
        result.update(status="error", reason="malformed_observer_result")
        return result
    if observed.get("status") in {"denied", "error", "unsupported", "unavailable"}:
        status = "denied" if observed["status"] == "denied" else "error"
        result.update(status=status, reason="observer_access_denied" if status == "denied" else "observer_query_failed")
        return result
    if observed.get("accessMode") != "authenticated" or observed.get("sessionType") != "authenticated":
        result.update(status="denied", reason="observer_session_not_authenticated")
        return result

    matches = []
    domains = observed.get("domains", [])
    if not isinstance(domains, list):
        result.update(status="error", reason="malformed_observer_result")
        return result
    for domain in domains:
        if not isinstance(domain, dict) or not isinstance(domain.get("name"), str):
            continue
        if tested[1] and domain["name"].casefold() != tested[1].casefold():
            continue
        users = domain.get("users", [])
        if not isinstance(users, list):
            continue
        for user in users:
            if not isinstance(user, dict) or not isinstance(user.get("name"), str):
                continue
            if user["name"].casefold() == tested[0].casefold():
                matches.append((domain, user))
    if len(matches) != 1:
        result["reason"] = "account_identity_ambiguous" if matches else "account_identity_not_verified"
        return result
    domain, user = matches[0]
    sid = user.get("sid")
    domain_sid = domain.get("sid")
    rid = user.get("rid")
    if (
        not isinstance(sid, str) or re.fullmatch(r"S-1-(?:\d+-)+\d+", sid) is None
        or not isinstance(domain_sid, str)
        or isinstance(rid, bool) or not isinstance(rid, int) or not 0 <= rid <= 0xFFFFFFFF
        or sid != f"{domain_sid}-{rid}"
    ):
        result["reason"] = "account_identity_not_verified"
        return result
    result.update(identityVerified=True, account=user["name"], domain=domain["name"], sid=sid)
    control = _returned_number(user, "account", "accountControl", 0xFFFFFFFF)
    count = _returned_number(user, "logon", "badPasswordCount", 0xFFFF)
    if control is not None:
        result["lockedOut"] = bool(control & samr.USER_ACCOUNT_AUTO_LOCKED)
    result["badPasswordCount"] = count
    if control is not None and count is not None:
        result.update(status="complete", reason=None)
    else:
        result["reason"] = "account_state_fields_not_returned"
    return result


__all__ = ["normalize_guess_identity", "observe_guess_account"]
