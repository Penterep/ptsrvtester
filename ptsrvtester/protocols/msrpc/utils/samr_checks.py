from __future__ import annotations

from copy import copy


SAMR_CODES = frozenset({"SAMRPOLICY", "SAMRUSERS", "SAMRGROUPS", "SAMRUSERINFO"})


def _anonymous_engine(engine):
    anonymous = copy(engine)
    anonymous.args = copy(engine.args)
    for field in ("username", "password", "usernames", "username_file", "password_file"):
        setattr(anonymous.args, field, None)
    anonymous.args.domain = ""
    anonymous.results = type(engine.results)()
    anonymous._transport_failures = {}
    anonymous._locked_accounts = set()
    return anonymous


def _run_phase(engine, code: str, method_name: str, *, anonymous: bool) -> dict:
    label = "Anonymous access check" if anonymous else "Authenticated inventory"
    engine.ptprint(label, out="INFO")
    if getattr(engine.args, "output", None):
        try:
            engine.write_to_file(f"{code}: {label}")
        except Exception as exc:
            engine.record_module_error(code, f"{type(exc).__name__}: Cannot write SAMR output")
    try:
        result = getattr(engine, method_name)()
        if not isinstance(result, dict):
            raise TypeError("SAMR query did not return a result")
        return result
    except Exception as exc:
        message = f"{type(exc).__name__}: SAMR query failed"
        engine.record_module_error(code, message, transport_error=exc)
        engine.ptprint(f"{label} failed ({type(exc).__name__})", out="TITLE")
        return {
            "status": "error",
            "reason": "operational_error",
            "accessMode": "anonymous" if anonymous else "authenticated",
            "sessionType": None,
            "anonymousLoginAccepted": False,
            "domains": [],
        }


def run_samr_checks(engine, code: str, method_name: str) -> dict:
    anonymous_engine = _anonymous_engine(engine)
    anonymous = _run_phase(anonymous_engine, code, method_name, anonymous=True)
    finding = engine.samr_disclosure_finding(code, anonymous)
    if isinstance(finding, dict):
        engine.ptprint("SAMR data is available without user authentication", out="VULN")
    elif anonymous.get("status") == "denied":
        engine.ptprint(
            f"The anonymous {code} query was denied; no disclosure confirmed", out="NOTVULN",
        )
    elif anonymous.get("status") == "complete":
        engine.ptprint(
            f"No disclosure was confirmed by the anonymous {code} query", out="TITLE",
        )
    else:
        engine.ptprint("Anonymous SAMR disclosure could not be determined", out="TITLE")
    authenticated = None
    if getattr(engine.args, "username", None) and getattr(engine.args, "password", None) is not None:
        authenticated = _run_phase(engine, code, method_name, anonymous=False)

    engine.results.samr_checks[code] = {
        "anonymous": anonymous,
        "authenticated": authenticated,
    }
    if authenticated is None:
        for family, failure in anonymous_engine._transport_failures.items():
            engine._transport_failures.setdefault(family, failure)
    anonymous_error = anonymous_engine.results.module_errors.get(code)
    if anonymous_error:
        message = str(anonymous_error)
        for field in ("username", "password", "domain"):
            value = getattr(engine.args, field, None)
            if value:
                message = message.replace(str(value), "[redacted]")
        message = f"Anonymous check: {message}"
        authenticated_error = engine.results.module_errors.get(code)
        if authenticated_error:
            message += f"; Authenticated inventory: {authenticated_error}"
        engine.results.module_errors[code] = message

    return authenticated if authenticated is not None else anonymous
