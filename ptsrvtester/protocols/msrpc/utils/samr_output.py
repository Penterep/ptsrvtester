"""Shared human-readable fields and authentication failures for SAMR probes."""
from __future__ import annotations


_AUTHENTICATION_FAILURE_REASONS = frozenset({
    "authentication_denied",
    "guest_session",
    "null_session",
    "anonymous_session",
    "unknown_session",
})


def is_samr_authentication_failure(result: dict) -> bool:
    """Keep RPC authorization and partial enumeration errors distinct."""
    return (
        result.get("status") == "denied"
        and result.get("reason") in _AUTHENTICATION_FAILURE_REASONS
        and not result.get("domains")
    )


def print_samr_authentication_failure(engine, result: dict) -> bool:
    """Emit the same concise console/export result for all SAMR modules."""
    if not is_samr_authentication_failure(result):
        return False
    message = "SAMR authentication failed"
    engine.ptprint(message, out="TITLE")
    if getattr(engine.args, "output", None):
        engine.write_to_file([message])
    return True


def format_samr_fields(fields, *, indent: int = 4, colon: bool = True) -> list[str]:
    """Align values while preserving labels and unavailable field evidence."""
    fields = [
        ((str(label) + ":" if colon else str(label)), value)
        for label, value in fields
    ]
    width = max((len(label) for label, _ in fields), default=0) + 2
    return [
        " " * indent + f"{label:<{width}}{value}"
        for label, value in fields
    ]
