"""Conversion helpers for read-only SAM domain policy data."""
from __future__ import annotations

from impacket.dcerpc.v5 import samr


WINDOWS_TICKS_PER_SECOND = 10_000_000
UNLIMITED_RELATIVE_INTERVAL = -(1 << 63)

PASSWORD_PROPERTY_FLAGS = (
    (samr.DOMAIN_PASSWORD_COMPLEX, "DOMAIN_PASSWORD_COMPLEX"),
    (samr.DOMAIN_PASSWORD_NO_ANON_CHANGE, "DOMAIN_PASSWORD_NO_ANON_CHANGE"),
    (samr.DOMAIN_PASSWORD_NO_CLEAR_CHANGE, "DOMAIN_PASSWORD_NO_CLEAR_CHANGE"),
    (samr.DOMAIN_LOCKOUT_ADMINS, "DOMAIN_LOCKOUT_ADMINS"),
    (samr.DOMAIN_PASSWORD_STORE_CLEARTEXT, "DOMAIN_PASSWORD_STORE_CLEARTEXT"),
    (samr.DOMAIN_REFUSE_PASSWORD_CHANGE, "DOMAIN_REFUSE_PASSWORD_CHANGE"),
)


def old_large_integer_value(value) -> int:
    """Combine an MS-SAMR OLD_LARGE_INTEGER into one signed 64-bit value."""
    low = int(value["LowPart"]) & 0xFFFFFFFF
    high = int(value["HighPart"]) & 0xFFFFFFFF
    combined = (high << 32) | low
    if combined & (1 << 63):
        combined -= 1 << 64
    return combined


def large_integer_value(value) -> int:
    """Extract Impacket's signed NDRHYPER representation."""
    try:
        return int(value["Data"])
    except (KeyError, TypeError):
        return int(value)


def relative_interval(raw_100ns: int) -> dict[str, int | float | bool | None]:
    """Return a JSON-safe Windows relative interval without losing its raw value."""
    raw = int(raw_100ns)
    if raw > 0:
        raise ValueError(f"relative SAM interval must not be positive: {raw}")
    unlimited = raw == UNLIMITED_RELATIVE_INTERVAL
    seconds: int | float | None
    if unlimited:
        seconds = None
    else:
        whole_seconds, remaining_ticks = divmod(abs(raw), WINDOWS_TICKS_PER_SECOND)
        seconds = (
            whole_seconds
            if remaining_ticks == 0
            else whole_seconds + (remaining_ticks / WINDOWS_TICKS_PER_SECOND)
        )
    return {
        "raw100ns": raw,
        "seconds": seconds,
        "unlimited": unlimited,
    }


def parse_domain_policy(
    domain_name: str,
    domain_sid: str,
    password_information,
    lockout_information,
) -> dict[str, object]:
    return {
        "status": "complete",
        "name": str(domain_name),
        "sid": str(domain_sid),
        "passwordPolicy": parse_password_policy(password_information),
        "lockoutPolicy": parse_lockout_policy(lockout_information),
        "errors": [],
    }


def parse_password_policy(password_information) -> dict[str, object]:
    properties = int(password_information["PasswordProperties"])
    return {
        "minimumPasswordLength": int(password_information["MinPasswordLength"]),
        "passwordHistoryLength": int(password_information["PasswordHistoryLength"]),
        "passwordProperties": properties,
        "unknownPasswordPropertyBits": properties & ~0x3F,
        "passwordPropertyFlags": [
            name for bit, name in PASSWORD_PROPERTY_FLAGS if properties & bit
        ],
        "passwordComplexityRequired": bool(properties & samr.DOMAIN_PASSWORD_COMPLEX),
        "reversibleEncryptionEnabled": bool(
            properties & samr.DOMAIN_PASSWORD_STORE_CLEARTEXT
        ),
        "minimumPasswordAge": relative_interval(
            old_large_integer_value(password_information["MinPasswordAge"])
        ),
        "maximumPasswordAge": relative_interval(
            old_large_integer_value(password_information["MaxPasswordAge"])
        ),
    }


def parse_lockout_policy(lockout_information) -> dict[str, object]:
    threshold = int(lockout_information["LockoutThreshold"])
    duration = relative_interval(
        large_integer_value(lockout_information["LockoutDuration"])
    )
    duration["untilAdministratorUnlock"] = threshold > 0 and duration["unlimited"]
    return {
        "lockoutEnabled": threshold > 0,
        "lockoutThreshold": threshold,
        "lockoutDuration": duration,
        "lockoutObservationWindow": relative_interval(
            large_integer_value(lockout_information["LockoutObservationWindow"])
        ),
    }


def format_interval(interval: dict[str, object]) -> str:
    if interval["unlimited"]:
        return "unlimited"
    seconds = interval["seconds"]
    if isinstance(seconds, int):
        if seconds and seconds % 86400 == 0:
            return f"{seconds // 86400} day(s) ({seconds} seconds)"
        if seconds and seconds % 60 == 0:
            return f"{seconds // 60} minute(s) ({seconds} seconds)"
    return f"{seconds} seconds"


__all__ = [
    "UNLIMITED_RELATIVE_INTERVAL",
    "format_interval",
    "large_integer_value",
    "old_large_integer_value",
    "parse_domain_policy",
    "parse_lockout_policy",
    "parse_password_policy",
    "relative_interval",
]
