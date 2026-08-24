"""Normalize SAMR user records for structured output."""
from __future__ import annotations

from impacket.dcerpc.v5 import samr

ACCOUNT_CONTROL_FLAGS = (
    (samr.USER_ACCOUNT_DISABLED, "USER_ACCOUNT_DISABLED"),
    (samr.USER_HOME_DIRECTORY_REQUIRED, "USER_HOME_DIRECTORY_REQUIRED"),
    (samr.USER_PASSWORD_NOT_REQUIRED, "USER_PASSWORD_NOT_REQUIRED"),
    (samr.USER_TEMP_DUPLICATE_ACCOUNT, "USER_TEMP_DUPLICATE_ACCOUNT"),
    (samr.USER_NORMAL_ACCOUNT, "USER_NORMAL_ACCOUNT"),
    (samr.USER_MNS_LOGON_ACCOUNT, "USER_MNS_LOGON_ACCOUNT"),
    (samr.USER_INTERDOMAIN_TRUST_ACCOUNT, "USER_INTERDOMAIN_TRUST_ACCOUNT"),
    (samr.USER_WORKSTATION_TRUST_ACCOUNT, "USER_WORKSTATION_TRUST_ACCOUNT"),
    (samr.USER_SERVER_TRUST_ACCOUNT, "USER_SERVER_TRUST_ACCOUNT"),
    (samr.USER_DONT_EXPIRE_PASSWORD, "USER_DONT_EXPIRE_PASSWORD"),
    (samr.USER_ACCOUNT_AUTO_LOCKED, "USER_ACCOUNT_AUTO_LOCKED"),
    (
        samr.USER_ENCRYPTED_TEXT_PASSWORD_ALLOWED,
        "USER_ENCRYPTED_TEXT_PASSWORD_ALLOWED",
    ),
    (samr.USER_SMARTCARD_REQUIRED, "USER_SMARTCARD_REQUIRED"),
    (samr.USER_TRUSTED_FOR_DELEGATION, "USER_TRUSTED_FOR_DELEGATION"),
    (samr.USER_NOT_DELEGATED, "USER_NOT_DELEGATED"),
    (samr.USER_USE_DES_KEY_ONLY, "USER_USE_DES_KEY_ONLY"),
    (samr.USER_DONT_REQUIRE_PREAUTH, "USER_DONT_REQUIRE_PREAUTH"),
    (samr.USER_PASSWORD_EXPIRED, "USER_PASSWORD_EXPIRED"),
    (
        samr.USER_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION,
        "USER_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION",
    ),
    (samr.USER_NO_AUTH_DATA_REQUIRED, "USER_NO_AUTH_DATA_REQUIRED"),
    (samr.USER_PARTIAL_SECRETS_ACCOUNT, "USER_PARTIAL_SECRETS_ACCOUNT"),
    (samr.USER_USE_AES_KEYS, "USER_USE_AES_KEYS"),
)

KNOWN_ACCOUNT_CONTROL_MASK = sum(bit for bit, _ in ACCOUNT_CONTROL_FLAGS)


def parse_samr_user(
    name: str,
    rid: int,
    account_control: int,
    domain_sid: str,
) -> dict[str, object]:
    name = str(name).rstrip("\x00")
    if not name:
        raise ValueError("SAMR user entry has an empty account name")
    rid = int(rid)
    if rid < 0 or rid > 0xFFFFFFFF:
        raise ValueError(f"SAMR user entry has an invalid RID: {rid}")
    account_control = int(account_control)
    if account_control < 0 or account_control > 0xFFFFFFFF:
        raise ValueError(
            f"SAMR user entry has invalid account-control flags: {account_control}"
        )
    return {
        "name": name,
        "rid": rid,
        "sid": f"{domain_sid}-{rid}",
        "stateStatus": "complete",
        "stateReason": None,
        "accountControl": account_control,
        "accountControlFlags": [
            flag_name
            for flag, flag_name in ACCOUNT_CONTROL_FLAGS
            if account_control & flag
        ],
        "unknownAccountControlBits": account_control & ~KNOWN_ACCOUNT_CONTROL_MASK,
        "disabled": bool(account_control & samr.USER_ACCOUNT_DISABLED),
        "lockedOut": bool(account_control & samr.USER_ACCOUNT_AUTO_LOCKED),
    }


def unavailable_samr_user(
    name: str,
    rid: int,
    domain_sid: str,
    reason: str,
) -> dict[str, object]:
    normalized_name = str(name).rstrip("\x00")
    normalized_rid = int(rid)
    if not normalized_name:
        raise ValueError("SAMR user entry has an empty account name")
    if normalized_rid < 0 or normalized_rid > 0xFFFFFFFF:
        raise ValueError(f"SAMR user entry has an invalid RID: {normalized_rid}")
    return {
        "name": normalized_name,
        "rid": normalized_rid,
        "sid": f"{domain_sid}-{normalized_rid}",
        "stateStatus": "denied",
        "stateReason": str(reason),
        "accountControl": None,
        "accountControlFlags": [],
        "unknownAccountControlBits": None,
        "disabled": None,
        "lockedOut": None,
    }


__all__ = [
    "ACCOUNT_CONTROL_FLAGS",
    "KNOWN_ACCOUNT_CONTROL_MASK",
    "parse_samr_user",
    "unavailable_samr_user",
]
