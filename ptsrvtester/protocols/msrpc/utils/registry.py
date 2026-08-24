"""MSRPC test metadata shared by CLI validation and module selection."""
from __future__ import annotations

MSRPC_TESTS: dict[str, dict[str, object]] = {
    "ENUMEPM": {
        "description": "Enumerate Endpoint Mapper registrations",
        "family": "rpc",
        "order": 10,
    },
    "ENUMMGMT": {
        "description": "Enumerate interfaces exposed by the RPC management interface",
        "family": "rpc",
        "order": 20,
    },
    "ENUMPIPES": {
        "description": "Check which common SMB named pipes are reachable",
        "family": "smb",
        "order": 30,
    },
    "ANONSMB": {
        "description": "Check anonymous SMB login and share enumeration",
        "family": "smb",
        "order": 40,
    },
    "SAMRPOLICY": {
        "description": "Read SAM password and account-lockout policy",
        "family": "smb",
        "order": 45,
        "explicit_only": True,
        "credential_mode": "direct_required",
    },
    "SAMRUSERS": {
        "description": "Enumerate normal SAM user accounts and account-state flags",
        "family": "smb",
        "order": 46,
        "explicit_only": True,
        "credential_mode": "direct_required",
    },
    "BRUTEPIPE": {
        "description": "Test supplied credentials against one SMB named pipe",
        "family": "smb",
        "order": 50,
        "explicit_only": True,
        "credential_mode": "product_required",
    },
    "BRUTESMB": {
        "description": "Test supplied credentials against SMB authentication",
        "family": "smb",
        "order": 60,
        "explicit_only": True,
        "credential_mode": "product_required",
    },
    "BRUTETCP": {
        "description": "Test supplied credentials against one RPC/TCP interface",
        "family": "rpc",
        "order": 70,
        "explicit_only": True,
        "credential_mode": "product_required",
    },
    "BRUTEHTTP": {
        "description": "Test supplied credentials against RPC over HTTP",
        "family": "http",
        "order": 80,
        "explicit_only": True,
        "credential_mode": "product_required",
    },
}

MSRPC_TEST_ORDER = tuple(MSRPC_TESTS)
MSRPC_EXPLICIT_ONLY_TESTS = frozenset(
    code for code, metadata in MSRPC_TESTS.items() if metadata.get("explicit_only")
)
MSRPC_DEFAULT_SUITE = tuple(
    code for code in MSRPC_TEST_ORDER if code not in MSRPC_EXPLICIT_ONLY_TESTS
)


def test_tokens(raw: str | None) -> list[str]:
    """Return normalized, de-duplicated ``-ts`` tokens in input order."""
    if not raw:
        return []
    tokens: list[str] = []
    seen: set[str] = set()
    for item in str(raw).split(","):
        token = item.strip().upper()
        if token and token not in seen:
            tokens.append(token)
            seen.add(token)
    return tokens


def expand_msrpc_selection(raw: str | None) -> list[str]:
    """Expand an empty selection or ``ALL`` to the default-safe suite.

    Explicit-only tests named alongside ``ALL`` remain selected. This allows
    ``ALL,SAMRPOLICY`` while keeping every explicit test out of ``ALL`` alone.
    Unknown tokens are kept so validation can report them precisely.
    """
    tokens = test_tokens(raw)
    if not tokens:
        return list(MSRPC_DEFAULT_SUITE)
    if "ALL" not in tokens:
        return tokens

    selected = list(MSRPC_DEFAULT_SUITE)
    selected.extend(
        token for token in tokens if token != "ALL" and token not in selected
    )
    return selected


def selection_families(codes: list[str]) -> set[str]:
    return {
        str(MSRPC_TESTS[code]["family"])
        for code in codes
        if code in MSRPC_TESTS
    }


def tests_with_credential_mode(codes: list[str], mode: str) -> set[str]:
    return {
        code
        for code in codes
        if code in MSRPC_TESTS and MSRPC_TESTS[code].get("credential_mode") == mode
    }


__all__ = [
    "MSRPC_DEFAULT_SUITE",
    "MSRPC_EXPLICIT_ONLY_TESTS",
    "MSRPC_TEST_ORDER",
    "MSRPC_TESTS",
    "expand_msrpc_selection",
    "selection_families",
    "test_tokens",
    "tests_with_credential_mode",
]
