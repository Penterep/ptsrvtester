"""Command-line contract for the MSRPC protocol module."""
from __future__ import annotations

import argparse
import re
import uuid as stdlib_uuid

from ..._base import BaseArgs
from .helpers import Target, valid_target
from .registry import (
    MSRPC_DEFAULT_SUITE,
    MSRPC_EXPLICIT_ONLY_TESTS,
    MSRPC_TEST_ORDER,
    MSRPC_TESTS,
    expand_msrpc_selection,
    selection_families,
    tests_with_credential_mode,
)

_INTERFACE_VERSION = re.compile(r"^[0-9]+\.[0-9]+$")


def _bounded_threads(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("threads must be an integer") from exc
    if not 1 <= parsed <= 100:
        raise argparse.ArgumentTypeError("threads must be between 1 and 100")
    return parsed


def _bounded_attempts(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("max attempts must be an integer") from exc
    if not 1 <= parsed <= 100_000:
        raise argparse.ArgumentTypeError("max attempts must be between 1 and 100000")
    return parsed


def _bounded_timeout(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number") from exc
    if not 1 <= parsed <= 60:
        raise argparse.ArgumentTypeError("timeout must be between 1 and 60 seconds")
    return parsed


def _bounded_samr_users(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("SAMR user limit must be an integer") from exc
    if not 1 <= parsed <= 10_000:
        raise argparse.ArgumentTypeError(
            "SAMR user limit must be between 1 and 10000"
        )
    return parsed


def _pipe_name(value: str) -> str:
    pipe = value.strip().replace("/", "\\")
    while pipe.lower().startswith("\\pipe\\"):
        pipe = pipe[6:]
    pipe = pipe.strip("\\")
    if not pipe or "\\" in pipe:
        raise argparse.ArgumentTypeError("pipe must be one named-pipe name, for example svcctl")
    return pipe


def _pipe_names(value: str) -> list[str]:
    values = [_pipe_name(item) for item in value.split(",") if item.strip()]
    if not values:
        raise argparse.ArgumentTypeError("pipes must contain at least one name")
    return list(dict.fromkeys(values))


def normalize_interface_uuid(value: str) -> str:
    """Validate ``UUID[:major.minor]`` and return its canonical spelling."""
    raw = value.strip()
    uuid_text = raw
    version = "1.0"
    if ":" in raw:
        uuid_text, version = raw.rsplit(":", 1)
        if not _INTERFACE_VERSION.fullmatch(version):
            raise argparse.ArgumentTypeError(
                "interface UUID version must use MAJOR.MINOR, for example 1.0"
            )
    try:
        parsed = stdlib_uuid.UUID(uuid_text)
    except (ValueError, AttributeError) as exc:
        raise argparse.ArgumentTypeError("uuid must be a valid interface UUID") from exc
    return f"{parsed}:{version}"


class MSRPCArgs(BaseArgs):
    target: Target
    tests: str | None
    pipes: list[str] | None
    username: str | None
    password: str | None
    username_file: str | None
    password_file: str | None
    pipe: str | None
    domain: str
    uuid: str | None
    output: str | None
    threads: int
    max_attempts: int
    samr_max_users: int
    timeout_seconds: float
    module_threads: int
    debug: bool
    json: bool

    @staticmethod
    def get_help():
        tests = ", ".join(MSRPC_TEST_ORDER)
        safe = ", ".join(MSRPC_DEFAULT_SUITE)
        return [
            {"description": ["MSRPC Testing Module"]},
            {"usage": ["ptsrvtester msrpc -ts <test>[,<test>...] -tg <host> <options>"]},
            {"usage_example": [
                "ptsrvtester msrpc -ts ENUMEPM -tg 192.168.1.1",
                "ptsrvtester msrpc -ts ALL -tg server.example.test",
                "ptsrvtester msrpc -ts ENUMPIPES -tg 192.168.1.1 -u auditor -pw secret",
                "ptsrvtester msrpc -ts SAMRPOLICY -tg 192.168.1.1 -u auditor -pw secret",
                "ptsrvtester msrpc -ts SAMRUSERS -tg 192.168.1.1 -u auditor -pw secret",
                "ptsrvtester msrpc -ts BRUTEPIPE -tg 192.168.1.1 --pipe svcctl -ul users.txt -pl passwords.txt",
                "ptsrvtester msrpc -ts BRUTETCP -tg 192.168.1.1:49154 --uuid 367abb81-9844-35f1-ad32-98f038001003:2.0 -u auditor -pw secret",
            ]},
            {"options": [
                ["-ts", "--tests", "<test>", f"{tests}; ALL/default safe suite: {safe}"],
                ["-tg", "--target", "<host>", "IPv4 or HOST[:PORT]; defaults: RPC 135, SMB 445, HTTPS RPC Proxy 443"],
                ["", "--pipe", "<name>", "BRUTEPIPE: named-pipe name"],
                ["", "--pipes", "<names>", "ENUMPIPES: comma-separated named-pipe names"],
                ["-d", "--domain", "<domain>", "Authentication domain"],
                ["", "--uuid", "<uuid[:ver]>", "BRUTETCP: interface UUID and optional version (default 1.0)"],
                ["-u", "--username", "<user>", "One username"],
                ["-ul", "--username-file", "<file>", "Username wordlist"],
                ["-pw", "--password", "<password>", "One password"],
                ["-pl", "--password-file", "<file>", "Password wordlist"],
                ["", "--threads", "<1-100>", "Credential-test concurrency (default 10)"],
                ["", "--max-attempts", "<1-100000>", "Reject larger credential products (default 1000)"],
                ["", "--samr-max-users", "<1-10000>", "SAMRUSERS: maximum returned users (default 1000)"],
                ["", "--timeout-seconds", "<1-60>", "Per-connection timeout (default 5)"],
                ["-o", "--output", "<file>", "Append positive enumeration/credential results"],
                ["-j", "--json", "", "JSON output"],
                ["-vv", "--verbose", "", "Verbose diagnostics"],
                ["-h", "--help", "", "Show this help"],
            ]},
        ]

    def add_subparser(self, name, subparsers):
        parser = subparsers.add_parser(
            name,
            add_help=True,
            formatter_class=argparse.RawTextHelpFormatter,
            epilog=(
                "Authenticated and credential tests marked explicit-only are never selected by ALL.\n"
                "An explicit target port is valid for one transport family at a time."
            ),
        )
        parser.add_argument(
            "-tg", "--target", type=valid_target, required=True, metavar="<host>", dest="target"
        )
        parser.add_argument("-ts", "--tests", default=None, metavar="<test>", dest="tests")
        parser.add_argument("--pipe", type=_pipe_name, default=None)
        parser.add_argument("--pipes", type=_pipe_names, default=None)
        parser.add_argument("-d", "--domain", default="")
        parser.add_argument("--uuid", type=normalize_interface_uuid, default=None)

        users = parser.add_mutually_exclusive_group()
        users.add_argument("-u", "--username", default=None)
        users.add_argument("-ul", "--username-file", "--username_file", dest="username_file", default=None)
        passwords = parser.add_mutually_exclusive_group()
        passwords.add_argument("-pw", "--password", default=None)
        passwords.add_argument("-pl", "--password-file", "--password_file", dest="password_file", default=None)

        parser.add_argument("--threads", type=_bounded_threads, default=10)
        parser.add_argument("--max-attempts", type=_bounded_attempts, default=1000)
        parser.add_argument(
            "--samr-max-users",
            type=_bounded_samr_users,
            default=1000,
            dest="samr_max_users",
        )
        parser.add_argument("--timeout-seconds", type=_bounded_timeout, default=5.0)
        parser.add_argument("-o", "--output", default=None)
        parser.add_argument(
            "--module-threads", type=int, default=1, dest="module_threads", help=argparse.SUPPRESS
        )


def validate_msrpc_selection(args: MSRPCArgs) -> list[str]:
    """Validate prerequisites before any DNS lookup or network connection."""
    selected = expand_msrpc_selection(getattr(args, "tests", None))
    unknown = [code for code in selected if code not in MSRPC_TESTS]
    if unknown:
        raise argparse.ArgumentError(
            None,
            f"Unknown MSRPC test(s): {', '.join(unknown)}. "
            f"Available: ALL, {', '.join(MSRPC_TEST_ORDER)}",
        )

    target = getattr(args, "target", None)
    if target is None:
        raise argparse.ArgumentError(None, "MSRPC requires -tg/--target")
    families = selection_families(selected)
    if getattr(target, "port", 0) and len(families) > 1:
        raise argparse.ArgumentError(
            None,
            "An explicit target port is ambiguous for mixed RPC/SMB/HTTP tests; "
            "run each transport family separately",
        )

    brute = tests_with_credential_mode(selected, "product_required")
    if brute:
        if not (getattr(args, "username", None) or getattr(args, "username_file", None)):
            raise argparse.ArgumentError(
                None, f"{', '.join(sorted(brute))} requires -u/--username or -ul/--username-file"
            )
        if not (getattr(args, "password", None) or getattr(args, "password_file", None)):
            raise argparse.ArgumentError(
                None, f"{', '.join(sorted(brute))} requires -pw/--password or -pl/--password-file"
            )

    direct = tests_with_credential_mode(selected, "direct_required")
    if direct:
        direct_names = ", ".join(sorted(direct))
        if not getattr(args, "username", None):
            raise argparse.ArgumentError(
                None, f"{direct_names} requires one direct -u/--username value"
            )
        if getattr(args, "password", None) is None:
            raise argparse.ArgumentError(
                None, f"{direct_names} requires one direct -pw/--password value"
            )
        if getattr(args, "username_file", None) or getattr(args, "password_file", None):
            raise argparse.ArgumentError(
                None, f"{direct_names} does not accept credential wordlists; run it separately"
            )
    if "BRUTEPIPE" in selected and not getattr(args, "pipe", None):
        raise argparse.ArgumentError(None, "BRUTEPIPE requires --pipe")
    if "BRUTETCP" in selected:
        if not getattr(args, "uuid", None):
            raise argparse.ArgumentError(None, "BRUTETCP requires --uuid")
        if not getattr(target, "port", 0):
            raise argparse.ArgumentError(
                None, "BRUTETCP requires the RPC endpoint port in -tg HOST:PORT"
            )
        other_rpc_tests = [
            code
            for code in selected
            if code != "BRUTETCP" and MSRPC_TESTS[code]["family"] == "rpc"
        ]
        if other_rpc_tests:
            raise argparse.ArgumentError(
                None,
                "BRUTETCP endpoint port cannot also be used by "
                f"{', '.join(other_rpc_tests)}; run BRUTETCP separately",
            )
    if "BRUTEHTTP" in selected and getattr(target, "port", 0) not in (0, 80, 443):
        raise argparse.ArgumentError(
            None, "BRUTEHTTP RPC Proxy transport supports only HTTP port 80 or HTTPS port 443"
        )
    if (
        "ENUMPIPES" in selected
        and not brute
        and (
            getattr(args, "username_file", None)
            or getattr(args, "password_file", None)
        )
    ):
        raise argparse.ArgumentError(
            None,
            "ENUMPIPES accepts only single -u/--username and -pw/--password values; "
            "wordlists are for explicit brute tests",
        )
    return selected


__all__ = [
    "MSRPCArgs",
    "MSRPC_DEFAULT_SUITE",
    "MSRPC_EXPLICIT_ONLY_TESTS",
    "MSRPC_TEST_ORDER",
    "normalize_interface_uuid",
    "validate_msrpc_selection",
]
