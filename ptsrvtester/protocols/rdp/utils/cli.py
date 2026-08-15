"""Command-line interface for the RDP protocol package."""

from __future__ import annotations

import argparse
import ipaddress
import math
import socket
from dataclasses import dataclass

try:
    from ptsrvtester.protocols._base import BaseArgs
except ModuleNotFoundError as exc:  # compatibility until the BaseMain rebase lands
    if exc.name != "ptsrvtester.protocols._base":
        raise
    from ptsrvtester.modules._base import BaseArgs


@dataclass
class Target:
    ip: str
    port: int


def valid_target(
    target: str,
    *,
    port_required: bool = False,
    domain_allowed: bool = False,
) -> Target:
    """Parse the legacy IPv4/hostname ``HOST[:PORT]`` target syntax."""
    split = target.split(":")
    if not port_required and len(split) > 2:
        raise argparse.ArgumentError(None, "The target has to be IP[:PORT]")
    if port_required and len(split) != 2:
        raise argparse.ArgumentError(None, "The target has to be IP:PORT")

    host = split[0]
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not domain_allowed:
            raise argparse.ArgumentError(None, "Invalid target IP address") from None
        try:
            socket.gethostbyname(host)
        except OSError:
            raise argparse.ArgumentError(
                None, f"Cannot resolve target name '{host}' into IP address"
            ) from None

    if len(split) > 1:
        try:
            port = int(split[1])
            if port <= 0 or port >= 65536:
                raise ValueError
        except ValueError:
            raise argparse.ArgumentError(None, "Invalid PORT number") from None
    else:
        port = 0
    return Target(host, port)


RDP_TEST_ORDER = (
    "NLA",
    "RDPSEC",
    "CREDSSP",
    "RDPENC",
    "CAPABIL",
    "VERSION",
    "SSL",
    "NTLMINFO",
    "AUTH",
    "RATELIMIT",
)
RDP_TEST_ALIASES = {"INFO": "NTLMINFO"}
RDP_TEST_CHOICES = RDP_TEST_ORDER + tuple(RDP_TEST_ALIASES)
IMPLEMENTED_TESTS = set(RDP_TEST_ORDER)
RDP_EXPLICIT_ONLY_TESTS = frozenset({"RATELIMIT"})


def valid_target_rdp(target: str) -> Target:
    """Accept an IP address or hostname with an optional port."""
    return valid_target(target, domain_allowed=True)


def _valid_test_token(value: str) -> str:
    """Validate one argparse token, which may contain comma-separated codes."""
    codes = [code.strip().upper() for code in value.split(",") if code.strip()]
    allowed = set(RDP_TEST_CHOICES) | {"ALL"}
    invalid = [code for code in codes if code not in allowed]
    if not codes or invalid:
        bad = ", ".join(invalid) if invalid else value
        raise argparse.ArgumentTypeError(
            f"unknown RDP test(s): {bad}; choose from {', '.join(RDP_TEST_CHOICES)}"
        )
    return ",".join(codes)


def _bounded_int_parser(option: str, minimum: int, maximum: int):
    """Build an argparse integer parser which enforces a safety boundary."""

    def parse(value: str) -> int:
        try:
            parsed = int(value)
        except ValueError:
            raise argparse.ArgumentTypeError(f"{option} must be an integer") from None
        if not minimum <= parsed <= maximum:
            raise argparse.ArgumentTypeError(
                f"{option} must be between {minimum} and {maximum}"
            )
        return parsed

    return parse


def _bounded_float_parser(option: str, minimum: float, maximum: float):
    """Build an argparse finite-float parser with inclusive bounds."""

    def parse(value: str) -> float:
        try:
            parsed = float(value)
        except ValueError:
            raise argparse.ArgumentTypeError(f"{option} must be a number") from None
        if not math.isfinite(parsed) or not minimum <= parsed <= maximum:
            raise argparse.ArgumentTypeError(
                f"{option} must be between {minimum:g} and {maximum:g}"
            )
        return parsed

    return parse


_RATE_COUNT = _bounded_int_parser("--rate-count", 5, 200)
_RATE_CONCURRENCY = _bounded_int_parser("--rate-concurrency", 1, 50)
_RATE_HOLD_SECONDS = _bounded_float_parser("--rate-hold-seconds", 0, 30)
_RATE_COOLDOWN_SECONDS = _bounded_float_parser(
    "--rate-cooldown-seconds",
    0,
    60,
)


class RDPArgs(BaseArgs):
    target: Target
    tests: list[str] | str | None
    login: str | None
    password: str | None
    insecure_auth: bool
    timeout: int
    allow_load_test: bool
    rate_mode: str
    rate_count: int
    rate_concurrency: int
    rate_hold_seconds: float
    rate_cooldown_seconds: float

    @staticmethod
    def get_help():
        return [
            {"description": ["RDP Testing Module"]},
            {"usage": ["ptsrvtester rdp <target> <options>"]},
            {"usage_example": [
                "ptsrvtester rdp 192.168.1.10 -ts NLA",
                "ptsrvtester rdp 12.32.43.163 -ts NLA AUTH -l admin -p pass123",
                "ptsrvtester rdp rdp.example.com -ts NLA",
            ]},
            {"options": [
                ["-ts", "--tests", "<test>", "Specify one or more tests to perform"],
                ["", "", "NLA", "Network Level Authentication requirement test"],
                ["", "", "RDPSEC", "Legacy Standard RDP Security negotiation test"],
                ["", "", "CREDSSP", "CredSSP protocol support test"],
                ["", "", "RDPENC", "Security protocols and RDP encryption enumeration"],
                ["", "", "CAPABIL", "RDP capability negotiation"],
                ["", "", "VERSION", "RDP protocol version reported by the server"],
                ["", "", "SSL", "TLS/RDP Security configuration test"],
                ["", "", "NTLMINFO", "Pre-auth CredSSP/NTLM server information test"],
                ["", "", "INFO", "Alias for NTLMINFO"],
                ["", "", "AUTH", "Single CredSSP/NTLM authentication test"],
                ["", "", "RATELIMIT", "RDP connection limiting test"],
                ["-l", "--login", "<login>", "Login for account-based tests"],
                ["-p", "--password", "<password>", "Password for account-based tests"],
                ["", "--allow-load-test", "", "Allow RATELIMIT connection load"],
                ["", "--rate-mode", "<mode>", "completed, held, or both"],
                ["", "--rate-count", "<count>", "Connections per RATELIMIT scenario"],
                ["", "--rate-concurrency", "<count>", "Parallel RATELIMIT connections"],
                ["", "--rate-hold-seconds", "<seconds>", "Held-connection duration"],
                ["", "--rate-cooldown-seconds", "<seconds>", "Post-load recovery delay"],
                ["", "--insecure-auth", "", "Allow credentials with an untrusted RDP TLS certificate"],
                ["-T", "--timeout", "<milliseconds>", "Network timeout (default 10000)"],
                ["", "", "", ""],
                ["-h", "--help", "", "Show this help message and exit"],
                ["-vv", "--verbose", "", "Enable verbose mode"],
            ]},
            {"note": [
                "When -ts/--tests is omitted, all safe pre-auth tests are executed; "
                "AUTH is also executed when both credentials are supplied.",
                "AUTH performs one CredSSP/NTLM authentication attempt.",
                "RATELIMIT is explicit-only, is not implied by ALL, and requires "
                "--allow-load-test.",
                "Use --insecure-auth only for an explicitly trusted test target "
                "whose RDP certificate cannot be validated.",
            ]},
        ]

    def add_subparser(self, name: str, subparsers) -> None:
        examples = """example usage:
  ptsrvtester rdp 192.168.1.10 -ts NLA
  ptsrvtester rdp 192.168.1.10 -ts NLA NTLMINFO
  ptsrvtester rdp 12.32.43.163 -ts NLA AUTH -l admin -p pass123
  ptsrvtester rdp rdp.example.com -ts NLA
  ptsrvtester rdp 192.168.1.10 -vv"""

        parser = subparsers.add_parser(
            name,
            add_help=True,
            epilog=examples,
            formatter_class=argparse.RawTextHelpFormatter,
        )

        if not isinstance(parser, argparse.ArgumentParser):
            raise TypeError

        parser.add_argument(
            "target",
            type=valid_target_rdp,
            help="IP[:PORT] or HOST[:PORT] (default port: 3389)",
        )
        parser.add_argument(
            "-ts",
            "--tests",
            nargs="+",
            type=_valid_test_token,
            metavar="TEST",
            help=(
                "tests to run: NLA, RDPSEC, CREDSSP, RDPENC, CAPABIL, "
                "VERSION, SSL, NTLMINFO, INFO, AUTH, RATELIMIT"
            ),
        )
        parser.add_argument("-l", "--login", help="login for account-based tests")
        parser.add_argument("-p", "--password", help="password for account-based tests")
        parser.add_argument(
            "--allow-load-test",
            action="store_true",
            help="allow active RATELIMIT connection load",
        )
        parser.add_argument(
            "--rate-mode",
            choices=("completed", "held", "both"),
            default="both",
            help="RATELIMIT scenario (default: both)",
        )
        parser.add_argument(
            "--rate-count",
            type=_RATE_COUNT,
            default=30,
            metavar="COUNT",
            help="connections per RATELIMIT scenario (default: 30; range: 5-200)",
        )
        parser.add_argument(
            "--rate-concurrency",
            type=_RATE_CONCURRENCY,
            default=10,
            metavar="COUNT",
            help="parallel RATELIMIT connections (default: 10; range: 1-50)",
        )
        parser.add_argument(
            "--rate-hold-seconds",
            type=_RATE_HOLD_SECONDS,
            default=3.0,
            metavar="SECONDS",
            help="how long held connections remain open (default: 3; range: 0-30)",
        )
        parser.add_argument(
            "--rate-cooldown-seconds",
            type=_RATE_COOLDOWN_SECONDS,
            default=2.0,
            metavar="SECONDS",
            help="recovery delay after RATELIMIT load (default: 2; range: 0-60)",
        )
        parser.add_argument(
            "--insecure-auth",
            action="store_true",
            help="allow credential use when the RDP TLS certificate is untrusted",
        )
        parser.add_argument(
            "-T",
            "--timeout",
            type=int,
            default=10000,
            metavar="MILLISECONDS",
            help="socket timeout in milliseconds (default: 10000)",
        )


__all__ = [
    "IMPLEMENTED_TESTS",
    "RDP_EXPLICIT_ONLY_TESTS",
    "RDPArgs",
    "RDP_TEST_ALIASES",
    "RDP_TEST_CHOICES",
    "RDP_TEST_ORDER",
    "valid_target_rdp",
]
