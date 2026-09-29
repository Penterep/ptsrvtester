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
    "AUTHMETHODS",
    "USERENUM",
    "BRUTEPROT",
    "RATELIMIT",
)
RDP_TEST_ALIASES = {"INFO": "NTLMINFO"}
RDP_TEST_CHOICES = RDP_TEST_ORDER + tuple(RDP_TEST_ALIASES)
IMPLEMENTED_TESTS = set(RDP_TEST_ORDER)
RDP_EXPLICIT_ONLY_TESTS = frozenset(
    {"AUTHMETHODS", "USERENUM", "BRUTEPROT", "RATELIMIT"}
)

_RDP_TEST_HELP = {
    "NLA": {
        "description": "Check whether Network Level Authentication is required",
        "detail": "Compare CredSSP negotiation with TLS and Standard RDP Security without NLA.",
    },
    "RDPSEC": {
        "description": "Check legacy Standard RDP Security",
        "detail": "Request Standard RDP Security and report whether the server accepts it.",
    },
    "CREDSSP": {
        "description": "Check CredSSP protocol support",
        "detail": "Negotiate CredSSP/NLA without submitting credentials.",
    },
    "RDPENC": {
        "description": "Enumerate RDP security and encryption",
        "detail": "Probe supported security protocols and legacy RDP encryption methods.",
    },
    "CAPABIL": {
        "description": "Inspect RDP capabilities",
        "detail": "Read Basic Settings and channel negotiation; credentials can expose additional session capabilities.",
        "options": (
            ["-l", "--login", "<login>", "Login for authenticated capability exchange"],
            ["-p", "--password", "<password>", "Password for authenticated capability exchange"],
            ["", "--insecure-auth", "", "Allow credentials with an unverified RDP TLS certificate"],
        ),
    },
    "VERSION": {
        "description": "Read the server's RDP protocol version",
        "detail": "Use Server Core Data, with an authenticated fallback if credentials are supplied; report the possible OS family.",
        "options": (
            ["-l", "--login", "<login>", "Login for the authenticated fallback"],
            ["-p", "--password", "<password>", "Password for the authenticated fallback"],
            ["", "--insecure-auth", "", "Allow credentials with an unverified RDP TLS certificate"],
        ),
    },
    "SSL": {
        "description": "Inspect RDP TLS configuration",
        "detail": "Check TLS negotiation, protocol versions, selected cipher and server certificate.",
    },
    "NTLMINFO": {
        "description": "Read pre-authentication NTLM information",
        "detail": "Decode the CredSSP NTLM challenge for server and domain information without logging in.",
    },
    "AUTH": {
        "description": "Try one CredSSP/NTLM login",
        "detail": "Attempt one supplied username and password over CredSSP/NLA.",
        "requires": ("-l/--login and -p/--password",),
        "usage_args": " -l <login> -p <password>",
        "options": (
            ["-l", "--login", "<login>", "Username to authenticate"],
            ["-p", "--password", "<password>", "Password to authenticate"],
            ["", "--insecure-auth", "", "Allow credentials with an unverified RDP TLS certificate"],
        ),
    },
    "AUTHMETHODS": {
        "description": "Check NTLM and Kerberos password authentication",
        "detail": "Probe CredSSP authentication methods; Kerberos needs valid credentials and domain settings.",
        "requires": ("Kerberos: -l/--login, -p/--password, --realm, --kdc and --spn-host",),
        "usage_args": " --auth-methods ntlm",
        "options": (
            ["", "--auth-methods", "<method>", "ntlm and/or kerberos (default: both)"],
            ["-l", "--login", "<login>", "Username for a credentialed attempt"],
            ["-p", "--password", "<password>", "Password for a credentialed attempt"],
            ["", "--realm", "<realm>", "Kerberos realm/domain"],
            ["", "--kdc", "<ip>", "Kerberos KDC IP address"],
            ["", "--spn-host", "<host>", "Hostname for the RDP service SPN"],
            ["", "--insecure-auth", "", "Allow credentials with an unverified RDP TLS certificate"],
        ),
    },
    "USERENUM": {
        "description": "Compare RDP responses for candidate usernames",
        "detail": "Send wrong passwords for a known login and optional candidates; attempts can contribute to lockout.",
        "requires": ("-l/--login (known valid username)", "--allow-auth-failures"),
        "usage_args": " -l <known-login> --allow-auth-failures",
        "options": (
            ["-l", "--login", "<login>", "Known valid username for the baseline"],
            ["-p", "--password", "<password>", "Optional valid password to verify the baseline"],
            ["-U", "--users", "<file>", "UTF-8 file with candidate usernames"],
            ["", "--allow-auth-failures", "", "Allow intentional failed logins"],
            ["", "--guess-delay-ms", "<ms>", "Delay between attempts (default: 100)"],
            ["", "--insecure-auth", "", "Allow credentials with an unverified RDP TLS certificate"],
        ),
    },
    "BRUTEPROT": {
        "description": "Check password-guessing protections",
        "detail": "Send bounded failed logins with random nonexistent identities; optional account-lockout check may lock a disposable account.",
        "requires": ("--allow-auth-failures", "--lockout-test: valid -l/--login and -p/--password for a disposable account"),
        "usage_args": " --allow-auth-failures",
        "options": (
            ["", "--allow-auth-failures", "", "Allow intentional failed logins"],
            ["", "--guess-attempts", "<count>", "Failed attempts (default: 10; range: 2-100)"],
            ["", "--guess-delay-ms", "<ms>", "Delay between attempts (default: 100)"],
            ["-l", "--login", "<login>", "Optional valid baseline; required for --lockout-test"],
            ["-p", "--password", "<password>", "Optional valid baseline; required for --lockout-test"],
            ["", "--lockout-test", "", "Test lockout of the supplied disposable account"],
            ["", "--lockout-attempts", "<count>", "Disposable-account attempts (default: 3; range: 1-20)"],
            ["", "--insecure-auth", "", "Allow credentials with an unverified RDP TLS certificate"],
        ),
    },
    "RATELIMIT": {
        "description": "Check RDP connection limiting",
        "detail": "Measure completed and/or held connection pressure and post-load recovery.",
        "requires": ("--allow-load-test",),
        "usage_args": " --allow-load-test",
        "options": (
            ["", "--allow-load-test", "", "Allow active connection load"],
            ["", "--rate-mode", "<mode>", "completed, held or both (default: both)"],
            ["", "--rate-count", "<count>", "Connections per scenario (default: 30; range: 5-200)"],
            ["", "--rate-concurrency", "<count>", "Parallel connections (default: 10; range: 1-50)"],
            ["", "--rate-hold-seconds", "<seconds>", "Held-connection duration (default: 3; range: 0-30)"],
            ["", "--rate-cooldown-seconds", "<seconds>", "Recovery delay (default: 2; range: 0-60)"],
        ),
    },
}


def _rdp_test_help(codes: list[str]):
    """Build the shared help printer's short guide for selected RDP tests."""
    if not codes:
        return None
    selected = [code.strip().upper() for code in codes if code.strip().upper() != "ALL"]
    if not selected:
        return None
    unknown = [code for code in selected if code not in RDP_TEST_CHOICES]
    if unknown:
        return [
            {"unknown_test": [f"Unknown test: {', '.join(unknown)}"]},
            {"available_tests": [f"ALL, {', '.join(RDP_TEST_CHOICES)}"]},
        ]

    help_data: list[dict] = []
    seen: set[str] = set()
    for requested in selected:
        canonical = RDP_TEST_ALIASES.get(requested, requested)
        if canonical in seen:
            continue
        seen.add(canonical)
        spec = _RDP_TEST_HELP[canonical]
        name = f"{requested} (alias for {canonical})" if requested != canonical else canonical
        help_data.append({"description": [f"{name}: {spec['description']}", spec["detail"]]})
        if spec.get("requires"):
            help_data.append({"requires": list(spec["requires"])})
        if spec.get("options"):
            help_data.append({"test_options": list(spec["options"])})
        usage_args = spec.get("usage_args", "")
        help_data.append({"usage": [f"ptsrvtester rdp -ts {requested}{usage_args} -tg <host>"]})
    return help_data


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


def _bounded_int_parser(
    option: str,
    minimum: int,
    maximum: int,
):
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


_GUESS_ATTEMPTS = _bounded_int_parser("--guess-attempts", 2, 100)
_GUESS_DELAY_MS = _bounded_int_parser("--guess-delay-ms", 0, 60_000)
_LOCKOUT_ATTEMPTS = _bounded_int_parser("--lockout-attempts", 1, 20)
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
    auth_methods: list[str] | None
    realm: str | None
    kdc: str | None
    spn_host: str | None
    users: str | None
    allow_auth_failures: bool
    guess_attempts: int
    guess_delay_ms: int
    lockout_test: bool
    lockout_attempts: int
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
            {"usage": ["ptsrvtester rdp -tg <host> <options>"]},
            {"usage_example": [
                "ptsrvtester rdp -tg 192.168.1.182",
                "ptsrvtester rdp -tg 12.32.43.163 -ts NLA AUTH -l admin -p pass123",
                "ptsrvtester rdp -tg 192.168.1.10 -ts AUTHMETHODS --auth-methods ntlm",
                "ptsrvtester rdp -tg 192.168.1.10 -ts USERENUM -l test-user --allow-auth-failures",
                "ptsrvtester rdp -tg 192.168.1.10 -ts BRUTEPROT --allow-auth-failures --guess-attempts 10",
                "ptsrvtester rdp -tg 192.168.1.10 -ts BRUTEPROT -l disposable -p test-pass --allow-auth-failures --lockout-test",
                "ptsrvtester rdp -tg rdp.example.com -ts NLA",
            ]},
            {"options": [
                ["-tg", "--target", "<host>", "Target IP[:PORT] or HOST[:PORT] (default port: 3389)"],
                ["-ts", "--tests", "<test>", "Specify tests; 'rdp -ts <TEST> -h' for test options"],
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
                ["", "", "AUTHMETHODS", "NLA/CredSSP password authentication through NTLM and Kerberos"],
                ["", "", "USERENUM", "Username enumeration test"],
                ["", "", "BRUTEPROT", "Password-guessing protection test"],
                ["", "", "RATELIMIT", "RDP connection limiting test"],
                ["-l", "--login", "<login>", "Login for account-based tests"],
                ["-p", "--password", "<password>", "Password for account-based tests"],
                ["-U", "--users", "<file>", "USERENUM candidate wordlist"],
                ["", "--auth-methods", "<method>", "AUTHMETHODS subset: ntlm kerberos"],
                ["", "--realm", "<realm>", "Kerberos realm/domain"],
                ["", "--kdc", "<ip>", "Kerberos KDC/domain-controller IP address"],
                ["", "--spn-host", "<host>", "RDP service hostname for the Kerberos SPN"],
                ["", "--allow-auth-failures", "", "Allow intentional failed login attempts"],
                ["", "--guess-attempts", "<count>", "Bounded BRUTEPROT attempt count"],
                ["", "--guess-delay-ms", "<ms>", "Delay between active authentication attempts"],
                ["", "--lockout-test", "", "May lock the supplied disposable account"],
                ["", "--lockout-attempts", "<count>", "Bounded disposable-account attempts"],
                ["", "--allow-load-test", "", "Allow RATELIMIT connection load"],
                ["", "--rate-mode", "<mode>", "completed, held, or both"],
                ["", "--rate-count", "<count>", "Connections per RATELIMIT scenario"],
                ["", "--rate-concurrency", "<count>", "Parallel RATELIMIT connections"],
                ["", "--rate-hold-seconds", "<seconds>", "Held-connection duration"],
                ["", "--rate-cooldown-seconds", "<seconds>", "Post-load recovery delay"],
                ["", "--insecure-auth", "", "Allow credentials with an untrusted RDP TLS certificate"],
                ["-T", "--timeout", "<milliseconds>", "Network timeout (default 10000)"],
                ["", "", "", ""],
                ["-h", "--help", "", "Show this help; 'rdp -ts <TEST> -h' for test options"],
                ["-vv", "--verbose", "", "Enable verbose mode"],
            ]},
            {"note": [
                (
                    "When -ts/--tests is omitted, all safe pre-auth tests are "
                    "executed; AUTH is also executed when both credentials are "
                    "supplied."
                ),
                "AUTH performs one CredSSP/NTLM authentication attempt.",
                (
                    "AUTHMETHODS, USERENUM, BRUTEPROT and RATELIMIT are "
                    "explicit-only and are not implied by ALL."
                ),
                (
                    "USERENUM and BRUTEPROT require --allow-auth-failures; "
                    "RATELIMIT requires --allow-load-test."
                ),
                (
                    "USERENUM sends a wrong password for the known login and each "
                    "tested candidate; these attempts can contribute to lockout."
                ),
                (
                    "BRUTEPROT normally uses random nonexistent identities and "
                    "observes source-wide behavior; --lockout-test may lock the "
                    "supplied disposable account."
                ),
                (
                    "Kerberos password authentication requires valid credentials, "
                    "--realm, --kdc and --spn-host."
                ),
                (
                    "Use --insecure-auth only for an explicitly trusted test target "
                    "whose RDP certificate cannot be validated."
                ),
            ]},
        ]

    @staticmethod
    def get_test_help(codes):
        """Per-test help object used by ``rdp -ts <TEST> -h``."""
        return _rdp_test_help(codes)

    def add_subparser(self, name: str, subparsers) -> None:
        examples = """example usage:
  ptsrvtester rdp -tg 192.168.1.182
  ptsrvtester rdp -tg 192.168.1.10 -ts NLA NTLMINFO
  ptsrvtester rdp -tg 12.32.43.163 -ts NLA AUTH -l admin -p pass123
  ptsrvtester rdp -tg 192.168.1.10 -ts AUTHMETHODS --auth-methods ntlm
  ptsrvtester rdp -tg 192.168.1.10 -ts USERENUM -l known-user --allow-auth-failures
  ptsrvtester rdp -tg 192.168.1.10 -ts BRUTEPROT --allow-auth-failures --guess-attempts 10
  ptsrvtester rdp -tg 192.168.1.10 -ts BRUTEPROT -l disposable -p test-pass --allow-auth-failures --lockout-test
  ptsrvtester rdp -tg rdp.example.com -ts NLA
  ptsrvtester rdp -tg 192.168.1.10 -vv"""

        parser = subparsers.add_parser(
            name,
            add_help=True,
            epilog=examples,
            formatter_class=argparse.RawTextHelpFormatter,
        )

        if not isinstance(parser, argparse.ArgumentParser):
            raise TypeError

        parser.add_argument(
            "-tg",
            "--target",
            type=valid_target_rdp,
            required=True,
            metavar="<host>",
            help="Target IP[:PORT] or HOST[:PORT] (default port: 3389)",
        )
        parser.add_argument(
            "-ts",
            "--tests",
            nargs="+",
            type=_valid_test_token,
            metavar="TEST",
            help=(
                "tests to run: NLA, RDPSEC, CREDSSP, RDPENC, CAPABIL, "
                "VERSION, SSL, NTLMINFO, INFO, AUTH, AUTHMETHODS, USERENUM, "
                "BRUTEPROT, RATELIMIT; use 'rdp -ts <TEST> -h' for details"
            ),
        )
        parser.add_argument("-l", "--login", help="login for account-based tests")
        parser.add_argument("-p", "--password", help="password for account-based tests")
        parser.add_argument(
            "-U",
            "--users",
            metavar="FILE",
            help="UTF-8 USERENUM candidates; one wrong-password attempt per entry",
        )
        parser.add_argument(
            "--auth-methods",
            nargs="+",
            choices=("ntlm", "kerberos"),
            help=(
                "NLA/CredSSP password authentication mechanisms to test "
                "(default: ntlm kerberos)"
            ),
        )
        parser.add_argument("--realm", help="Kerberos realm/domain")
        parser.add_argument("--kdc", help="Kerberos KDC/domain-controller IP address")
        parser.add_argument(
            "--spn-host",
            help="RDP service hostname used to construct the Kerberos SPN",
        )
        parser.add_argument(
            "--allow-auth-failures",
            action="store_true",
            help="allow intentional failed authentication attempts",
        )
        parser.add_argument(
            "--guess-attempts",
            type=_GUESS_ATTEMPTS,
            default=10,
            metavar="COUNT",
            help="failed attempts for BRUTEPROT (default: 10; range: 2-100)",
        )
        parser.add_argument(
            "--guess-delay-ms",
            type=_GUESS_DELAY_MS,
            default=100,
            metavar="MILLISECONDS",
            help="delay between USERENUM/BRUTEPROT attempts (default: 100; range: 0-60000)",
        )
        parser.add_argument(
            "--lockout-test",
            action="store_true",
            help="test lockout; may lock the supplied disposable account",
        )
        parser.add_argument(
            "--lockout-attempts",
            type=_LOCKOUT_ATTEMPTS,
            default=3,
            metavar="COUNT",
            help="wrong passwords in --lockout-test (default: 3; range: 1-20)",
        )
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
    "RDP_TEST_ALIASES",
    "RDP_TEST_CHOICES",
    "RDP_TEST_ORDER",
    "RDPArgs",
    "valid_target_rdp",
]
