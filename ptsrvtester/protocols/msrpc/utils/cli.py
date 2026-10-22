"""Command-line contract for the MSRPC protocol module."""
from __future__ import annotations

import argparse
import math
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
_GUESS_TESTS = frozenset({"NTLMGUESS", "CHGUESS"})
_SAMR_TESTS = frozenset({"SAMRPOLICY", "SAMRUSERS", "SAMRGROUPS", "SAMRUSERINFO"})
_EPM_INTERFACE = "e1af8308-5d1f-11c9-91a4-08002b14a0fa:3.0"


def _bounded_guess_attempts(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("guess attempts must be an integer") from exc
    if not 1 <= parsed <= 100:
        raise argparse.ArgumentTypeError("guess attempts must be between 1 and 100")
    return parsed


def _bounded_guess_delay(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("guess delay must be a number") from exc
    if not math.isfinite(parsed) or not 0 <= parsed <= 60:
        raise argparse.ArgumentTypeError("guess delay must be between 0 and 60 seconds")
    return parsed


def _bounded_guess_window(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("guess window must be a number") from exc
    if not math.isfinite(parsed) or not 1 <= parsed <= 600:
        raise argparse.ArgumentTypeError("guess window must be between 1 and 600 seconds")
    return parsed


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


def _bounded_samr_inventory(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("SAMR inventory limit must be an integer") from exc
    if not 1 <= parsed <= 10_000:
        raise argparse.ArgumentTypeError("SAMR inventory limit must be between 1 and 10000")
    return parsed


def _samr_name(value: str) -> str:
    name = value.strip()
    if not name or "\x00" in name:
        raise argparse.ArgumentTypeError("SAMR name must be nonempty and contain no NUL")
    return name


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


def _credential_identity(username: str, domain: str | None) -> tuple[str, str]:
    if "\\" in username:
        domain, username = username.split("\\", 1)
    elif "@" in username:
        username, domain = username.rsplit("@", 1)
    return (domain or "").strip().casefold(), username.strip().casefold()


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


class _DirectUsers(argparse.Action):
    """Keep the single-user attribute used by direct SAMR and pipe probes."""

    def __call__(self, parser, namespace, values, option_string=None):
        namespace.usernames = values
        namespace.username = values[0] if len(values) == 1 else None


class MSRPCArgs(BaseArgs):
    target: Target
    tests: str | None
    pipes: list[str] | None
    username: str | None
    usernames: list[str] | None
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
    samr_max_groups: int
    samr_max_members: int
    samr_user: str | None
    samr_domain: str | None
    timeout_seconds: float
    module_threads: int
    guess_attempts: int
    guess_delay: float
    guess_window: float
    expect_lockout_after: int | None
    observer_user: str | None
    observer_password: str | None
    observer_domain: str | None
    debug: bool
    json: bool

    @staticmethod
    def get_help():
        safe = ", ".join(MSRPC_DEFAULT_SUITE)
        test_rows = [
            ["", "", code, str(MSRPC_TESTS[code]["description"])]
            for code in MSRPC_TEST_ORDER
        ]
        return [
            {"description": [
                "MSRPC Testing Module",
                "SAMR tests first check anonymous access. Optional -u/-p credentials add authenticated inventory; only anonymous disclosure creates a PTV finding.",
            ]},
            {"usage": ["ptsrvtester msrpc -ts <test>[,<test>...] -tg <host> <options>"]},
            {"usage_example": [
                "ptsrvtester msrpc -ts ENUMEPM -tg 192.168.1.1",
                "ptsrvtester msrpc -ts ALL -tg server.example.test",
                "ptsrvtester msrpc -ts ENUMPIPES -tg 192.168.1.1 -u auditor -p secret",
                "ptsrvtester msrpc -ts ANONSMB,SHARES -tg 192.168.1.1",
                "ptsrvtester msrpc -ts BRUTESMB -tg 192.168.1.1 -u auditor -p",
                'ptsrvtester msrpc -ts BRUTESMB -tg 192.168.1.1 -u auditor -p ""',
                "ptsrvtester msrpc -ts SAMRPOLICY -tg 192.168.1.1 -u auditor -p secret",
                "ptsrvtester msrpc -ts SAMRUSERS -tg 192.168.1.1",
                "ptsrvtester msrpc -ts SAMRUSERS -tg 192.168.1.1 -u auditor -p secret",
                "ptsrvtester msrpc -ts SAMRGROUPS -tg 192.168.1.1 -u auditor -p secret",
                "ptsrvtester msrpc -ts SAMRUSERINFO -tg 192.168.1.1 -u auditor -p secret --samr-user alice",
                "ptsrvtester msrpc -ts BRUTEPIPE -tg 192.168.1.1 --pipe svcctl -U users.txt -P passwords.txt",
                "ptsrvtester msrpc -ts BRUTETCP -tg 192.168.1.1:49154 --uuid 12345778-1234-abcd-ef00-0123456789ac:1.0 -u auditor -p secret",
                "ptsrvtester msrpc -ts NTLMGUESS -tg 192.168.1.1 -u test-account -p secret --guess-attempts 5",
                "ptsrvtester msrpc -ts CHGUESS -tg proxy.example.test -u test-account -p secret --guess-attempts 5",
            ]},
            {"options": [
                ["-ts", "--tests", "<test>", "One or more tests, comma-separated; ALL/default runs the safe suite"],
                ["", "", "ALL", f"Default safe suite: {safe}"],
                *test_rows,
                ["-tg", "--target", "<host>", "IPv4 or HOST[:PORT]; defaults: RPC 135, SMB 445, HTTPS RPC Proxy 443"],
                ["", "--pipe", "<name>", "BRUTEPIPE: pipe to open after SMB login; no RPC bind/call"],
                ["", "--pipes", "<names>", "ENUMPIPES: names to try opening; not a complete pipe inventory"],
                ["-d", "--domain", "<domain>", "Authentication domain"],
                ["", "--uuid", "<uuid[:ver]>", "BRUTETCP/NTLMGUESS: supported EPM/MGMT/SAMR/LSAD interface; NTLMGUESS defaults to EPM 3.0"],
                ["-u", "--user", "<name> ...", "Username(s); one for SAMR/ENUMPIPES/guessing-protection tests"],
                ["-U", "--users", "<wordlist>", "Username wordlist"],
                ["-p", "--password", "[<password>]", "Password; omit the value for an empty password"],
                ["-P", "--passwords", "<wordlist>", "Password wordlist"],
                ["", "--threads", "<1-100>", "Credential-test concurrency across accounts (default 10; one active attempt per account)"],
                ["", "--max-attempts", "<1-100000>", "Maximum credential product per test (default 1000); confirmed lockout stops further attempts for that account"],
                ["", "--guess-attempts", "<1-100>", "NTLMGUESS/CHGUESS: maximum generated invalid-password attempts (default 5; serial)"],
                ["", "--guess-delay", "<0-60>", "NTLMGUESS/CHGUESS: seconds between invalid attempts (default 0.2)"],
                ["", "--guess-window", "<1-600>", "NTLMGUESS/CHGUESS: maximum invalid-attempt burst duration in seconds (default 60)"],
                ["", "--expect-lockout-after", "<1-100>", "Expected lockout by this many invalid attempts, persisting through the post-burst control; limits the burst budget"],
                ["", "--observer-user", "<name>", "NTLMGUESS only: independent SMB/SAMR account observing the tested account's lockout state and failed-logon counter"],
                ["", "--observer-password", "[<password>]", "Observer account password; omit the value for an empty password"],
                ["", "--observer-domain", "<domain>", "Observer authentication domain (defaults to --domain)"],
                ["", "--samr-max-users", "<1-10000>", "SAMRUSERS/SAMRUSERINFO: global user limit (default 1000)"],
                ["", "--samr-max-groups", "<1-10000>", "SAMRGROUPS: global group/alias limit (default 1000)"],
                ["", "--samr-max-members", "<1-10000>", "SAMRGROUPS: returned members per group (default 1000; server response is not paginated)"],
                ["", "--samr-user", "<name>", "SAMRUSERINFO: look up one account instead of enumerating users"],
                ["", "--samr-domain", "<name>", "SAMRUSERINFO: target SAM domain; distinct from authentication --domain"],
                ["", "--timeout-seconds", "<1-60>", "Per-connection timeout (default 5)"],
                ["-o", "--output", "<file>", "Append positive enumeration/credential results"],
                ["-j", "--json", "", "JSON output"],
                ["-vv", "--verbose", "", "Verbose diagnostics"],
                ["-h", "--help", "", "Show this help"],
            ]},
        ]

    @staticmethod
    def get_test_help(codes: list[str]):
        selected = list(dict.fromkeys(code.strip().upper() for code in codes if code.strip()))
        if not selected or selected == ["ALL"]:
            return None
        unknown = [code for code in selected if code != "ALL" and code not in MSRPC_TESTS]
        if unknown:
            return [
                {"unknown_test": [f"Unknown test: {', '.join(unknown)}"]},
                {"available_tests": [f"ALL, {', '.join(MSRPC_TEST_ORDER)}"]},
            ]

        common_options = MSRPCArgs.get_help()[-1]["options"]
        selected_options = {
            "ENUMPIPES": {"--pipes", "--user", "--password", "--domain"},
            "SAMRPOLICY": {"--user", "--password", "--domain"},
            "SAMRUSERS": {"--user", "--password", "--domain", "--samr-max-users"},
            "SAMRGROUPS": {"--user", "--password", "--domain", "--samr-max-groups", "--samr-max-members"},
            "SAMRUSERINFO": {"--user", "--password", "--domain", "--samr-max-users", "--samr-user", "--samr-domain"},
        }
        brute_options = {"--user", "--users", "--password", "--passwords", "--domain", "--threads", "--max-attempts"}
        guess_options = {
            "--user", "--password", "--domain", "--guess-attempts", "--guess-delay",
            "--guess-window", "--expect-lockout-after", "--observer-user",
            "--observer-password", "--observer-domain",
        }
        help_data = []
        for code in selected:
            if code == "ALL":
                continue
            metadata = MSRPC_TESTS[code]
            family = str(metadata["family"])
            default_port = {"rpc": 135, "smb": 445, "http": 443}[family]
            description = [f"{code}: {metadata['description']}", f"Transport: {family.upper()}, default TCP port {default_port}."]
            if metadata.get("explicit_only"):
                description.append("Select this test explicitly; ALL does not include it.")
            help_data.append({"description": description})
            mode = metadata.get("credential_mode")
            usage_args = ""
            if mode == "direct_required":
                help_data.append({"requires": ["One -u/--user and -p/--password; credential wordlists are not accepted."]})
                usage_args = " -u auditor -p secret"
            elif mode == "direct_optional":
                help_data.append({"authentication": [
                    "Always check anonymous access first, using a separate connection without the supplied credentials.",
                    "Without -u/-p, or with both values empty, run only the anonymous check.",
                    "With one -u/--user and -p/--password, then run authenticated inventory in a separate connection; an empty password is valid for a named account.",
                    "Only proven anonymous disclosure creates a PTV finding; authenticated inventory alone does not create a disclosure finding.",
                    "Credential wordlists are not accepted.",
                ]})
            options = set(selected_options.get(code, ()))
            if mode == "product_required":
                options.update(brute_options)
                help_data.append({"requires": ["Usernames from -u/-U and passwords from -p/-P; each combination is tested within --max-attempts."]})
                usage_args = " -U users.txt -P passwords.txt"
            if code == "BRUTEPIPE":
                options.add("--pipe")
                usage_args += " --pipe svcctl"
                help_data.append({"requires": ["--pipe <name>; success confirms SMB identity and pipe opening, without an RPC bind or call."]})
            if code == "BRUTETCP":
                options.add("--uuid")
                usage_args += " --uuid 12345778-1234-abcd-ef00-0123456789ac:1.0"
                help_data.append({"requires": ["An explicit endpoint port in -tg HOST:PORT and --uuid for a supported EPM/MGMT/SAMR/LSAD interface; success requires a confirmed read-only RPC call."]})
            if code == "BRUTEHTTP":
                help_data.append({"requires": ["An HTTPS RPC Proxy with an EPM backend; success requires a confirmed read-only RPC call."]})
            if code in _GUESS_TESTS:
                options.update(guess_options)
                help_data.append({"method": [
                    "Use one known-valid account and password to confirm a signed read-only RPC baseline, then send a bounded serial burst of generated invalid passwords.",
                    "This test can lock the account. No successful logon for that account is interleaved with the invalid-password burst.",
                    "A successful control is checked after the burst. Generic authentication errors, RPC faults and timeouts do not prove account lockout.",
                    "Without --expect-lockout-after, a finite burst only reports observations; it does not create a missing-protection vulnerability.",
                    "With --expect-lockout-after N, the invalid-attempt budget is limited to N. The requirement is that account lockout persists through the single post-burst valid-credential control.",
                    "A vulnerability requires evidence that this specific account-lockout criterion was not met; no universal threshold is assumed.",
                    "This account-lockout criterion does not establish absence of other throttling or guessing protections.",
                    "Passwords are not printed.",
                ]})
            if code == "NTLMGUESS":
                options.add("--uuid")
                help_data.append({"requires": [
                    "Defaults to EPM 3.0 on TCP port 135. A different explicit endpoint port requires --uuid for a supported read-only confirmation call.",
                    "An independent --observer-user/--observer-password account can read SAMR evidence from the target host through SMB on port 445.",
                    "Specify --domain or a domain-qualified tested username to match observer evidence to the actual SAM domain.",
                ]})
            if code == "CHGUESS":
                options.difference_update({"--observer-user", "--observer-password", "--observer-domain"})
                help_data.append({"requires": [
                    "A working HTTP/HTTPS RPC Proxy on port 80/443 and an EPM backend; HTTP reachability or an opened tunnel alone does not establish a valid baseline.",
                    "One logical attempt may authenticate HTTP channels and the RPC backend; it is not an exact count of Windows failed logons.",
                    "Observer options are not supported: the RPC Proxy host's SMB accounts cannot be assumed to belong to the RPC backend.",
                ]})
            options.update({"--target", "--timeout-seconds", "--output", "--json", "--verbose", "--help"})
            help_data.append({"test_options": [row for row in common_options if row[1] in options]})
            target = "<host>:<port>" if code == "BRUTETCP" else "<host>"
            help_data.append({"usage": [f"ptsrvtester msrpc -ts {code} -tg {target}{usage_args}"]})
        return help_data

    def add_subparser(self, name, subparsers):
        parser = subparsers.add_parser(
            name,
            add_help=True,
            formatter_class=argparse.RawTextHelpFormatter,
            epilog=(
                "SAMR and credential tests marked explicit-only are never selected by ALL.\n"
                "SAMR tests first check anonymous access; optional -u/-p credentials add authenticated inventory.\n"
                "Only anonymous disclosure creates a PTV finding. Both credential values empty mean anonymous-only for SAMR selections.\n"
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

        parser.set_defaults(username=None)
        users = parser.add_mutually_exclusive_group()
        users.add_argument("-u", "--user", nargs="+", action=_DirectUsers, dest="usernames", metavar="<name>", default=None)
        users.add_argument("--username", nargs=1, action=_DirectUsers, dest="usernames", help=argparse.SUPPRESS)
        users.add_argument("-U", "--users", dest="username_file", metavar="<wordlist>", default=None)
        users.add_argument("-ul", "--username-file", "--username_file", dest="username_file", help=argparse.SUPPRESS)
        passwords = parser.add_mutually_exclusive_group()
        passwords.add_argument(
            "-p", "--password", nargs="?", const="", default=None,
            metavar="<password>", help="Password; omit the value for an empty password",
        )
        passwords.add_argument("-pw", dest="password", help=argparse.SUPPRESS)
        passwords.add_argument("-P", "--passwords", dest="password_file", metavar="<wordlist>", default=None)
        passwords.add_argument("-pl", "--password-file", "--password_file", dest="password_file", help=argparse.SUPPRESS)

        parser.add_argument("--threads", type=_bounded_threads, default=10)
        parser.add_argument("--max-attempts", type=_bounded_attempts, default=1000)
        parser.add_argument("--guess-attempts", type=_bounded_guess_attempts, default=5)
        parser.add_argument("--guess-delay", type=_bounded_guess_delay, default=0.2)
        parser.add_argument("--guess-window", type=_bounded_guess_window, default=60.0)
        parser.add_argument("--expect-lockout-after", type=_bounded_guess_attempts, default=None)
        parser.add_argument("--observer-user", type=_samr_name, default=None)
        parser.add_argument("--observer-password", nargs="?", const="", default=None)
        parser.add_argument("--observer-domain", type=_samr_name, default=None)
        parser.add_argument(
            "--samr-max-users",
            type=_bounded_samr_users,
            default=1000,
            dest="samr_max_users",
        )
        parser.add_argument("--samr-max-groups", type=_bounded_samr_inventory, default=1000)
        parser.add_argument("--samr-max-members", type=_bounded_samr_inventory, default=1000)
        parser.add_argument("--samr-user", type=_samr_name, default=None)
        parser.add_argument("--samr-domain", type=_samr_name, default=None)
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

    if (
        set(selected) <= _SAMR_TESTS
        and getattr(args, "usernames", None) == [""]
        and getattr(args, "username", None) == ""
        and getattr(args, "password", None) == ""
        and not getattr(args, "username_file", None)
        and not getattr(args, "password_file", None)
    ):
        args.username = None
        args.usernames = None
        args.password = None

    brute = tests_with_credential_mode(selected, "product_required")
    if brute:
        if not (
            any(name.strip() for name in (getattr(args, "usernames", None) or []))
            or getattr(args, "username", None)
            or getattr(args, "username_file", None)
        ):
            raise argparse.ArgumentError(
                None, f"{', '.join(sorted(brute))} requires -u/--user or -U/--users"
            )
        if (
            getattr(args, "password", None) is None
            and not getattr(args, "password_file", None)
        ):
            raise argparse.ArgumentError(
                None, f"{', '.join(sorted(brute))} requires -p/--password or -P/--passwords"
            )

    required_direct = tests_with_credential_mode(selected, "direct_required")
    direct = required_direct | tests_with_credential_mode(selected, "direct_optional")
    if direct:
        direct_names = ", ".join(sorted(direct))
        if getattr(args, "username_file", None) or getattr(args, "password_file", None):
            raise argparse.ArgumentError(
                None, f"{direct_names} does not accept credential wordlists; run it separately"
            )
        has_credentials = (
            getattr(args, "username", None) is not None
            or bool(getattr(args, "usernames", None))
            or getattr(args, "password", None) is not None
        )
        if required_direct or has_credentials:
            if not getattr(args, "username", None) or not args.username.strip():
                raise argparse.ArgumentError(
                    None, f"{direct_names} requires one direct -u/--user value"
                )
            if getattr(args, "password", None) is None:
                raise argparse.ArgumentError(
                    None, f"{direct_names} requires one direct -p/--password value"
                )
    if "BRUTEPIPE" in selected and not getattr(args, "pipe", None):
        raise argparse.ArgumentError(None, "BRUTEPIPE requires --pipe")
    guessing = _GUESS_TESTS.intersection(selected)
    expectation = getattr(args, "expect_lockout_after", None)
    observer_user = getattr(args, "observer_user", None)
    observer_password = getattr(args, "observer_password", None)
    observer_domain = getattr(args, "observer_domain", None)
    if not guessing and (
        expectation is not None or observer_user is not None
        or observer_password is not None or observer_domain is not None
    ):
        raise argparse.ArgumentError(
            None, "--expect-lockout-after and observer options require NTLMGUESS or CHGUESS"
        )
    if guessing:
        if expectation is not None and expectation > getattr(args, "guess_attempts", 5):
            raise argparse.ArgumentError(
                None, "--expect-lockout-after cannot exceed --guess-attempts"
            )
        if (observer_user is None) != (observer_password is None):
            raise argparse.ArgumentError(
                None, "--observer-user and --observer-password must be provided together"
            )
        if observer_domain is not None and observer_user is None:
            raise argparse.ArgumentError(None, "--observer-domain requires --observer-user")
        if "CHGUESS" in guessing and observer_user is not None:
            raise argparse.ArgumentError(
                None, "Observer options are only supported by NTLMGUESS; the CHGUESS proxy host is not a verified RPC backend"
            )
        if observer_user is not None:
            tested_identity = _credential_identity(args.username, getattr(args, "domain", ""))
            observer_identity = _credential_identity(
                observer_user,
                observer_domain if observer_domain is not None else getattr(args, "domain", ""),
            )
            if observer_identity[1] == tested_identity[1]:
                raise argparse.ArgumentError(
                    None, "--observer-user must be a different account from the tested user"
                )
    if (getattr(args, "samr_user", None) or getattr(args, "samr_domain", None)) and "SAMRUSERINFO" not in selected:
        raise argparse.ArgumentError(None, "--samr-user and --samr-domain require SAMRUSERINFO")
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
    if "NTLMGUESS" in selected:
        if getattr(target, "port", 0) not in (0, 135) and not getattr(args, "uuid", None):
            raise argparse.ArgumentError(
                None, "NTLMGUESS requires --uuid when an endpoint other than TCP 135 is selected"
            )
        other_rpc_tests = [
            code for code in selected
            if code != "NTLMGUESS" and MSRPC_TESTS[code]["family"] == "rpc"
        ]
        if other_rpc_tests and (
            getattr(target, "port", 0) not in (0, 135)
            or (getattr(args, "uuid", None) or _EPM_INTERFACE).lower() != _EPM_INTERFACE
        ):
            raise argparse.ArgumentError(
                None, "Run a custom NTLMGUESS endpoint separately from other RPC tests"
            )
    rpc_probe_tests = set(selected).intersection({"BRUTETCP", "NTLMGUESS"})
    if rpc_probe_tests:
        from impacket import uuid
        from .rpc_auth import SUPPORTED_RPC_PROBES
        normalized = normalize_interface_uuid(getattr(args, "uuid", None) or _EPM_INTERFACE)
        interface_uuid, version = normalized.rsplit(":", 1)
        if uuid.uuidtup_to_bin((interface_uuid, version)) not in SUPPORTED_RPC_PROBES:
            supported = ", ".join(
                f"{interface}:{ver}"
                for interface, ver in (uuid.bin_to_uuidtup(value) for value in SUPPORTED_RPC_PROBES)
            )
            raise argparse.ArgumentError(
                None, f"{', '.join(sorted(rpc_probe_tests))} has no read-only confirmation call for {normalized}. Supported: {supported}",
            )
    http_probe_tests = set(selected).intersection({"BRUTEHTTP", "CHGUESS"})
    if http_probe_tests and getattr(target, "port", 0) not in (0, 80, 443):
        raise argparse.ArgumentError(
            None, f"{', '.join(sorted(http_probe_tests))} RPC Proxy transport supports only HTTP port 80 or HTTPS port 443"
        )
    if (
        "ENUMPIPES" in selected
        and (
            getattr(args, "username_file", None)
            or getattr(args, "password_file", None)
        )
    ):
        raise argparse.ArgumentError(
            None,
            "ENUMPIPES accepts only single -u/--user and -p/--password values; "
            "wordlists are for explicit brute tests",
        )
    if "ENUMPIPES" in selected and len(getattr(args, "usernames", None) or []) > 1:
        raise argparse.ArgumentError(None, "ENUMPIPES accepts only one -u/--user value")
    return selected


__all__ = [
    "MSRPCArgs",
    "MSRPC_DEFAULT_SUITE",
    "MSRPC_EXPLICIT_ONLY_TESTS",
    "MSRPC_TEST_ORDER",
    "normalize_interface_uuid",
    "validate_msrpc_selection",
]
