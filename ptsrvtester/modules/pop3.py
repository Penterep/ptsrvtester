import argparse, ipaddress, poplib, random, re, socket, ssl, string, threading
from base64 import b64encode, b64decode
from dataclasses import dataclass
from enum import Enum
from typing import NamedTuple

from ptlibs.ptjsonlib import PtJsonLib
from ..ptntlmauth.ptntlmauth import NTLMInfo, get_NegotiateMessage_data, decode_ChallengeMessage_blob

from ._base import BaseModule, BaseArgs, Out
from .utils import ptprinthelper
from .utils.ptprinthelper import get_colored_text
from .utils.helpers import (
    Target,
    Creds,
    ArgsWithBruteforce,
    check_if_brute,
    get_mode,
    text,
    valid_target,
    vendor_from_cpe,
    add_bruteforce_args,
    simple_bruteforce,
)
from .utils.service_identification import identify_service


def valid_target_pop3(target: str) -> Target:
    """Argparse helper: IP or hostname with optional port (like SMTP)."""
    return valid_target(target, domain_allowed=True)


# POP3 CAPA: known capabilities and security classification (IANA RFC 2449, 2595, 3206, 5034, 6856)
POP3_KNOWN_CAPABILITIES = frozenset(
    {
        "TOP", "UIDL", "USER", "SASL", "RESP-CODES", "LOGIN-DELAY", "PIPELINING",
        "EXPIRE", "IMPLEMENTATION", "STLS", "AUTH-RESP-CODE", "UTF8", "LANG",
    }
)
# SASL method -> OK / WARNING / ERROR when on PLAIN. Over STLS/TLS all are OK (RFC 8314).
POP3_SASL_METHOD_LEVEL_PLAIN = {
    "PLAIN": "ERROR", "LOGIN": "ERROR", "CRAM-MD5": "ERROR", "DIGEST-MD5": "ERROR",
    "NTLM": "ERROR", "ANONYMOUS": "ERROR", "KERBEROS_V4": "ERROR", "GSSAPI": "ERROR",
    "EXTERNAL": "WARNING",
    "XOAUTH2": "OK", "OAUTHBEARER": "OK", "SCRAM-SHA-1": "OK", "SCRAM-SHA-256": "OK",
}
POP3_CAPA_WARNING = frozenset({"USER", "IMPLEMENTATION"})  # USER=plaintext, IMPLEMENTATION=info disclosure


def _parse_capa_commands(
    capability: dict[str, list[str]], connection_encrypted: bool = False
) -> list[tuple[str, str]]:
    """
    Parse POP3 CAPA dict into list of (display_string, level) for output.
    Level is OK, WARNING, or ERROR. Expands SASL into separate methods.
    When connection_encrypted is True (STLS/TLS), SASL PLAIN/LOGIN etc. are OK (RFC 8314).
    If STLS is not advertised (on plain), appends [✗] STLS (is not allowed).
    """
    if not capability:
        return []
    result: list[tuple[str, str]] = []
    seen_stls = False

    for capa, vals in sorted(capability.items()):
        capa_upper = str(capa or "").upper().strip()
        vals_str = [str(v) for v in (vals or [])]

        if capa_upper == "STLS":
            seen_stls = True

        if capa_upper == "SASL":
            methods = vals_str
            for method in methods:
                method_upper = method.upper()
                level = "OK" if connection_encrypted else POP3_SASL_METHOD_LEVEL_PLAIN.get(method_upper, "OK")
                result.append((f"SASL {method_upper}", level))
            continue

        if capa_upper in POP3_CAPA_WARNING:
            level = "WARNING"
        elif capa_upper in POP3_KNOWN_CAPABILITIES:
            level = "OK"
        else:
            level = "OK"  # Unknown capability: show as OK

        display = f"{capa_upper} {' '.join(vals_str)}".strip() if vals_str else capa_upper
        result.append((display, level))

    if not seen_stls and not connection_encrypted:
        result.append(("STLS (is not allowed)", "ERROR"))

    return result


def _capa_level_bullet(level: str) -> str:
    if level == "ERROR":
        return "VULN"
    if level == "WARNING":
        return "WARNING"
    return "NOTVULN"


# region data classes


class NTLMResult(NamedTuple):
    success: bool
    ntlm: NTLMInfo | None


class InfoResult(NamedTuple):
    banner: str | None
    capability: dict[str, list[str]] | None
    capability_stls: dict[str, list[str]] | None = None  # CAPA after STLS upgrade (when PLAIN had STLS)


class HelpInfoResult(NamedTuple):
    """Result of HELP and IMPLEMENTATION info disclosure test. HELP is non-standard (RFC 1939);
    IMPLEMENTATION is a CAPA capability per RFC 2449."""
    help_response: str | None  # Response to HELP command (None = not supported)
    implementation: str | None  # IMPLEMENTATION value from CAPA (None = not in CAPA)


class EncryptionResult(NamedTuple):
    """
    Result of encryption test: which connection types are available on the port.
    Stored in POP3Results.encryption so that subsequent logic can use it.
    """
    plaintext_ok: bool
    stls_ok: bool
    tls_ok: bool


# Catch-all / brute-force protection: "configured" | "not_configured" | "indeterminate"
CatchAllResult = str


@dataclass
class POP3Results:
    info: InfoResult | None = None
    info_error: str | None = None  # When connect/info fails
    banner_requested: bool = False
    commands_requested: bool = False
    help_info: HelpInfoResult | None = None
    anonymous: bool | None = None
    ntlm: NTLMResult | None = None
    creds: set[Creds] | None = None
    encryption: EncryptionResult | None = None
    encryption_error: str | None = None
    catch_all: CatchAllResult | None = None  # Server accepts invalid creds -> indeterminate


class VULNS(Enum):
    Anonymous = "PTV-GENERAL-ANONYMOUS"
    NTLM = "PTV-GENERAL-NTLMINFORMATION"
    WeakCreds = "PTV-GENERAL-WEAKCREDENTIALS"


# endregion


# region -ts test registry (single source of truth for `-ts/--tests`)

# Internal per-test dest flags driven by -ts. The legacy short flags were removed;
# -ts is the only public interface, so these dests must be initialised explicitly
# (argparse no longer defines them). run() reads exactly these attributes.
POP3_TEST_DESTS: tuple[str, ...] = (
    "info", "banner", "commands", "help_info", "isencrypt", "anonymous", "ntlm",
)

# Ordered groups for the main help table.
POP3_TEST_GROUPS: list[tuple[str, list[str]]] = [
    ("Recon & fingerprint", ["BANNER", "CAPA", "ENCRYPT", "NTLM", "HELPINFO"]),
    ("Authentication & credentials", ["ANON", "BRUTE"]),
]

# Per-test definitions:
#   desc      one-line description for the main -ts table
#   long      list of <=3 lines describing the test (per-test help)
#   flags     dict dest->value applied to the args namespace when selected
#   requires  human-readable prerequisite strings (per-test help + validation)
#   mods      test-specific option rows [short, long, metavar, help] (per-test help)
POP3_TESTS: dict[str, dict] = {
    "BANNER": {
        "desc": "Grab banner and service identification",
        "long": ["Connect and read the greeting banner, then identify the product,",
                 "version and CPE from the advertised software string."],
        "flags": {"banner": True},
    },
    "CAPA": {
        "desc": "Grab CAPA capabilities",
        "long": ["Send CAPA and list advertised capabilities; flags weak options",
                 "(USER plaintext, IMPLEMENTATION disclosure, missing STLS)."],
        "flags": {"commands": True},
    },
    "ENCRYPT": {
        "desc": "Test encryption options (plaintext / STLS / TLS)",
        "long": ["Inspect supported transport encryption on the port: plaintext",
                 "login, explicit STLS upgrade and implicit TLS."],
        "flags": {"isencrypt": True},
    },
    "NTLM": {
        "desc": "Inspect NTLM authentication",
        "long": ["Probe NTLM (NTLMSSP) authentication and decode the server",
                 "challenge for leaked domain / host information."],
        "flags": {"ntlm": True},
    },
    "HELPINFO": {
        "desc": "Test HELP and IMPLEMENTATION info disclosure",
        "long": ["Send HELP (non-standard) and read IMPLEMENTATION from CAPA to",
                 "reveal software / version information disclosed by the server."],
        "flags": {"help_info": True},
    },
    "ANON": {
        "desc": "Check anonymous authentication",
        "long": ["Attempt anonymous / guest login and a catch-all probe to detect",
                 "servers that accept arbitrary credentials."],
        "flags": {"anonymous": True},
    },
    "BRUTE": {
        "desc": "Login bruteforce (USER/PASS)",
        "long": ["Bruteforce POP3 login with the supplied username(s) and",
                 "password(s); runs a catch-all check first."],
        "requires": ["-u/--user or -U/--users", "-p/--password or -P/--passwords"],
        "mods": [
            ["-u", "--user", "<name>", "Single username"],
            ["-U", "--users", "<wordlist>", "Username wordlist"],
            ["-p", "--password", "<password>", "Single password"],
            ["-P", "--passwords", "<wordlist>", "Password wordlist"],
        ],
    },
}


def _pop3_parse_test_codes(raw: str | None) -> list[str]:
    """Split and upper-case a raw -ts value into a list of codes."""
    if not raw:
        return []
    return [c.strip().upper() for c in str(raw).split(",") if c.strip()]


def _apply_pop3_tests(args) -> None:
    """Translate ``-ts/--tests`` codes into the internal per-test dest flags.

    ``ALL`` (or no ``-ts``) leaves every flag at its default -> run-all mode.
    Since the legacy flags were removed, every test dest is initialised here so
    ``run()`` can read them unconditionally.
    """
    for dest in POP3_TEST_DESTS:
        if not hasattr(args, dest):
            setattr(args, dest, False)

    codes = _pop3_parse_test_codes(getattr(args, "tests", None))
    if not codes or "ALL" in codes:
        # No -ts or explicit ALL: apply nothing so _is_default_mode() stays True.
        return

    unknown = [c for c in codes if c not in POP3_TESTS]
    if unknown:
        available = ", ".join(POP3_TESTS)
        raise argparse.ArgumentError(
            None,
            f"Unknown test(s): {', '.join(unknown)}. Available: ALL, {available}",
        )

    for code in codes:
        for dest, val in POP3_TESTS[code].get("flags", {}).items():
            setattr(args, dest, val)

    # Every explicitly selected test must actually activate; otherwise report what
    # is missing instead of silently falling back to run-all mode.
    inactive: list[tuple[str, list[str]]] = []
    for code in codes:
        spec = POP3_TESTS[code]
        if code == "BRUTE":
            active = check_if_brute(args)
        elif "flags" in spec:
            active = all(getattr(args, dest, None) for dest in spec["flags"])
        else:
            active = True
        if not active:
            inactive.append((code, list(spec.get("requires", []))))
    if inactive:
        parts = [
            f"{code} requires {'; '.join(req)}" if req else f"{code} could not be activated"
            for code, req in inactive
        ]
        raise argparse.ArgumentError(None, "; ".join(parts))


def _pop3_test_help(codes: list[str]):
    """Build a help object (for ptprinthelper.help_print) describing given test codes."""
    if not codes:
        return None
    valid = [c for c in codes if c in POP3_TESTS]
    if not valid:
        available = ", ".join(POP3_TESTS)
        return [
            {"unknown_test": [f"Unknown test: {', '.join(codes)}"]},
            {"available_tests": [f"ALL, {available}"]},
        ]
    out: list[dict] = []
    for code in valid:
        spec = POP3_TESTS[code]
        header = f"{code} — {spec.get('desc', '')}"
        out.append({"test": [header, *spec.get("long", [])]})
        req = list(spec.get("requires", []))
        if req:
            out.append({"requires": req})
        rows: list[list[str]] = list(spec.get("mods", []))
        if rows:
            out.append({"test_options": rows})
        has_opts = bool(rows or req)
        usage = f"ptsrvtester pop3 -ts {code} " + ("<options> <target>" if has_opts else "<target>")
        out.append({"usage": [usage]})
    return out


# endregion

# region arguments


class POP3Args(ArgsWithBruteforce):
    target: Target
    tls: bool
    starttls: bool
    tests: str | None
    info: bool
    ntlm: bool
    anonymous: bool
    isencrypt: bool
    help_info: bool

    @staticmethod
    def get_help():
        # Test selection table (-ts): one code + one-line description per test.
        options: list[list[str]] = [
            ["-ts", "--tests", "<test>", "One or more tests, comma-separated (e.g. BANNER,CAPA); ALL runs everything:"],
        ]
        for group_title, codes in POP3_TEST_GROUPS:
            options.append(["", "", "", ""])
            options.append(["", "", get_colored_text(group_title, "TITLE")])
            for code in codes:
                options.append(["", "", code, POP3_TESTS[code]["desc"]])

        # Global options (test-specific modifiers live in `pop3 -ts <TEST> -h`).
        options += [
            ["", "", "", ""],
            [get_colored_text("Connection", "TITLE")],
            ["", "--tls", "", "Use implicit SSL/TLS (default port 995)"],
            ["", "--starttls", "", "Use explicit STLS (default port 110)"],
            ["", "", "", ""],
            [get_colored_text("Credentials (BRUTE)", "TITLE")],
            ["-u", "--user", "<name>", "Single username"],
            ["-U", "--users", "<wordlist>", "Username wordlist"],
            ["-p", "--password", "<password>", "Single password"],
            ["-P", "--passwords", "<wordlist>", "Password wordlist"],
            ["", "--spray", "", "Try one password against all users"],
            ["", "--brute-threads", "<n>", "Threads for bruteforce (default: 10)"],
            ["", "", "", ""],
            [get_colored_text("Output", "TITLE")],
            ["-j", "--json", "", "Output in JSON format"],
            ["-vv", "--verbose", "", "Enable verbose mode"],
            ["-h", "--help", "", "Show this help; 'pop3 -ts <TEST> -h' for test options"],
        ]

        return [
            {"description": ["POP3 Testing Module"]},
            {"usage": ["ptsrvtester pop3 -ts <test>[,<test>...] <options> <target>"]},
            {"usage_example": [
                "ptsrvtester pop3 -ts BANNER,CAPA 127.0.0.1",
                "ptsrvtester pop3 -ts ALL 127.0.0.1",
                "ptsrvtester pop3 -ts ENCRYPT 127.0.0.1",
                "ptsrvtester pop3 -ts ALL --tls 127.0.0.1:995",
                "ptsrvtester pop3 -ts ANON,HELPINFO 127.0.0.1",
                "ptsrvtester pop3 -ts BRUTE -u admin -P passwords.txt 127.0.0.1:110",
                "ptsrvtester pop3 -ts BRUTE -h",
            ]},
            {"options": options},
        ]

    @staticmethod
    def get_test_help(codes):
        """Per-test help object (used by `pop3 -ts <TEST> -h`)."""
        return _pop3_test_help(codes)

    def add_subparser(self, name: str, subparsers) -> None:
        """Adds a subparser of POP3 arguments"""
        examples = """example usage:
  ptsrvtester pop3 -h
  ptsrvtester pop3 -ts BANNER,CAPA 127.0.0.1
  ptsrvtester pop3 -ts ALL 127.0.0.1
  ptsrvtester pop3 -ts ENCRYPT 127.0.0.1
  ptsrvtester pop3 -ts ALL --tls 127.0.0.1:995
  ptsrvtester -j pop3 -ts BRUTE -u admin -P passwords.txt --brute-threads 20 127.0.0.1:110
  ptsrvtester pop3 -ts BRUTE -h"""

        parser = subparsers.add_parser(
            name,
            add_help=True,
            epilog=examples,
            formatter_class=argparse.RawTextHelpFormatter,
        )

        if not isinstance(parser, argparse.ArgumentParser):
            raise TypeError  # IDE typing

        parser.add_argument(
            "target",
            type=valid_target_pop3,
            help="IP[:PORT] or HOST[:PORT] (e.g. 127.0.0.1 or mail.example.com:110)",
        )

        parser.add_argument("--tls", action="store_true", help="use implicit SSL/TLS")
        parser.add_argument("--starttls", action="store_true", help="use explicit SSL/TLS")

        parser.add_argument(
            "-ts",
            "--tests",
            type=str,
            default=None,
            metavar="<test>",
            dest="tests",
            help="Comma-separated test codes (e.g. BANNER,CAPA) or ALL; 'pop3 -ts <TEST> -h' for test options",
        )

        add_bruteforce_args(parser)


# endregion


# region main module code


class POP3(BaseModule):
    @staticmethod
    def module_args():
        return POP3Args()

    def __init__(self, args: BaseArgs, ptjsonlib: PtJsonLib):

        if not isinstance(args, POP3Args):
            raise argparse.ArgumentError(
                None, f'module "{args.module}" received wrong arguments namespace'
            )

        # Translate -ts/--tests codes into the internal per-test dest flags before validation.
        _apply_pop3_tests(args)

        # Default port: 995 for implicit TLS (--tls), 110 for plain/STARTTLS (RFC 2595)
        if args.target.port == 0:
            if args.tls:
                args.target.port = 995
            else:
                args.target.port = 110

        self.do_brute = check_if_brute(args)
        self.use_json = getattr(args, "json", False)

        self.args = args
        self.ptjsonlib = ptjsonlib
        self.results: POP3Results
        self.pop3: poplib.POP3
        self._output_lock = threading.Lock()

    def _is_default_mode(self) -> bool:
        """True when only target is given (no test switches). Run basic info + anonymous + encryption."""
        return not (
            self.args.info
            or self.args.banner
            or self.args.commands
            or self.args.help_info
            or self.args.isencrypt
            or self.args.ntlm
            or self.args.anonymous
            or self.do_brute
        )

    def _test_catch_all(self) -> CatchAllResult:
        """
        Test if server accepts invalid credentials (+OK on nonsense user/pass).
        Returns 'indeterminate' if server accepts, 'not_configured' otherwise.
        """
        try:
            fake_user = "".join(random.choices(string.ascii_letters + string.digits, k=24))
            fake_pass = "".join(random.choices(string.ascii_letters + string.digits, k=24))
            pop3 = self.connect()
            try:
                pop3.user(fake_user)
                pop3.pass_(fake_pass)
                return "indeterminate"
            except Exception:
                return "not_configured"
            finally:
                pop3.close()
        except Exception:
            return "not_configured"

    def _silent_info(self) -> InfoResult | None:
        """Silent load of banner and CAPA (no output). Used before brute-only when -i not set."""
        try:
            pop3 = self.connect()
            try:
                return self._do_info(pop3, get_commands=True)
            finally:
                pop3.close()
        except Exception:
            return None

    def _do_info(self, pop3: poplib.POP3 | poplib.POP3_SSL, get_commands: bool = True) -> InfoResult:
        """Core info logic: banner + optional CAPA (and CAPA after STLS if applicable)."""
        banner = pop3.welcome
        capability = None
        capability_stls = None
        if get_commands:
            try:
                capability = pop3.capa()
            except poplib.error_proto:
                capability = None
            if (
                capability
                and "STLS" in capability
                and self.args.target.port != 995
                and not self.args.tls
                and not isinstance(pop3, poplib.POP3_SSL)
            ):
                try:
                    pop3.stls()
                    capability_stls = pop3.capa()
                except Exception:
                    pass
        return InfoResult(text(banner), capability, capability_stls)

    def _do_help_info(self, pop3: poplib.POP3 | poplib.POP3_SSL) -> HelpInfoResult:
        """
        Test HELP command and extract IMPLEMENTATION from CAPA.
        HELP is non-standard (RFC 1939); IMPLEMENTATION is a CAPA tag per RFC 2449.
        """
        help_response: str | None = None
        try:
            resp, lines, _ = pop3._longcmd("HELP")
            # Empty list (+OK followed by . only) = no actual disclosure → treat as [✓]
            if not lines:
                help_response = None
            else:
                parts = [text(resp)]
                parts.extend(text(ln) for ln in lines)
                help_response = "\n".join(p for p in parts if p.strip())
                if not help_response.strip():
                    help_response = None
        except poplib.error_proto:
            help_response = None

        impl_val: str | None = None
        try:
            capa = pop3.capa()
        except Exception:
            capa = None
        if capa:
            # poplib returns keys as sent by server; servers typically use uppercase (RFC 2449: case-insensitive)
            impl_list = capa.get("IMPLEMENTATION")
            if impl_list:
                impl_val = " ".join(str(v).strip() for v in impl_list).strip()

        return HelpInfoResult(help_response=help_response, implementation=impl_val)

    def run(self) -> None:
        """Executes POP3 methods based on module configuration. All results streamed immediately."""
        self.results = POP3Results()

        # Only -ie: no need to connect; test_encryption() opens its own connections.
        if (
            self.args.isencrypt
            and not self.args.info
            and not self.args.banner
            and not self.args.commands
            and not self.args.help_info
            and not self.args.ntlm
            and not self.args.anonymous
            and not self.do_brute
        ):
            try:
                self.results.encryption = self.test_encryption()
            except Exception as e:
                self.results.encryption_error = str(e)
            self.ptprint("Encryption", Out.INFO)
            self._stream_encryption_result()
            return

        if self._is_default_mode():
            self.results.banner_requested = True
            self.results.commands_requested = True
        try:
            self.pop3 = self.connect()
        except (SystemExit, KeyboardInterrupt):
            raise
        except Exception as e:
            self.results.info_error = str(e)
            return

        if self._is_default_mode():
            # Only target given: run basic tests, stream immediately after each
            self.results.info = self.info(get_commands=True)
            self.ptprint("Banner", Out.INFO)
            self._stream_banner_result()
            self._stream_capa_result()
            if self.args.target.port == 995:
                self.results.encryption = EncryptionResult(
                    plaintext_ok=False, stls_ok=False, tls_ok=True
                )
            elif self.results.info and self.results.info.capability and "STLS" in self.results.info.capability:
                self.results.encryption = EncryptionResult(
                    plaintext_ok=True, stls_ok=True, tls_ok=False
                )
            else:
                self.results.encryption = EncryptionResult(
                    plaintext_ok=True, stls_ok=False, tls_ok=False
                )
            self.ptprint("Encryption", Out.INFO)
            self._stream_encryption_result()
            self.results.anonymous = self.auth_anonymous()
            self.ptprint("Anonymous authentication", Out.INFO)
            self._stream_anonymous_result()
            self.results.help_info = self._do_help_info(self.pop3)
            self.ptprint("Help/Implementation info", Out.INFO)
            self._stream_help_info_result()
            return

        if self.args.info or self.args.banner or self.args.commands:
            do_banner = self.args.banner or self.args.info
            do_commands = self.args.commands or self.args.info
            self.results.banner_requested = do_banner
            self.results.commands_requested = do_commands
            info = self.info(get_commands=do_commands)
            self.results.info = InfoResult(
                info.banner if do_banner else None,
                info.capability if do_commands else None,
                getattr(info, "capability_stls", None) if do_commands else None,
            )
            if do_banner:
                self.ptprint("Banner", Out.INFO)
            self._stream_banner_result()
            self._stream_capa_result()

        if self.args.help_info:
            self.results.help_info = self._do_help_info(self.pop3)
            self.ptprint("Help/Implementation info", Out.INFO)
            self._stream_help_info_result()

        if self.args.isencrypt:
            try:
                self.results.encryption = self.test_encryption()
            except Exception as e:
                self.results.encryption_error = str(e)
            self.ptprint("Encryption", Out.INFO)
            self._stream_encryption_result()

        if self.args.ntlm:
            self.ptprint("NTLM information", Out.INFO)
            self.results.ntlm = self.auth_ntlm()
            self._stream_ntlm_result()

        if self.args.anonymous:
            self.ptprint("Anonymous authentication", Out.INFO)
            self.results.anonymous = self.auth_anonymous()
            self._stream_anonymous_result()

        if self.do_brute:
            # Brute-only: silent load banner+CAPA, stream immediately
            if not (
                self.args.info or self.args.banner or self.args.commands
                or self.args.isencrypt or self.args.ntlm or self.args.anonymous
            ):
                silent = self._silent_info()
                if silent:
                    self.results.info = silent
                    self.results.banner_requested = True
                    self.results.commands_requested = True
                    self.ptprint("Banner", Out.INFO)
                    self._stream_banner_result()
                    self._stream_capa_result()

            self.results.catch_all = self._test_catch_all()
            self.ptprint("Catch-all test", Out.INFO)
            self._stream_catch_all_result()

            self.ptprint("Login bruteforce", Out.INFO)
            self.results.creds = simple_bruteforce(
                self._try_login,
                self.args.user,
                self.args.users,
                self.args.password,
                self.args.passwords,
                self.args.spray,
                self.args.threads,
                on_success=self._on_brute_success if not self.use_json else None,
            )
            self._stream_brute_result()

    def connect(self) -> poplib.POP3 | poplib.POP3_SSL:
        """
        Establishes a new POP3 connection with the appropriate
        encryption mode according to module arguments.
        Port 995 is implicit TLS only, so we use POP3_SSL even without --tls.
        Timeout 10s prevents HELP from hanging on poorly configured servers/firewalls.
        """
        timeout = 10.0
        try:
            if self.args.tls or self.args.target.port == 995:
                ctx = ssl._create_unverified_context()
                pop3 = poplib.POP3_SSL(
                    self.args.target.ip,
                    self.args.target.port,
                    context=ctx,
                    timeout=timeout,
                )
            else:
                pop3 = poplib.POP3(self.args.target.ip, self.args.target.port, timeout=timeout)
                if self.args.starttls:
                    pop3.stls()
        except Exception as e:
            mode = "TLS" if (self.args.tls or self.args.target.port == 995) else get_mode(self.args)
            msg = (
                f"Could not connect to the target server "
                + f"{self.args.target.ip}:{self.args.target.port} ({mode}): {e}"
            )
            raise OSError(msg) from e
        return pop3

    def test_encryption(self) -> EncryptionResult:
        """
        Test which encryption options are available on the target port:
        plaintext, STLS (STARTTLS), and implicit TLS (POP3_SSL).
        Uses fresh connections for each test; does not use self.args.tls/starttls.
        Same methodology as SMTP: unverified context and, when connecting by IP,
        server_hostname=None for TLS so SNI does not break hostname-only certs.

        The caller stores the return value in self.results.encryption so that
        subsequent logic can use it to select the appropriate connection type.
        """
        host = self.args.target.ip
        port = self.args.target.port
        timeout = 10.0
        plaintext_ok = False
        stls_ok = False
        tls_ok = False

        _ssl_ctx = ssl._create_unverified_context()
        # Port 995 is implicit TLS only: skip plaintext and STLS (they would hang/timeout).
        tls_only_port = port == 995

        if not tls_only_port:
            # 1. Plaintext (no TLS)
            try:
                pop3 = poplib.POP3(host, port, timeout=timeout)
                try:
                    _ = pop3.welcome
                    plaintext_ok = True
                finally:
                    pop3.close()
            except Exception as e:
                self.ptdebug(f"Plaintext test failed: {e}", Out.INFO)

            # 2. STLS (plain then upgrade). RFC 2595: CAPA, then STLS, then CAPA again.
            try:
                pop3 = poplib.POP3(host, port, timeout=timeout)
                try:
                    _ = pop3.welcome
                    caps = pop3.capa()
                    if "STLS" in caps:
                        resp = pop3._shortcmd("STLS")
                        if resp.startswith(b"+OK"):
                            try:
                                ipaddress.ip_address(host)
                                _sni = None
                            except ValueError:
                                _sni = host
                            sock_ssl = _ssl_ctx.wrap_socket(
                                pop3.sock, server_hostname=_sni
                            )
                            pop3.sock = sock_ssl
                            pop3.file = sock_ssl.makefile("rb")
                            pop3._tls_established = True
                            pop3.capa()
                            stls_ok = True
                finally:
                    pop3.close()
            except Exception as e:
                self.ptdebug(f"STLS test failed: {e}", Out.INFO)

        # 3. Implicit TLS (port 995). Manual connect with SNI control.
        _connect_timeout = 15.0 if tls_only_port else timeout
        def _try_implicit_tls(sni):
            sock = socket.create_connection((host, port), timeout=_connect_timeout)
            try:
                sock_ssl = _ssl_ctx.wrap_socket(sock, server_hostname=sni)
                sock_ssl.settimeout(_connect_timeout)  # SSL socket may not inherit timeout
                try:
                    f = sock_ssl.makefile("rb")
                    line = f.readline()
                    f.close()
                    return line and line.strip().startswith(b"+OK")
                finally:
                    sock_ssl.close()
            finally:
                pass

        try:
            try:
                ipaddress.ip_address(host)
                _sni_first, _sni_fallback = None, host
            except ValueError:
                _sni_first, _sni_fallback = host, None
            for _sni in (_sni_first, _sni_fallback):
                if _sni is None and _sni_fallback is None:
                    continue
                try:
                    if _try_implicit_tls(_sni):
                        tls_ok = True
                        break
                except Exception as e:
                    self.ptdebug(f"Implicit TLS test failed (SNI={_sni!r}): {e}", Out.INFO)
        except Exception as e:
            self.ptdebug(f"Implicit TLS test failed: {e}", Out.INFO)

        return EncryptionResult(plaintext_ok, stls_ok, tls_ok)

    def info(self, get_commands: bool = True) -> InfoResult:
        """Performs bannergrabbing; optionally CAPA (capabilities).
        If on plain connection and CAPA advertises STLS, upgrades and gets second CAPA (STLS).

        Returns:
            InfoResult: (banner, capability or None, capability_stls or None)
        """
        return self._do_info(self.pop3, get_commands)

    def auth_anonymous(self) -> bool:
        """Attempts anonymous authentication

        Returns:
            bool: result
        """
        try:
            res: bytes = self.pop3._shortcmd("AUTH ANONYMOUS")

            # Only "+" awaiting further data?
            if len(res.strip()) == 1:
                res = self.pop3._shortcmd(b64encode(b"HELLO").decode())

            return True
        except:
            return False

    def auth_ntlm(self) -> NTLMResult:
        """
        Performs NTLM authentication to extract internal server
        information from server's challenge response.

        Returns:
            NTLMResult: operation status and disclosed information
        """

        try:
            # Separate connection not to corrupt the main socket
            pop3 = self.connect()

            res: bytes = pop3._shortcmd("AUTH NTLM")
            if res.strip().startswith(b"+"):
                b64_ntlm_negotiation = b64encode(get_NegotiateMessage_data()).decode()
                res = pop3._shortcmd(b64_ntlm_negotiation).strip()

                # res = b'+ base64containing+signs'
                b64_ntlm_challenge = b"+".join(res.split(b"+")[1:])

                ntlminfo = decode_ChallengeMessage_blob(b64decode(b64_ntlm_challenge))
                return NTLMResult(True, ntlminfo)
            else:
                return NTLMResult(False, None)
        except:
            return NTLMResult(False, None)

    def _try_login(self, creds: Creds) -> Creds | None:
        """Login attempt function for bruteforce

        Args:
            creds (Creds): Creds to use for login

        Returns:
            Creds | None: Creds if success, None if failed
        """
        try:
            pop3 = self.connect()
        except OSError:
            return None
        try:
            pop3.user(creds.user)
            pop3.pass_(creds.passw)
            result = creds
        except:
            result = None
        finally:
            pop3.close()
            return result

    def _on_brute_success(self, cred: Creds) -> None:
        """Callback for real-time streaming of found credentials (thread-safe)."""
        with self._output_lock:
            ptprinthelper.ptprint(
                f"user: {cred.user}, password: {cred.passw}",
                bullet_type="TEXT",
                condition=not self.use_json,
                indent=4,
            )

    def _stream_banner_result(self) -> None:
        """Stream banner + Service Identification immediately (thread-safe)."""
        pp = ptprinthelper.ptprint
        show = not self.use_json
        if not (info := self.results.info) or info.banner is None:
            return
        with self._output_lock:
            sid = identify_service(info.banner)
            if sid is None:
                banner_bullet = "NOTVULN"
            elif sid.version is not None:
                banner_bullet = "VULN"
            else:
                banner_bullet = "WARNING"
            pp(info.banner, bullet_type=banner_bullet, condition=show, indent=4)
            if sid is not None:
                self.ptprint("Service Identification", Out.INFO)
                pp(f"Product:  {sid.product}", bullet_type="TEXT", condition=show, indent=4)
                pp(
                    f"Version:  {sid.version if sid.version else 'unknown'}",
                    bullet_type="TEXT",
                    condition=show,
                    indent=4,
                )
                pp(f"CPE:      {sid.cpe}", bullet_type="TEXT", condition=show, indent=4)

    def _emit_capa_section(
        self, title: str, capa: dict[str, list[str]], connection_encrypted: bool
    ) -> None:
        pp = ptprinthelper.ptprint
        show = not self.use_json
        self.ptprint(title, Out.INFO)
        for display_str, level in _parse_capa_commands(capa, connection_encrypted):
            pp(display_str, bullet_type=_capa_level_bullet(level), condition=show, indent=4)

    def _stream_capa_result(self) -> None:
        """Stream CAPA capabilities immediately (thread-safe)."""
        if not (info := self.results.info) or not (info.capability or getattr(info, "capability_stls", None)):
            return
        capa_stls = getattr(info, "capability_stls", None)
        encrypted = self.args.target.port == 995 or self.args.tls
        with self._output_lock:
            if info.capability is not None and capa_stls is not None:
                self._emit_capa_section("CAPA command (PLAIN)", info.capability, False)
                self._emit_capa_section("CAPA command (STLS)", capa_stls, True)
            elif info.capability is not None:
                title = "CAPA command (TLS)" if encrypted else "CAPA command (PLAIN)"
                self._emit_capa_section(title, info.capability, encrypted)

    def _stream_help_info_result(self) -> None:
        """Stream HELP and IMPLEMENTATION info disclosure result (thread-safe)."""
        pp = ptprinthelper.ptprint
        show = not self.use_json
        hi = self.results.help_info
        if hi is None:
            return
        with self._output_lock:
            if hi.help_response is not None:
                pp("HELP:", bullet_type="WARNING", condition=show, indent=4)
                for line in hi.help_response.splitlines():
                    pp(line, bullet_type="TEXT", condition=show, indent=8)
            else:
                pp("HELP: not supported", bullet_type="NOTVULN", condition=show, indent=4)
            if hi.implementation is not None:
                pp(f"IMPLEMENTATION: {hi.implementation}", bullet_type="WARNING", condition=show, indent=4)
            else:
                pp("IMPLEMENTATION: not advertised in CAPA", bullet_type="NOTVULN", condition=show, indent=4)

    def _stream_encryption_result(self) -> None:
        """Stream encryption test result to terminal (thread-safe)."""
        pp = ptprinthelper.ptprint
        show = not self.use_json
        with self._output_lock:
            if (encryption_error := self.results.encryption_error) is not None:
                pp(f"Encryption test failed: {encryption_error}", bullet_type="VULN", condition=show, indent=4)
                return
            enc = self.results.encryption
            if enc is None:
                return
            plaintext_only = enc.plaintext_ok and not enc.stls_ok and not enc.tls_ok
            any_ok = enc.plaintext_ok or enc.stls_ok or enc.tls_ok
            if plaintext_only:
                pp("Plaintext only", bullet_type="VULN", condition=show, indent=4)
            elif any_ok:
                if enc.plaintext_ok:
                    bullet = "WARNING" if (enc.stls_ok or enc.tls_ok) else "NOTVULN"
                    pp("Plaintext", bullet_type=bullet, condition=show, indent=4)
                if enc.stls_ok:
                    pp("STLS", bullet_type="NOTVULN", condition=show, indent=4)
                if enc.tls_ok:
                    pp("TLS", bullet_type="NOTVULN", condition=show, indent=4)
            else:
                pp(
                    "No connection mode available (plaintext, STLS, TLS failed)",
                    bullet_type="VULN",
                    condition=show,
                    indent=4,
                )

    def _stream_catch_all_result(self) -> None:
        """Stream catch-all test result immediately (thread-safe)."""
        pp = ptprinthelper.ptprint
        show = not self.use_json
        catch_all = getattr(self.results, "catch_all", None)
        if catch_all is None:
            return
        with self._output_lock:
            if catch_all == "indeterminate":
                pp(
                    "Server accepted invalid credentials (indeterminate). Results may be false positives.",
                    bullet_type="WARNING",
                    condition=show,
                    indent=4,
                )
            else:
                pp("Not configured (server rejects invalid creds)", bullet_type="NOTVULN", condition=show, indent=4)

    def _stream_anonymous_result(self) -> None:
        """Stream anonymous auth result immediately (thread-safe)."""
        pp = ptprinthelper.ptprint
        show = not self.use_json
        if (anonymous := self.results.anonymous) is None:
            return
        with self._output_lock:
            if anonymous:
                pp("Enabled", bullet_type="VULN", condition=show, indent=4)
            else:
                pp("Disabled", bullet_type="NOTVULN", condition=show, indent=4)

    def _stream_ntlm_result(self) -> None:
        """Stream NTLM info result immediately (thread-safe)."""
        pp = ptprinthelper.ptprint
        show = not self.use_json
        if (ntlm := self.results.ntlm) is None:
            return
        with self._output_lock:
            if not ntlm.success:
                pp("Not available", bullet_type="NOTVULN", condition=show, indent=4)
            elif ntlm.ntlm is not None:
                pp("NTLM information", bullet_type="VULN", condition=show, indent=4)
                for line in (
                    f"Target name: {ntlm.ntlm.target_name}",
                    f"NetBios domain name: {ntlm.ntlm.netbios_domain}",
                    f"NetBios computer name: {ntlm.ntlm.netbios_computer}",
                    f"DNS domain name: {ntlm.ntlm.dns_domain}",
                    f"DNS computer name: {ntlm.ntlm.dns_computer}",
                    f"DNS tree: {ntlm.ntlm.dns_tree}",
                    f"OS version: {ntlm.ntlm.os_version}",
                ):
                    for part in (line or "").replace("\r", "").splitlines():
                        pp(part, bullet_type="TEXT", condition=show, indent=8)

    def _stream_brute_result(self) -> None:
        """Stream brute-force summary (credentials already streamed via on_success) (thread-safe)."""
        creds = self.results.creds
        if creds is None or len(creds) == 0:
            return
        with self._output_lock:
            ptprinthelper.ptprint(
                f"Found {len(creds)} valid credentials",
                bullet_type="INFO",
                condition=not self.use_json,
                indent=4,
            )

    # region output

    def output(self) -> None:
        """Build JSON node(s) and print result. Terminal output is streamed from run()."""
        if (info_error := getattr(self.results, "info_error", None)) is not None:
            if self.use_json:
                self.ptjsonlib.end_error(info_error, self.use_json)
            ptprinthelper.ptprint(info_error, bullet_type="VULN", condition=not self.use_json, indent=4)
            return

        properties = {
            "software_type": None,
            "name": "pop3",
            "version": None,
            "vendor": None,
            "description": None,
        }
        deferred_vulns = []

        if (info := self.results.info) and info.banner is not None:
            sid = identify_service(info.banner)
            vendor = vendor_from_cpe(sid.cpe) if sid else None
            version = sid.version if sid else None
            properties.update(
                {
                    "description": f"Banner: {info.banner}",
                    "version": version,
                    "vendor": vendor,
                }
            )
            if sid is not None:
                if sid.version is not None:
                    deferred_vulns.append({"vuln_code": "PTV-SVC-BANNER"})
                properties.update({"cpe": sid.cpe})

        if (info := self.results.info) and (info.capability or getattr(info, "capability_stls", None)):
            capa_stls = getattr(info, "capability_stls", None)
            encrypted = self.args.target.port == 995 or self.args.tls

            def _capa_to_lines(capa: dict[str, list[str]], connection_encrypted: bool) -> list[str]:
                return [d for d, _ in _parse_capa_commands(capa, connection_encrypted)]

            json_lines: list[str] = []
            if info.capability is not None and capa_stls is not None:
                json_lines = _capa_to_lines(info.capability, False) + ["---"] + _capa_to_lines(capa_stls, True)
            elif info.capability is not None:
                json_lines = _capa_to_lines(info.capability, encrypted)
            if json_lines:
                properties.update({"capability": "\n".join(json_lines)})

        if (hi := self.results.help_info) is not None:
            if hi.help_response is not None:
                properties.update({"helpCommand": hi.help_response})
            if hi.implementation is not None:
                properties.update({"implementation": hi.implementation})

        if (encryption_error := self.results.encryption_error) is not None:
            properties.update({"encryptionError": encryption_error})
        elif (enc := self.results.encryption) is not None:
            properties.update(
                {
                    "encryption": {
                        "plaintext": enc.plaintext_ok,
                        "stls": enc.stls_ok,
                        "tls": enc.tls_ok,
                    }
                }
            )

        if (anonymous := self.results.anonymous) is not None and anonymous:
            deferred_vulns.append(
                {"vuln_code": VULNS.Anonymous.value, "vuln_request": "anonymous authentication"}
            )

        if ntlm := self.results.ntlm:
            if not ntlm.success:
                properties.update({"ntlmInfoStatus": "failed"})
            elif ntlm.ntlm is not None:
                properties.update({"ntlmInfoStatus": "ok"})
                out_lines = [
                    f"Target name: {ntlm.ntlm.target_name}",
                    f"NetBios domain name: {ntlm.ntlm.netbios_domain}",
                    f"NetBios computer name: {ntlm.ntlm.netbios_computer}",
                    f"DNS domain name: {ntlm.ntlm.dns_domain}",
                    f"DNS computer name: {ntlm.ntlm.dns_computer}",
                    f"DNS tree: {ntlm.ntlm.dns_tree}",
                    f"OS version: {ntlm.ntlm.os_version}",
                ]
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.NTLM.value,
                        "vuln_request": "ntlm authentication",
                        "vuln_response": "\n".join(out_lines),
                    }
                )

        if (catch_all := getattr(self.results, "catch_all", None)) == "indeterminate":
            properties.update({"catchAll": "indeterminate"})

        if (creds := self.results.creds) is not None and len(creds) > 0:
            json_lines = [f"user: {cred.user}, password: {cred.passw}" for cred in creds]
            if self.args.user is not None:
                user_str = f"username: {self.args.user}"
            else:
                user_str = f"usernames: {self.args.users}"
            if self.args.password is not None:
                passw_str = f"password: {self.args.password}"
            else:
                passw_str = f"passwords: {self.args.passwords}"
            deferred_vulns.append(
                {
                    "vuln_code": VULNS.WeakCreds.value,
                    "vuln_request": f"{user_str}\n{passw_str}",
                    "vuln_response": "\n".join(json_lines),
                }
            )

        pop3_node = self.ptjsonlib.create_node_object("software", None, None, properties)
        self.ptjsonlib.add_node(pop3_node)
        node_key = pop3_node["key"]
        for v in deferred_vulns:
            self.ptjsonlib.add_vulnerability(node_key=node_key, **v)

        self.ptjsonlib.set_status("finished", "")
        self.ptprint(self.ptjsonlib.get_result_json(), json=True)


# endregion
