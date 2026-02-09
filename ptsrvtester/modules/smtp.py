import argparse, ipaddress, queue, random, re, smtplib, socket, ssl, threading, time, unicodedata, dns.resolver
from base64 import b64decode, b64encode
from dataclasses import dataclass
from enum import Enum
from typing import NamedTuple

from ptlibs.ptjsonlib import PtJsonLib
from ..ptntlmauth.ptntlmauth import NTLMInfo, get_NegotiateMessage_data, decode_ChallengeMessage_blob

from ._base import BaseModule, BaseArgs, Out
from ptlibs.ptprinthelper import get_colored_text
from .utils.helpers import (
    Target,
    Creds,
    ArgsWithBruteforce,
    check_if_brute,
    get_mode,
    valid_target,
    add_bruteforce_args,
    simple_bruteforce,
    text_or_file,
)
from .utils.blacklist_parser import BlacklistParser
from .utils.service_identification import identify_service


def _registrable_domain_psl(host: str) -> str | None:
    """Get registrable domain from hostname using Public Suffix List (e.g. relay01.prod.amazon.co.jp -> amazon.co.jp).
    Returns None on failure or if ptlibs.tldparser is unavailable.
    """
    host = (host or "").strip()
    if not host or "." not in host:
        return None
    try:
        from ptlibs.tldparser import parse
        r = parse(host)
        if r is None:
            return None
        domain = getattr(r, "domain", None)
        suffix = getattr(r, "suffix", None)
        if domain and suffix:
            return f"{domain}.{suffix}"
        if domain:
            return domain
        return None
    except Exception:
        return None


# region helper methods


class TestFailedError(Exception):
    """Raised when a test fails in run-all mode; caught to continue with next test."""


def _is_private_ip(ip: str) -> bool:
    """True if ip is a private (RFC 1918 / ULA) address. Blacklist services only check public IPs."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def valid_target_smtp(target: str) -> Target:
    return valid_target(target, domain_allowed=True)


# SMTP EHLO: known extensions and security classification for output
SMTP_KNOWN_EXTENSIONS = frozenset(
    {
        "HELO", "EHLO", "MAIL", "RCPT", "DATA", "RSET", "NOOP", "QUIT",
        "VRFY", "EXPN", "HELP", "SEND", "SOML", "SAML", "TURN", "ETRN", "ATRN",
        "8BITMIME", "SIZE", "CHUNKING", "BINARYMIME", "CHECKPOINT", "DELIVERBY",
        "PIPELINING", "DSN", "AUTH", "BURL", "SMTPUTF8", "STARTTLS", "ENHANCEDSTATUSCODES",
        "VERB",  # seen in practice
    }
)
# AUTH method -> OK / WARNING / ERROR when on PLAIN (cleartext). Over TLS/STARTTLS all are OK.
SMTP_AUTH_METHOD_LEVEL_PLAIN = {
    "PLAIN": "ERROR", "LOGIN": "ERROR", "CRAM-MD5": "ERROR", "DIGEST-MD5": "ERROR",
    "NTLM": "ERROR", "ANONYMOUS": "ERROR", "KERBEROS_V4": "ERROR", "GSSAPI": "ERROR",
    "EXTERNAL": "WARNING",
    "XOAUTH2": "OK", "OAUTHBEARER": "OK", "SCRAM-SHA-1": "OK", "SCRAM-SHA-256": "OK",
}
SMTP_CMD_ERROR = frozenset({"VRFY", "EXPN"})   # user enumeration risk (plain or encrypted)
SMTP_CMD_WARNING = frozenset({"RCPT", "ETRN"})
SIZE_OK_MAX = 26214400       # 25 MB
SIZE_WARNING_MAX = 52428800  # 50 MB
# RCPT TO limit per message: recommended ranges by server role (for evaluation display)
RCPT_LIMIT_SUBMISSION_RANGE = (50, 200)   # Submission server: max recipients per message
RCPT_LIMIT_MTA_RANGE = (100, 1000)        # MTA: max recipients per message


def _parse_rcptmax_from_ehlo(ehlo_raw: str) -> int | None:
    """Parse EHLO for LIMITS RCPTMAX=N (RFC 9422). Returns N or None."""
    if not ehlo_raw or not ehlo_raw.strip():
        return None
    for line in ehlo_raw.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = line.strip().upper()
        if "LIMITS" not in line:
            continue
        # e.g. "250-LIMITS MAILMAX=100 RCPTMAX=512" or "250 LIMITS RCPTMAX=20"
        match = re.search(r"RCPTMAX\s*=\s*(\d+)", line, re.IGNORECASE)
        if match:
            return int(match.group(1))
    return None


def _parse_ehlo_commands(ehlo_raw: str, connection_encrypted: bool = False) -> list[tuple[str, str]]:
    """
    Parse EHLO response into list of (display_string, level) for output.
    Level is OK, WARNING, or ERROR. Hostname line (first line) is skipped.
    Expands AUTH CRAM-MD5 DIGEST-MD5 into separate AUTH CRAM-MD5, AUTH DIGEST-MD5.
    Handles both raw SMTP (250-...) and smtplib-style (no prefix) response.
    When connection_encrypted is True (TLS or STARTTLS), "STARTTLS (is not allowed)" is not
    added, since it is expected and OK on an already-encrypted connection.
    """
    if not ehlo_raw or not ehlo_raw.strip():
        return []
    lines = ehlo_raw.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    result: list[tuple[str, str]] = []
    seen_starttls = False
    first_line = True  # RFC: first EHLO line is always server hostname, not an extension

    for line in lines:
        line = line.strip()
        if not line:
            continue
        # Strip SMTP code if present: "250-..." or "250 ..."; else use whole line (smtplib often strips code)
        if line.startswith("250-"):
            rest = line[4:].strip()
        elif line.startswith("250 "):
            rest = line[3:].strip()
        else:
            rest = line.strip()
        if not rest:
            continue
        # Normalize \r so key/value match (SMTP uses \r\n; smtplib may leave \r on lines)
        rest = rest.replace("\r", " ").strip()
        if not rest:
            continue
        # First token is key, rest is value (e.g. "SIZE 29360128", "AUTH CRAM-MD5 DIGEST-MD5")
        parts = rest.split(None, 1)
        key = (parts[0] or "").upper().strip()
        value = (parts[1] or "").strip() if len(parts) > 1 else ""

        # Skip generic 250 completion (e.g. "250 Ok" / "250 OK") – not an extension
        if key == "OK":
            continue

        # Hostname line (key has dot, not a known extension): skip, not a command
        if "." in key and key not in SMTP_KNOWN_EXTENSIONS:
            continue
        # Unknown extension (no dot): show as OK, except first such line is usually hostname (RFC) – skip once
        if key not in SMTP_KNOWN_EXTENSIONS and "." not in key:
            if first_line:
                first_line = False
                continue
            result.append((rest, "OK"))
            if key == "STARTTLS":
                seen_starttls = True
            continue

        if key == "STARTTLS":
            seen_starttls = True

        if key == "AUTH":
            methods = value.split() if value else []
            for method in methods:
                method_upper = method.upper()
                # Over TLS/STARTTLS, AUTH PLAIN/LOGIN etc. are OK (RFC 8314). On plain they are ERROR.
                level = "OK" if connection_encrypted else SMTP_AUTH_METHOD_LEVEL_PLAIN.get(method_upper, "OK")
                result.append((f"AUTH {method_upper}", level))
            continue

        if key == "SIZE":
            try:
                size_val = int(value) if value else 0
                if size_val <= SIZE_OK_MAX:
                    level = "OK"
                elif size_val <= SIZE_WARNING_MAX:
                    level = "WARNING"
                else:
                    level = "ERROR"
            except (ValueError, TypeError):
                level = "OK"
            result.append((f"SIZE {value}".strip() or "SIZE", level))
            continue

        if key in SMTP_CMD_ERROR:
            level = "ERROR"
        elif key in SMTP_CMD_WARNING:
            level = "WARNING"
        else:
            level = "OK"
        display = f"{key} {value}".strip() if value else key
        result.append((display, level))

    if not seen_starttls and not connection_encrypted:
        result.append(("STARTTLS (is not allowed)", "ERROR"))

    return result


# endregion

# region data classes


class NTLMResult(NamedTuple):
    success: bool
    ntlm: NTLMInfo | None


class MaxConnectionsResult(NamedTuple):
    max: int | None
    ban_minutes: float | None


class RcptLimitResult(NamedTuple):
    """Result of RCPT TO limit test: max accepted before server rejected or we stopped."""
    max_accepted: int
    limit_triggered: bool  # True if server sent 421/452/5xx or closed connection
    server_response: str | None  # First error response when limit triggered
    rejected_addresses: bool = False  # True if server rejected test addresses (450/550) before any accepted
    domain_used: str | None = None  # Domain used for MAIL FROM/RCPT TO (for hint when test failed)


class EnumResult(NamedTuple):
    method: str
    vulnerable: bool
    slowdown: bool | None
    results: list[str] | None


class BlacklistEntry(NamedTuple):
    blacklist: str
    reason: str
    ttl: str


class BlacklistResult(NamedTuple):
    listed: bool
    results: list[BlacklistEntry] | None


class InfoResult(NamedTuple):
    banner: str
    ehlo: str
    ehlo_starttls: str | None = None  # EHLO after STARTTLS upgrade (when PLAIN had STARTTLS)


class EncryptionResult(NamedTuple):
    """
    Result of encryption test: which connection types are available on the port.
    Stored in SMTPResults.encryption so that subsequent tests can use it to choose
    the appropriate connection mode (plaintext, STARTTLS, or TLS).
    """
    plaintext_ok: bool
    starttls_ok: bool
    tls_ok: bool


# Catch-all test result: "configured" | "not_configured" | "indeterminate"
CatchAllResult = str


@dataclass
class SMTPResults:
    blacklist: BlacklistResult | None = None
    blacklist_private_ip_skipped: bool = False  # True when target is private IP (not on public blacklists)
    spf_records: dict[str, list[str]] | None = None
    spf_error: str | None = None  # When run-all SPF test fails
    spf_requires_domain: bool = False  # True when SPF requested but target is IP
    creds: set[Creds] | None = None
    enum_results: list[EnumResult] | None = None
    enum_error: str | None = None  # When run-all enumeration fails (e.g. timeout)
    info: InfoResult | None = None
    info_error: str | None = None  # When run-all info/connect fails
    banner_requested: bool = False
    commands_requested: bool = False
    max_connections: MaxConnectionsResult | None = None
    max_connections_error: str | None = None  # When run-all max connections test fails
    ntlm: NTLMResult | None = None
    ntlm_error: str | None = None  # When run-all NTLM test fails
    open_relay: bool | None = None
    open_relay_error: str | None = None  # When run-all open relay test fails
    blacklist_error: str | None = None  # When run-all blacklist test fails
    encryption: EncryptionResult | None = None
    encryption_error: str | None = None  # When encryption test fails
    catch_all: CatchAllResult | None = None  # "configured" | "not_configured" | "indeterminate"
    rcpt_limit: RcptLimitResult | None = None
    rcpt_limit_error: str | None = None


class VULNS(Enum):
    Blacklist = "PTV-SMTP-BLACKLIST"
    NTLM = "PTV-GENERAL-NTLMINFORMATION"
    OpenRelay = "PTV-SMTP-OPENRELAY"
    UserEnum = "PTV-SMTP-USERENUMERATION"
    WeakCreds = "PTV-GENERAL-WEAKCREDENTIALS"


# endregion

# region arguments


class SMTPArgs(ArgsWithBruteforce):
    target: Target
    tls: bool
    starttls: bool
    info: bool
    ntlm: bool
    mail_from: str | None
    rcpt_to: str | None
    wordlist: str | None
    fqdn: str | None
    enumerate: list[str] | str | None
    blacklist_test: bool
    max_connections: bool
    slow_down: bool
    spf_test: bool
    open_relay: bool
    interactive: bool
    isencrypt: bool

    @staticmethod
    def get_help():
        return [
            {"description": ["SMTP Testing Module"]},
            {"usage": ["ptsrvtester smtp <options> <target>"]},
            {"usage_example": [
                "ptsrvtester smtp -e ALL -sd -w wordlist.txt mail.example.com:25",
                "ptsrvtester smtp --info --ntlm 127.0.0.1"
            ]},
            {"options": [
                ["-i", "--info", "", "Gather basic information (banner and commands)"],
                ["-b", "--banner", "", "Grab banner + Service Identification (product, version, CPE)"],
                ["-c", "--commands", "", "Grab EHLO extensions only"],
                ["-ie", "--isencrypt", "", "Test encryption options (plaintext, STARTTLS, TLS)"],
                ["", "--ntlm", "", "Inspect NTLM authentication"],
                ["-e", "--enumerate", "[VRFY/EXPN/RCPT/ALL]", "User enumeration (default: ALL)"],
                ["-w", "--wordlist", "<wordlist>", "Usernames for enumeration"],
                ["", "--enum-threads", "<N>", "Parallel threads for enumeration (default: 1)"],
                ["-sd", "--slow-down", "", "Test slow-down protection (requires -e)"],
                ["-mc", "--max-connections", "", "Max connections test"],
                ["-rl", "--recipient-limit", "", "Test RCPT TO recipient limit per message"],
                ["-d", "--domain", "<domain>", "Recipient domain for RCPT TO limit test"],
                ["-or", "--open-relay", "", "Test open relay"],
                ["-I", "--interactive", "", "Interactive SMTP CLI"],
                ["", "", "", ""],
                ["-bl", "--blacklist-test", "", "Test against blacklists"],
                ["-s", "--spf-test", "", "Test SPF records (requires domain name)"],
                ["", "", "", ""],
                ["", "--tls", "", "Use implicit SSL/TLS"],
                ["", "--starttls", "", "Use explicit SSL/TLS"],
                ["", "", "", ""],
                ["-u", "--user", "<username>", "Single username for bruteforce"],
                ["-U", "--users", "<wordlist>", "File with usernames"],
                ["-p", "--password", "<password>", "Single password for bruteforce"],
                ["-P", "--passwords", "<wordlist>", "File with passwords"],
                ["", "", "", ""],
                ["-h", "--help", "", "Show this help message and exit"],
            ]}
        ]

    def add_subparser(self, name: str, subparsers) -> None:
        examples = """example usage:
  ptsrvtester smtp -h
  ptsrvtester smtp -e ALL -sd -w wordlist.txt mail.example.com:25"""

        parser = subparsers.add_parser(
            name,
            epilog=examples,
            add_help=True,
            formatter_class=argparse.RawTextHelpFormatter,
        )

        if not isinstance(parser, argparse.ArgumentParser):
            raise TypeError  # IDE typing

        parser.add_argument(
            "target",
            type=valid_target_smtp,
            help="IP[:PORT] or HOST[:PORT] (e.g. 127.0.0.1 or localhost:25)",
        )

        parser.add_argument("--tls", action="store_true", help="use implicit SSL/TLS")
        parser.add_argument("--starttls", action="store_true", help="use explicit SSL/TLS")
        parser.add_argument("-f", "--fqdn", type=str, help="")

        indirect = parser.add_argument_group(
            "INDIRECT SCANNING",
            "Operations that do NOT communicate directly with the target server",
        )
        indirect.add_argument(
            "-bl", "--blacklist-test", action="store_true", help="Test target against blacklists"
        )
        indirect.add_argument("-s", "--spf-test", action="store_true", help="Test SPF records (requires domain name)")

        direct = parser.add_argument_group(
            "DIRECT SCANNING", "Operations that communicate directly with the target server"
        )
        direct.add_argument(
            "-i",
            "--info",
            action="store_true",
            help="Gather basic information (banner and commands)",
        )
        direct.add_argument("-b", "--banner", action="store_true", help="Grab banner + Service Identification (product, version, CPE)")
        direct.add_argument("-c", "--commands", action="store_true", help="Grab EHLO extensions only")
        direct.add_argument(
            "-ie",
            "--isencrypt",
            action="store_true",
            help="Test encryption options on port (plaintext, STARTTLS, TLS)",
        )
        direct.add_argument("--ntlm", action="store_true", help="inspect NTLM authentication")
        direct.add_argument("-w", "--wordlist", type=str, help="Usernames for enumeration")
        direct.add_argument(
            "--enum-threads",
            type=int,
            default=1,
            metavar="N",
            help="Parallel threads for user enumeration (default: 1)",
        )
        direct.add_argument(
            "-e",
            "--enumerate",
            type=str,
            choices=["VRFY", "EXPN", "RCPT", "ALL"],
            nargs="?",
            const="ALL",
            default=None,
            help="User enumeration [VRFY/EXPN/RCPT/ALL] (default: ALL)",
        )
        direct.add_argument(
            "-sd",
            "--slow-down",
            action="store_true",
            help="Test against slow-down protection during enumeration (requires -e)",
        )
        direct.add_argument(
            "-mc", "--max-connections", action="store_true", help="Max connections test"
        )
        direct.add_argument(
            "-rl", "--recipient-limit",
            action="store_true",
            dest="rcpt_limit",
            help="Test RCPT TO recipient limit per message",
        )
        direct.add_argument(
            "-d", "--domain",
            type=str,
            metavar="domain",
            default=None,
            help="Recipient domain for RCPT TO limit test (default: from server banner/EHLO)",
        )
        direct.add_argument("-or", "--open-relay", action="store_true", help="Test Open relay")
        direct.add_argument("-m", "--mail-from", type=str, help="")
        direct.add_argument("-r", "--rcpt-to", type=str, help="")
        direct.add_argument(
            "-I", "--interactive", action="store_true", help="Establish interactive SMTP CLI"
        )

        add_bruteforce_args(parser)


# endregion

# region main module code


class SMTP(BaseModule):
    @staticmethod
    def module_args():
        return SMTPArgs()

    def __init__(self, args: BaseArgs, ptjsonlib: PtJsonLib):
        if not isinstance(args, SMTPArgs):
            raise argparse.ArgumentError(
                None, f'module "{args.module}" received wrong arguments namespace'
            )

        if args.slow_down and args.enumerate == None:
            raise argparse.ArgumentError(None, "--slow-down requires also --enumerate")

        if args.interactive and args.json:
            raise argparse.ArgumentError(None, "--interactive cannot be used together with --json")

        self.use_json = args.json
        self.ptjsonlib = ptjsonlib
        self.already_enumerated = None

        self.max_connections_is_error = None
        self.is_slow_down = None
        self.fqdn = "example.com" if not args.fqdn else args.fqdn

        # Load enumeration wordlist; keep only lines whose local part is valid (RFC 5322/6531)
        if args.wordlist:
            raw = list(filter(lambda x: x != "", text_or_file(None, args.wordlist)))
            self.wordlist = [u for u in raw if self._is_valid_local_part(u.split("@")[0].strip())]
            self._wordlist_skipped = len(raw) - len(self.wordlist)
        else:
            self.wordlist = None
            self._wordlist_skipped = 0

        # Default port number: 465 for implicit TLS (--tls), 587 for STARTTLS, 25 otherwise
        if args.target.port == 0:
            if args.tls:
                args.target.port = 465
            elif getattr(args, "starttls", False):
                args.target.port = 587
            else:
                args.target.port = 25
        self.target = args.target.ip
        self.port = args.target.port

        self.do_brute = check_if_brute(args)

        try:
            socket.inet_aton(self.target)
            self.target_is_ip = True
        except socket.error as e:
            self.target_is_ip = False
        if self.target_is_ip:
            self.target_ip = self.target
        else:
            try:
                self.target_ip = socket.gethostbyname(self.target)
            except socket.gaierror:
                raise argparse.ArgumentError(
                    None, f"Cannot resolve domain name '{self.target}' to IP address"
                )

        self.args = args
        self.results: SMTPResults

    def _is_run_all_mode(self) -> bool:
        """True when only target is given (no test switches). Run all tests in sequence."""
        return not (
            self.args.blacklist_test
            or self.args.spf_test
            or self.args.info
            or self.args.banner
            or self.args.commands
            or self.args.isencrypt
            or self.args.interactive
            or self.args.ntlm
            or self.args.open_relay
            or self.args.enumerate is not None
            or self.args.max_connections
            or self.do_brute
        )

    def _fail(self, msg: str) -> None:
        """In run-all mode: raise TestFailedError. Otherwise: end_error + SystemExit."""
        if self.run_all_mode:
            raise TestFailedError(msg)
        self.ptjsonlib.end_error(msg, self.use_json)
        raise SystemExit

    def run(self):
        self.results = SMTPResults()
        smtp = None
        self.run_all_mode = self._is_run_all_mode()

        if self.run_all_mode:
            self._run_all_tests()
            return

        # Indirect scanning (blacklist: domain + public IP; private IP skipped with message)
        if self.args.blacklist_test:
            bl_result, skipped_private = self.test_blacklist(self.target)
            if skipped_private:
                self.results.blacklist_private_ip_skipped = True
            elif bl_result is not None:
                self.results.blacklist = bl_result

        if self.args.spf_test:
            if self.target_is_ip:
                self.results.spf_requires_domain = True
            else:
                try:
                    self.results.spf_records = self._get_nameservers(self.target)
                except SystemExit:
                    raise
                except Exception as e:
                    self.ptjsonlib.end_error(f"Error during SPF test: {e}", self.use_json)
                    raise SystemExit

        # Direct scanning
        # Only -ie: no need to connect; test_encryption() opens its own connections
        if (
            self.args.isencrypt
            and not self.args.info
            and not self.args.interactive
            and not self.args.ntlm
            and not self.args.open_relay
            and self.args.enumerate is None
            and not self.args.max_connections
            and not self.do_brute
        ):
            self.results.encryption = self.test_encryption()
            return

        # enter only if any of these arguments were explicitly specified
        need_info = (
            self.args.info
            or self.args.banner
            or self.args.commands
            or self.args.interactive
            or self.args.isencrypt
            or self.args.ntlm
            or self.args.open_relay
            or self.args.enumerate is not None
            or self.args.max_connections
            or getattr(self.args, "rcpt_limit", False)
            or self.do_brute
        )
        if need_info:
            do_banner = self.args.banner or self.args.info
            do_commands = (
                self.args.commands or self.args.info or (self.args.enumerate is not None)
                or (getattr(self.args, "rcpt_limit", False) and not getattr(self.args, "domain", None))
            )
            smtp, info = self.initial_info(get_commands=do_commands)
            self.results.banner_requested = do_banner
            self.results.commands_requested = self.args.commands or self.args.info
            self.results.info = InfoResult(
                info.banner if do_banner else None,
                info.ehlo if do_commands else None,
                getattr(info, "ehlo_starttls", None),
            )

            if self.args.isencrypt:
                self.results.encryption = self.test_encryption()

            if self.args.interactive and not self.use_json:
                self.start_interactive_mode(smtp)

            if self.args.ntlm:
                self.results.ntlm = self.auth_ntlm(smtp)

            if self.args.open_relay:
                self.results.open_relay = self.open_relay_test(
                    smtp, "TEST", self.args.mail_from, self.args.rcpt_to
                )

            if self.args.enumerate is not None:
                smtp_enum = self.get_smtp_handler()
                smtp_enum.docmd("EHLO", self.fqdn)
                self.results.enum_results = self.enumeration(smtp_enum)

            smtp_ca = self.get_smtp_handler()
            smtp_ca.docmd("EHLO", self.fqdn)
            self.results.catch_all = self.test_catchall(smtp_ca)

            if self.args.max_connections:
                self.results.max_connections = self.max_connections_test()

            if getattr(self.args, "rcpt_limit", False):
                try:
                    smtp_rc = self.get_smtp_handler()
                    smtp_rc.docmd("EHLO", self.fqdn)
                    self.results.rcpt_limit = self.test_rcpt_limit(smtp_rc)
                except TestFailedError as e:
                    self.results.rcpt_limit_error = str(e)
                except Exception as e:
                    self.results.rcpt_limit_error = str(e)

            if self.do_brute:
                self.results.creds = simple_bruteforce(
                    self._try_login,
                    self.args.user,
                    self.args.users,
                    self.args.password,
                    self.args.passwords,
                    self.args.spray,
                    self.args.threads,
                )

    def _run_all_tests(self) -> None:
        """Run all tests in sequence. On failure: print error, continue with next.
        
        Note: max_connections test is NOT included in run-all mode because it opens
        many connections and triggers rate limits (421) on most servers, causing
        subsequent tests to fail. Use -mc flag explicitly if needed.
        """
        # 1. Banner + commands (plaintext connection, EHLO)
        self.results.banner_requested = True
        self.results.commands_requested = True
        try:
            smtp, info = self.initial_info(get_commands=True)
            self.results.info = info
        except TestFailedError as e:
            self.results.info_error = str(e)
            return
        except Exception as e:
            self.results.info_error = str(e)
            return
        # 2. Encryption: on port 465 we connected via TLS, so set tls_ok=True.
        #    With --starttls we already upgraded, so starttls_ok=True (EHLO may omit STARTTLS after upgrade).
        #    On other ports: STARTTLS from EHLO if present.
        #    Full test_encryption() (all three modes) only with -ie flag.
        if self.args.target.port == 465:
            self.results.encryption = EncryptionResult(
                plaintext_ok=False, starttls_ok=False, tls_ok=True
            )
        elif self.args.starttls or (info.ehlo and "STARTTLS" in info.ehlo.upper()):
            self.results.encryption = EncryptionResult(
                plaintext_ok=True, starttls_ok=True, tls_ok=False
            )
        else:
            self.results.encryption = EncryptionResult(
                plaintext_ok=True, starttls_ok=False, tls_ok=False
            )

        # 3. Open relay (always in run-all; use defaults if mail_from/rcpt_to not set)
        try:
            mail_from = self.args.mail_from or f"relaytest@{self.fqdn}"
            rcpt_to = self.args.rcpt_to or "relaytest@external.relaytest.local"
            self.results.open_relay = self.open_relay_test(smtp, "TEST", mail_from, rcpt_to)
        except TestFailedError as e:
            self.results.open_relay_error = str(e)
        except Exception as e:
            self.results.open_relay_error = str(e)

        # 4. Blacklist (domain + public IP; private IP skipped)
        try:
            bl_result, skipped_private = self.test_blacklist(self.target)
            if skipped_private:
                self.results.blacklist_private_ip_skipped = True
            elif bl_result is not None:
                self.results.blacklist = bl_result
        except TestFailedError as e:
            self.results.blacklist_error = str(e)
        except Exception as e:
            self.results.blacklist_error = str(e)

        # 5. SPF (only if domain)
        if self.target_is_ip:
            self.results.spf_requires_domain = True
        else:
            try:
                self.results.spf_records = self._get_nameservers(self.target)
            except TestFailedError as e:
                self.results.spf_error = str(e)
            except Exception as e:
                self.results.spf_error = str(e)

        # 6. User enumeration (ALL) – use fresh connection (open_relay may have closed smtp)
        save_enum = self.args.enumerate
        try:
            self.args.enumerate = "ALL"
            smtp_enum = self.get_smtp_handler()
            smtp_enum.docmd("EHLO", self.fqdn)
            self.results.enum_results = self.enumeration(smtp_enum)
        except TestFailedError as e:
            self.results.enum_error = str(e)
        except Exception as e:
            self.results.enum_error = str(e)
        finally:
            self.args.enumerate = save_enum

        # 6b. Catch-all (after enumeration so we can use enum_results to choose method)
        try:
            smtp_ca = self.get_smtp_handler()
            smtp_ca.docmd("EHLO", self.fqdn)
            self.results.catch_all = self.test_catchall(smtp_ca)
        except Exception:
            self.results.catch_all = "indeterminate"

        # 6c. RCPT TO limit (per message)
        try:
            smtp_rc = self.get_smtp_handler()
            smtp_rc.docmd("EHLO", self.fqdn)
            self.results.rcpt_limit = self.test_rcpt_limit(smtp_rc)
        except TestFailedError as e:
            self.results.rcpt_limit_error = str(e)
        except Exception as e:
            self.results.rcpt_limit_error = str(e)

        # 7. NTLM
        try:
            self.results.ntlm = self.auth_ntlm(smtp)
        except TestFailedError as e:
            self.results.ntlm_error = str(e)
        except Exception as e:
            self.results.ntlm_error = str(e)

    def connect(self) -> tuple[smtplib.SMTP | smtplib.SMTP_SSL, int, bytes]:
        """Port 465 is implicit TLS only (SMTPS), so we use TLS even without --tls.
        For IP targets we connect manually with server_hostname=None so SNI does not break."""
        try:
            if self.args.tls or self.args.target.port == 465:
                ctx = ssl._create_unverified_context()
                host, port = self.args.target.ip, self.args.target.port
                try:
                    ipaddress.ip_address(host)
                    server_hostname = None
                except ValueError:
                    server_hostname = host
                sock = socket.create_connection((host, port), timeout=15.0)
                sock_ssl = ctx.wrap_socket(sock, server_hostname=server_hostname)
                smtp = smtplib.SMTP(timeout=15.0)
                smtp.sock = sock_ssl
                smtp.file = None
                status, reply = smtp.getreply()
            else:
                smtp = smtplib.SMTP(timeout=15.0)
                status, reply = smtp.connect(self.args.target.ip, self.args.target.port)
                if self.args.starttls and status == 220:
                    status_stls, _ = smtp.docmd("STARTTLS")
                    if status_stls == 220:
                        ctx = ssl._create_unverified_context()
                        try:
                            _is_ip = ipaddress.ip_address(self.args.target.ip)
                            server_hostname = None
                        except ValueError:
                            server_hostname = self.args.target.ip
                        sock_ssl = ctx.wrap_socket(smtp.sock, server_hostname=server_hostname)
                        smtp.sock = sock_ssl
                        smtp.file = None
                        smtp.helo_resp = None
                        smtp.ehlo_resp = None
                        smtp.esmtp_features = {}
                        smtp.does_esmtp = False

            return smtp, status, reply
        except Exception as e:
            mode = "TLS" if (self.args.tls or self.args.target.port == 465) else get_mode(self.args)
            msg = (
                f"Could not connect to the target server "
                f"{self.args.target.ip}:{self.args.target.port} ({mode}): {e}"
            )
            if self.args.target.port == 587 and not self.args.starttls and "refused" in str(e).lower():
                msg += " (na portu 587 zkus --starttls)"
            self._fail(msg)

    def get_smtp_handler(self) -> smtplib.SMTP:
        smtp_handler, status, reply = self.connect()
        if status == 220:
            return smtp_handler
        else:
            self.ptjsonlib.end_error(
                f"SMTP Info - [{status}] {self.bytes_to_str(reply)}", self.use_json
            )
            raise SystemExit

    def _get_smtp_connection(self):
        smtp, status, reply = self.connect()

        if status == 220:
            status, reply = smtp.docmd("EHLO", f"{self.fqdn}")
            if status == 250:
                # print("OK CONNECTION", reply)
                return smtp
            else:
                raise Exception("Error when EHLOing")
        else:
            # Include actual server response (e.g. 421 = too many connections, try later)
            raise Exception(f"Server responded {status}: {self.bytes_to_str(reply)}")

    def wait_for_unban(self, seconds, ban_duration=0, retries_left=12):
        """Wait for server to unban, then try to reconnect. Returns (ban_minutes, reconnected)."""
        self.noop_smtp_connections()
        ban_duration += seconds
        time.sleep(seconds)
        try:
            self.ptdebug(f">", end="")
            self._get_smtp_connection()
            self.ptdebug(f"\r", end="")
            return (ban_duration / 60, True)
        except Exception as e:
            if retries_left <= 0:
                return (ban_duration / 60, False)
            return self.wait_for_unban(5, ban_duration, retries_left - 1)

    def noop_smtp_connections(self):
        for smtp in self.smtp_list:
            status, reply = smtp.docmd("noop")
            if status != 250:
                return True
        return False

    def close_smtp_connections(
        self,
    ):
        for smtp in self.smtp_list:
            try:
                smtp.quit()
            except Exception as e:
                # print("error closing smtp connections:", e)
                continue
        del self.smtp_list

    def max_connections_test(self) -> MaxConnectionsResult:
        self.smtp_list = []
        allowed_connections = None
        is_disconnect = False
        ban_duration = None
        ban_reconnected = True

        self.ptdebug(f"Max smtp connections test", title=True)
        start_time = time.time()
        self.ptdebug(f"", Out.INFO, end="")
        for index, i in enumerate(range(100)):
            try:
                self.ptdebug(f">", end="")
                self.smtp_list.append(self._get_smtp_connection())
                if self.noop_smtp_connections() and not is_disconnect:
                    is_disconnect = time.time() - start_time
            except Exception as e:
                # ve chvili kdy uz neni mozne navazat spojeni
                allowed_connections = len(self.smtp_list)
                self.ptdebug(f"\r", end="")
                self.ptdebug(
                    f"Maximum number of estabilished connections: {allowed_connections} {' '*(allowed_connections-35)}",
                    Out.INFO,
                )
                if index == 0:
                    self._fail(f"Could not retrieve initial smtp connection - {e}")
                self.smtp_list.pop()
                try:
                    # self.noop_smtp_connections()
                    self.smtp_list.append(self._get_smtp_connection())
                except Exception as e:
                    self.ptdebug(f"You're banned, reconnecting in 60 seconds ...", Out.INFO)
                    self.ptdebug(f"", Out.INFO, end="")
                    ban_duration, ban_reconnected = self.wait_for_unban(60)
                    if not ban_reconnected:
                        self.ptdebug(
                            f"Could not reconnect after ban (max retries exceeded)",
                            Out.INFO,
                        )
                break

        # close all smtp connections and delete *self.smtp_list*
        self.close_smtp_connections()

        if is_disconnect:
            self.ptdebug(
                f"Refreshed connection is disconnected after: {round(is_disconnect)} seconds",
                Out.INFO,
            )
        if ban_duration:
            if ban_reconnected:
                self.ptdebug(f"Unblocked after {ban_duration} minutes", Out.INFO)
        else:
            self.ptdebug(f"Not banned", Out.INFO)

        return MaxConnectionsResult(allowed_connections, ban_duration)

    def open_relay_test(self, smtp, msg, mail_from, rcpt_to) -> bool:
        self.ptdebug(f"Open Relay Test:", title=True)
        try:
            smtp.sendmail(mail_from, rcpt_to, msg)
            self.ptdebug("Server is vulnerable to Open relay", Out.VULN)
            return True
        except:
            self.ptdebug("Server is not vulnerable to Open relay", Out.NOTVULN)
            return False

    @staticmethod
    def _to_parent_domain(host: str) -> str:
        """Reduce hostname to parent (second-level) domain: strip leftmost label if 3+ parts."""
        host = (host or "").strip().lower()
        if not host or "." not in host:
            return host
        parts = host.split(".")
        if len(parts) >= 3:
            return ".".join(parts[1:])
        return host

    def _get_rcpt_limit_domain(self) -> str:
        """Domain for RCPT TO limit test: -d/--domain, or from server banner/EHLO (via PSL), or fqdn, or test.com.
        User -d is used as-is. Domain from server: FQDN is resolved to registrable domain via Public Suffix List
        (e.g. relay01.prod.amazon.co.jp -> amazon.co.jp); fallback to full hostname or _to_parent_domain if PSL fails.
        """
        domain = getattr(self.args, "domain", None)
        if domain and domain.strip():
            return domain.strip()
        host: str | None = None
        info = getattr(self.results, "info", None)
        if info and getattr(info, "banner", None):
            line = (info.banner or "").replace("\r", "").split("\n")[0].strip()
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "220":
                host = parts[1]
            elif parts:
                host = parts[0]
            if host and "." in host:
                psl_domain = _registrable_domain_psl(host)
                if psl_domain:
                    return psl_domain
                return host
        if info and getattr(info, "ehlo", None):
            raw = (info.ehlo or "").replace("\r\n", "\n").replace("\r", "\n")
            for line in raw.split("\n"):
                line = line.strip()
                if line.startswith("250-"):
                    rest = line[4:].strip()
                elif line.startswith("250 "):
                    rest = line[3:].strip()
                else:
                    continue
                if rest and "." in rest.split()[0]:
                    host = rest.split()[0]
                    psl_domain = _registrable_domain_psl(host)
                    if psl_domain:
                        return psl_domain
                    return host
        if self.fqdn and "." in self.fqdn and "pentereptools" not in self.fqdn.lower():
            psl_domain = _registrable_domain_psl(self.fqdn)
            if psl_domain:
                return psl_domain
            return self._to_parent_domain(self.fqdn)
        return "test.com"

    def _run_rcpt_limit_for_domain(self, smtp: smtplib.SMTP, domain: str) -> RcptLimitResult:
        """Run MAIL FROM + RCPT TO loop for a given domain. Used so we can retry with parent domain."""
        max_try = 2000
        mail_from = f"a@{domain}"

        try:
            status, reply = smtp.docmd("MAIL FROM:", f"<{mail_from}>")
            if status != 250:
                return RcptLimitResult(0, False, self.bytes_to_str(reply), False)
        except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError) as e:
            return RcptLimitResult(0, True, str(e), False)

        accepted = 0
        limit_response: str | None = None
        for i in range(1, max_try + 1):
            try:
                status, reply = smtp.docmd("RCPT TO:", f"<{i}@{domain}>")
                reply_str = self.bytes_to_str(reply)
                if status == 250:
                    accepted += 1
                    continue
                limit_response = f"[{status}] {reply_str}".strip()
                # Policy rejection (relay/sender/recipient) when no recipient accepted yet – not a count limit
                if accepted == 0 and status in (450, 550, 553, 554):
                    self.ptdebug(f"Server rejects test addresses: {limit_response}", Out.INFO)
                    return RcptLimitResult(0, False, limit_response, rejected_addresses=True)
                # Real RCPT count limit: 421 Limit exceeded, 452 Too many recipients, other 5xx
                if status in (421, 452) or (500 <= status <= 599):
                    self.ptdebug(f"Server limit after {accepted} recipients: {limit_response}", Out.INFO)
                    return RcptLimitResult(accepted, True, limit_response, False)
                return RcptLimitResult(accepted, False, limit_response, False)
            except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError) as e:
                self.ptdebug(f"Server closed connection after {accepted} recipients", Out.INFO)
                return RcptLimitResult(accepted, True, str(e), False)

        self.ptdebug(f"No limit observed up to {accepted} recipients", Out.VULN)
        return RcptLimitResult(accepted, False, None, False)

    def test_rcpt_limit(self, smtp: smtplib.SMTP) -> RcptLimitResult:
        """
        Test RCPT TO limit per message: send MAIL FROM then many RCPT TO
        until server rejects (452 Too many recipients, 421, 5xx) or closes.
        When domain is taken from server (banner/EHLO) and server rejects with 550/553,
        retry with parent domain (e.g. calm.festiveloft.net -> festiveloft.net).
        """
        self.ptdebug("RCPT TO limit test (per message)", title=True)
        domain = self._get_rcpt_limit_domain()
        result = self._run_rcpt_limit_for_domain(smtp, domain)
        domain_used = domain

        # If server rejected (e.g. "User unknown" for full hostname) and user did not set -d,
        # retry with parent domain so test can succeed (e.g. festiveloft.net accepts 1@, 2@, ...)
        if (
            getattr(result, "rejected_addresses", False)
            and not getattr(self.args, "domain", None)
            and domain.count(".") >= 2
        ):
            parent = self._to_parent_domain(domain)
            if parent != domain:
                self.ptdebug(f"Retrying RCPT TO limit with parent domain: {parent}", Out.INFO)
                try:
                    smtp.docmd("RSET")
                except Exception:
                    pass
                result = self._run_rcpt_limit_for_domain(smtp, parent)
                domain_used = parent

        return RcptLimitResult(
            result.max_accepted,
            result.limit_triggered,
            result.server_response,
            getattr(result, "rejected_addresses", False),
            domain_used,
        )

    def start_interactive_mode(self, smtp: smtplib.SMTP):
        self.ptprint("\n", end="")
        while True:
            user_input = input("[*] INTERACTIVE MODE: ").upper()
            status, reply = smtp.docmd(user_input)
            if user_input in ("EXIT", "QUIT"):
                break
            if user_input == "HELP":
                self.ptprint(f"[{status}] " + self.bytes_to_str(reply))
            if not self.bytes_to_str(reply).endswith("\n"):
                self.ptprint(f"[{status}] " + self.bytes_to_str(reply))
                self.ptprint(f" ")
            else:
                self.ptprint(f"[{status}] " + self.bytes_to_str(reply).replace("\n", "\n      "))

    def expn_vrfy_slow_down_test(self, method: str, smtp):
        if sum(self.slow_down_results.values()) >= 1:
            self.ptdebug(f"New smtp handle required, initiating new smtp connection ...", Out.INFO)
            smtp = self.get_smtp_handler()
            smtp.docmd("EHLO", f"{self.fqdn}")

        self.ptdebug(f"[{method}] SLOW DOWN TEST {' '*6}", Out.INFO, end="\r")

        dummy_data = [
            "".join(random.choices("abcdefghijk", k=random.randint(1, 5))) for i in range(29)
        ]
        half = int(len(dummy_data) / 2)
        is_slow_down = False
        initial_time = 0
        last_request_time = 0
        first_half_time = 0
        second_half_time = 0
        for index, user in enumerate(dummy_data):
            endl = "\n" if index + 1 == len(dummy_data) else "\r"
            self.ptdebug(
                f"[{method}] SLOW DOWN TEST [{index+1}/{len(dummy_data)}]", Out.INFO, end=endl
            )
            start_time = time.time()
            try:
                smtp.docmd(method, user)
            except:
                return {method.lower(): True}

            end_time = time.time() - start_time

            last_request_time = end_time
            if index == 0:
                initial_time += end_time

            if index < half:
                first_half_time += end_time
            else:
                second_half_time += end_time

            if end_time >= 3:
                is_unstable_response = True
            if end_time >= 3 and is_unstable_response:
                self.ptdebug(f"[{method}] SLOW DOWN TEST [{index+1}/{index+1}]", Out.INFO)
                self.ptdebug(f"Unstable response (>3sec), break", Out.VULN)
                is_slow_down = True
                break

        if (second_half_time - first_half_time) > initial_time * 10:
            is_slow_down = True
        if is_slow_down:
            self.ptdebug(f"{method} Method have slow-down protection implemented", Out.NOTVULN)
        self.ptdebug(f"First request response time: {str(initial_time)[:8]}", Out.INFO)
        self.ptdebug(f"Last request response time:  {str(last_request_time)[:8]}", Out.INFO)

        return {method.lower(): is_slow_down}

    def rcpt_slow_down_test(self, smtp):
        if sum(self.slow_down_results.values()) >= 1:
            # print("Retrieving new smtp handle ... for rcpt test")
            smtp = self.get_smtp_handler()
            smtp.docmd("EHLO", f"{self.fqdn}")

        self.ptdebug(f"[RCPT] SLOW DOWN TEST {' '*6}", Out.INFO, end="\r")
        status, reply = smtp.docmd("MAIL FROM:", "<mail@from.me>")

        dummy_data = [
            "".join(random.choices("abcdefghijk", k=random.randint(1, 5))) for i in range(20)
        ]
        half = int(len(dummy_data) / 2)
        time_data = []
        is_slow_down = False

        first_half_time = 0
        initial_time = 0
        second_half_time = 0
        last_request_time = 0

        is_unstable_response = False
        for index, user in enumerate(dummy_data):
            endl = "\n" if index + 1 == len(dummy_data) else "\r"
            self.ptdebug(f"[RCPT] SLOW DOWN TEST [{index+1}/{len(dummy_data)}]", Out.INFO, end=endl)
            start_time = time.time()
            status, reply = smtp.docmd("RCPT TO:", f"<{user}>")
            end_time = time.time() - start_time

            last_request_time = end_time
            if index == 0:
                initial_time += end_time
            # if index+1 == len(dummy_data):
            if index < half:
                first_half_time += end_time
            else:
                second_half_time += end_time

            if end_time >= 3:
                is_unstable_response = True
            if end_time >= 3 and is_unstable_response:
                # print("unstable response, break")
                is_slow_down = True
                break

        if (second_half_time - first_half_time) > initial_time * 10:
            is_slow_down = True
        if is_slow_down:
            self.ptdebug(f"[RCPT] Method have slow-down protection implemented", Out.NOTVULN)

        self.ptdebug(f"First request response time: {str(initial_time)[:8]}", Out.INFO)
        self.ptdebug(f"Last request response time:  {str(last_request_time)[:8]}", Out.INFO)

        return {"rcpt": is_slow_down}

    def expn_vrfy_enumeration(self, method, smtp) -> list[str]:
        enum_threads = getattr(self.args, "enum_threads", 1)
        ehlo = (self.results.info and self.results.info.ehlo) or ""
        supports_smtputf8 = "SMTPUTF8" in ehlo.upper()
        if getattr(self, "_wordlist_skipped", 0) > 0:
            self.ptdebug(
                f"Skipped {self._wordlist_skipped} invalid local parts from wordlist",
                Out.INFO,
            )
        self.ptdebug(f"Enumerating users:" + (f" ({enum_threads} threads)" if enum_threads > 1 else ""), Out.INFO)
        enumerated_users: list[str] = []
        total_aliases = 0 if method == "EXPN" else None

        def _skip_non_ascii_no_utf8(s: str) -> bool:
            return not supports_smtputf8 and any(ord(c) >= 128 for c in s)

        if enum_threads <= 1:
            if supports_smtputf8:
                smtp.command_encoding = "utf-8"
            for user in self.wordlist:
                if _skip_non_ascii_no_utf8(user):
                    continue
                try:
                    status, reply = smtp.docmd(method, user)
                except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError) as e:
                    self.ptdebug(
                        f"{method} enumeration interrupted (connection closed/reset): {e}",
                        Out.INFO,
                    )
                    try:
                        smtp = self.get_smtp_handler()
                        smtp.docmd("EHLO", f"{self.fqdn}")
                        if supports_smtputf8:
                            smtp.command_encoding = "utf-8"
                        status, reply = smtp.docmd(method, user)
                    except Exception:
                        break
                if status != 550:
                    user_email = re.findall(r"<(.*?)>", self.bytes_to_str(reply))
                    if user_email:
                        enumerated_users.extend(user_email)
                        self.ptdebug(user_email[0])
                    if method == "EXPN" and len(user_email) > 1:
                        for alias in user_email[1:]:
                            total_aliases += len(user_email[1:])
                            self.ptdebug(f"   {alias}", Out.ADDITIONS)
        else:
            user_queue: queue.Queue[str | None] = queue.Queue()
            for u in self.wordlist:
                if not _skip_non_ascii_no_utf8(u):
                    user_queue.put(u)
            for _ in range(enum_threads):
                user_queue.put(None)
            result_lock = threading.Lock()

            def worker() -> None:
                try:
                    conn = self.get_smtp_handler()
                    conn.docmd("EHLO", f"{self.fqdn}")
                    if supports_smtputf8:
                        conn.command_encoding = "utf-8"
                except Exception:
                    return
                while True:
                    user = user_queue.get()
                    if user is None:
                        user_queue.task_done()
                        break
                    try:
                        status, reply = conn.docmd(method, user)
                    except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError):
                        try:
                            conn = self.get_smtp_handler()
                            conn.docmd("EHLO", f"{self.fqdn}")
                            if supports_smtputf8:
                                conn.command_encoding = "utf-8"
                            status, reply = conn.docmd(method, user)
                        except Exception:
                            user_queue.task_done()
                            continue
                    if status != 550:
                        user_email = re.findall(r"<(.*?)>", self.bytes_to_str(reply))
                        if user_email:
                            with result_lock:
                                enumerated_users.extend(user_email)
                                self.ptdebug(user_email[0])
                    user_queue.task_done()

            threads_list = [threading.Thread(target=worker) for _ in range(enum_threads)]
            for t in threads_list:
                t.start()
            for t in threads_list:
                t.join()
            total_aliases = 0

        additional_message = (
            f"(total {len(enumerated_users) + (total_aliases or 0)} with aliases)"
            if method == "EXPN"
            else ""
        )
        self.ptdebug(f" ")
        self.ptdebug(f"-- Enumerated {len(enumerated_users)} emails {additional_message} --")
        self.ptdebug(f" ")

        self.already_enumerated = True
        return enumerated_users

    def expn_vrfy_test(self, method, smtp) -> bool:
        status, reply = smtp.docmd(method, "foofoofoo")
        self.ptdebug(f"Testing {method} method: [{status}] {self.bytes_to_str(reply)}", Out.INFO)
        if status in [250, 550] and not "AUTH" in self.bytes_to_str(reply).upper():
            is_vulnerable = True
            self.ptdebug(f"Server is vulnerable to {method} enumeration", Out.VULN)
        else:
            is_vulnerable = False
            self.ptdebug(f"Server is not vulnerable to {method} enumeration", Out.INFO)
        return is_vulnerable

    def newline_to_reply(self, reply):
        reply = self.bytes_to_str(reply)
        if not reply.endswith("\n"):
            reply += "\n"
        return reply

    def rcpt_test(self, smtp) -> bool:
        """RCPT enum vulnerability"""
        self.ptdebug(f"Testing RCPT method:", Out.INFO, end=" ")

        status, reply = smtp.docmd("MAIL FROM:", "<mail@from.me>")
        status, reply = smtp.docmd("RCPT TO:", "<foofoofoo>")
        reply = self.bytes_to_str(reply)
        self.ptdebug(f"[{status}] " + reply)
        if (
            status in [250, 550]
            and not "AUTH" in reply.upper()
            and ("UNKNOWN" in reply.upper() or "OK" in reply.upper())
        ):
            is_vulnerable = True
            self.ptdebug(f"Server is vulnerable to RCPT enumeration", Out.VULN)
        else:
            is_vulnerable = False
            self.ptdebug(f"Server is not vulnerable to RCPT enumeration", Out.NOTVULN)
        return is_vulnerable

    def test_catchall(self, smtp: smtplib.SMTP) -> CatchAllResult:
        """
        Detect Catch-All mailbox: if server accepts 3 invalid addresses as valid,
        catch-all is configured (VRFY/EXPN) or indeterminate (RCPT).
        Uses VRFY or EXPN when available; otherwise RCPT. RCPT cannot distinguish
        valid address from catch-all, so result is Indeterminate when all accepted.
        Per RFC 5321: 250/251/252 are success for VRFY/EXPN; 550 = user unknown.
        """
        CATCHALL_INVALID = ("catchallnx001", "catchallnx002", "catchallnx003")
        # RFC 5321: 250 = verified, 251 = forward, 252 = cannot verify (e.g. relay)
        VRFY_EXPN_ACCEPT = (250, 251, 252)

        def _choose_method() -> str | None:
            if self.results.enum_results:
                for e in self.results.enum_results:
                    if e.vulnerable and e.method in ("expn", "vrfy", "rcpt"):
                        return e.method
            try:
                status, _ = smtp.docmd("VRFY", "catchallprobe")
                if status in (*VRFY_EXPN_ACCEPT, 550):
                    return "vrfy"
            except Exception:
                pass
            try:
                status, _ = smtp.docmd("EXPN", "catchallprobe")
                if status in (*VRFY_EXPN_ACCEPT, 550):
                    return "expn"
            except Exception:
                pass
            try:
                smtp.docmd("MAIL FROM:", "<catchall@probe.test>")
                status, _ = smtp.docmd("RCPT TO:", "<catchallprobe>")
                if status in (250, 251, 252, 550):
                    return "rcpt"
            except Exception:
                pass
            return None

        try:
            method = _choose_method()
            if not method:
                return "indeterminate"

            if method in ("vrfy", "expn"):
                cmd = "VRFY" if method == "vrfy" else "EXPN"
                accepted = 0
                for user in CATCHALL_INVALID:
                    try:
                        status, _ = smtp.docmd(cmd, user)
                        if status in VRFY_EXPN_ACCEPT:
                            accepted += 1
                        elif status == 550:
                            return "not_configured"
                    except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError):
                        return "indeterminate"
                return "configured" if accepted == 3 else "indeterminate"

            else:
                try:
                    smtp.docmd("MAIL FROM:", "<catchall@probe.test>")
                except Exception:
                    return "indeterminate"
                for user in CATCHALL_INVALID:
                    try:
                        status, reply = smtp.docmd("RCPT TO:", f"<{user}>")
                        if status == 550 or "UNKNOWN" in self.bytes_to_str(reply).upper():
                            return "not_configured"
                    except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError):
                        return "indeterminate"
                return "indeterminate"
        except Exception:
            return "indeterminate"

    def rcpt_enumeration(self, smtp) -> list[str]:
        enum_threads = getattr(self.args, "enum_threads", 1)
        ehlo = (self.results.info and self.results.info.ehlo) or ""
        supports_smtputf8 = "SMTPUTF8" in ehlo.upper()
        if getattr(self, "_wordlist_skipped", 0) > 0:
            self.ptdebug(
                f"Skipped {self._wordlist_skipped} invalid local parts from wordlist",
                Out.INFO,
            )
        self.ptdebug(f"Enumerating users:" + (f" ({enum_threads} threads)" if enum_threads > 1 else ""), Out.INFO)
        enumerated_users: list[str] = []

        def _skip(local: str) -> bool:
            return not supports_smtputf8 and any(ord(c) >= 128 for c in local)

        if enum_threads <= 1:
            if supports_smtputf8:
                smtp.command_encoding = "utf-8"
            for user in self.wordlist:
                local = user.split("@")[0].strip()
                if _skip(local):
                    continue
                try:
                    status, reply = smtp.docmd("RCPT TO:", f"<{local}>")
                except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError) as e:
                    self.ptdebug(
                        f"RCPT enumeration interrupted (connection closed/reset): {e}",
                        Out.INFO,
                    )
                    try:
                        smtp = self.get_smtp_handler()
                        smtp.docmd("EHLO", f"{self.fqdn}")
                        if supports_smtputf8:
                            smtp.command_encoding = "utf-8"
                        smtp.docmd("MAIL FROM:", "<mail@from.me>")
                        status, reply = smtp.docmd("RCPT TO:", f"<{local}>")
                    except Exception:
                        break
                if status != 550 and not "UNKNOWN" in self.bytes_to_str(reply).upper():
                    enumerated_users.append(local)
                    self.ptdebug(local)
        else:
            locals_to_try = [u.split("@")[0].strip() for u in self.wordlist if not _skip(u.split("@")[0].strip())]
            user_queue: queue.Queue[str | None] = queue.Queue()
            for local in locals_to_try:
                user_queue.put(local)
            for _ in range(enum_threads):
                user_queue.put(None)
            result_lock = threading.Lock()

            def rcpt_worker() -> None:
                try:
                    conn = self.get_smtp_handler()
                    conn.docmd("EHLO", f"{self.fqdn}")
                    if supports_smtputf8:
                        conn.command_encoding = "utf-8"
                    conn.docmd("MAIL FROM:", "<mail@from.me>")
                except Exception:
                    return
                while True:
                    local = user_queue.get()
                    if local is None:
                        user_queue.task_done()
                        break
                    try:
                        status, reply = conn.docmd("RCPT TO:", f"<{local}>")
                    except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError):
                        try:
                            conn = self.get_smtp_handler()
                            conn.docmd("EHLO", f"{self.fqdn}")
                            if supports_smtputf8:
                                conn.command_encoding = "utf-8"
                            conn.docmd("MAIL FROM:", "<mail@from.me>")
                            status, reply = conn.docmd("RCPT TO:", f"<{local}>")
                        except Exception:
                            user_queue.task_done()
                            continue
                    if status != 550 and not "UNKNOWN" in self.bytes_to_str(reply).upper():
                        with result_lock:
                            enumerated_users.append(local)
                            self.ptdebug(local)
                    user_queue.task_done()

            threads_list = [threading.Thread(target=rcpt_worker) for _ in range(enum_threads)]
            for t in threads_list:
                t.start()
            for t in threads_list:
                t.join()

        self.ptdebug(f" ")
        self.ptdebug(f"-- Enumerated {len(enumerated_users)} users --")
        self.ptdebug(f" ")

        self.already_enumerated = True
        return enumerated_users

    def bytes_to_str(self, text):
        return text.decode("utf-8")

    # RFC 5322 atext (atom text) + dot; RFC 6531 allows Unicode letters/digits in local part
    _ATEXT_ASCII = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+-/=?^_`{|}~.")

    @classmethod
    def _is_valid_local_part(cls, s: str) -> bool:
        """True if s is a valid email local part (RFC 5322 atext / dot-atom, RFC 6531 Unicode)."""
        if not s or len(s) > 64:
            return False
        if s[0] == "." or s[-1] == "." or ".." in s:
            return False
        for c in s:
            if c in cls._ATEXT_ASCII:
                continue
            if ord(c) < 128:
                return False
            cat = unicodedata.category(c)
            if cat not in ("Ll", "Lu", "Lm", "Lo", "Lt", "Nl", "Nd"):
                return False
        return True

    def test_blacklist(self, target: str) -> tuple[BlacklistResult | None, bool]:
        """Run blacklist check. Returns (result, skipped_private). skipped_private=True for private IP (no API call)."""
        self.ptdebug("Testing target against blacklists:", title=True)
        if self.target_is_ip and _is_private_ip(target):
            self.ptdebug("Blacklist test skipped: private/internal IP (not on public blacklists)", Out.INFO)
            return (None, True)

        blacklist_parser = BlacklistParser(self.ptdebug, self.args.json)

        try:
            error_msg = blacklist_parser.lookup(target)
        except Exception as e:
            self._fail(f"Exception during Blacklist lookup: {e}")

        if error_msg:
            self.ptdebug(error_msg, Out.VULN)
            # API returned "Cannot test Private IP Address" or similar
            if error_msg == "Cannot test Private IP Address":
                return (None, True)
            # Other error: no result, not "skipped private"
            return (BlacklistResult(False, None), False)

        # Check if result is None or doesn't have the expected structure
        if blacklist_parser.result is None or "table_result" not in blacklist_parser.result:
            return (BlacklistResult(False, None), False)

        listed = [
            BlacklistEntry(r[1], r[2], r[3])
            for r in blacklist_parser.result["table_result"]
            if r[0] == "LISTED"
        ]

        if len(listed) > 0:
            return (BlacklistResult(True, listed), False)
        return (BlacklistResult(False, None), False)

    def _resolver_query(self, resolver, domain, ns, record_type):
        data = resolver.resolve(domain, record_type)
        return [self._rdata_to_str(rdata) for rdata in data]

    def _get_spf_records(self, resolver, domain, ns):
        # self.ptprint(f"SPF Records for {ns}:", "INFO", self.use_json))
        spf_result = {ns: []}
        try:
            for record in ["SPF", "TXT"]:
                data = resolver.resolve(domain, record)
                for rdata in data:
                    spf_result[ns].append(self._rdata_to_str(rdata))
        except dns.resolver.NoAnswer as e:
            pass
        except dns.resolver.Timeout as e:
            pass
        return spf_result

    def _rdata_to_str(self, rdata):
        str_rdata = str(rdata)
        if str_rdata.startswith('"') and str_rdata.endswith('"'):
            str_rdata = str_rdata[1:-1]
        return str_rdata

    def _get_nameservers(self, domain) -> dict[str, list[str]]:
        self.ptdebug(f"Retrieving SPF records for: {self.target}", title=True)

        resolver = dns.resolver.Resolver()
        resolver.timeout = 10
        resolver.lifetime = 10
        self.ptdebug(f"Retrieving nameservers for domain: {domain}", title=True)
        try:
            ns_query = resolver.resolve(domain, "NS", tcp=True)
            nameserver_list = [str(rdata)[:-1] for rdata in ns_query]
            self.ptdebug("    " + "\n    ".join(nameserver_list))
        except Exception as e:
            # Make error message more user-friendly
            error_msg = str(e)
            if "does not exist" in error_msg or "NXDOMAIN" in error_msg:
                user_msg = f"Domain '{domain}' does not exist in DNS"
            elif "does not contain an answer" in error_msg or "NoAnswer" in str(type(e).__name__):
                # Check if it's a subdomain
                parts = domain.split('.')
                if len(parts) > 2:
                    main_domain = '.'.join(parts[-2:])
                    user_msg = f"Could not retrieve nameservers for '{domain}'. SPF records are usually on the main domain. Try using '{main_domain}' instead."
                else:
                    user_msg = f"Could not retrieve nameservers for '{domain}'. The domain may not have NS records configured."
            else:
                user_msg = f"Error retrieving nameservers for '{domain}': {error_msg}"
            if self.run_all_mode:
                self._fail(user_msg)
            full_msg = f"{user_msg}\n\nUse 'ptsrvtester smtp -h' for help."
            self.ptjsonlib.end_error(full_msg, self.use_json)
            raise SystemExit

        spf_result = {}
        for ns in nameserver_list:
            try:
                ns_ip = socket.gethostbyname(ns)
            except Exception as e:
                self.ptdebug(f"Exception - {e}", Out.ERROR)
                continue
            resolver.nameservers = [ns_ip]
            spf_result.update({ns: []})
            self.ptdebug(f"{ns}:", Out.INFO)
            spf_result[ns].extend(self._get_spf_for_ns(domain, resolver))

        is_spf_difference = self._check_difference_between_ns_response(spf_result)

        results = {ns: val for ns, val in spf_result.items() if len(val) > 0}
        return results

    def _check_difference_between_ns_response(self, result):
        is_difference = False
        for index, value in enumerate(result.values()):
            for index_2, value_2 in enumerate(result.values()):
                if index == index_2:
                    continue
                if value != value_2:
                    is_difference = True
        if is_difference:
            self.ptdebug(f"Different response between nameservers", Out.VULN)
            return True
        else:
            return False

    def _get_spf_for_ns(self, domain, resolver):
        try:
            result = []
            for dns_type in ["TXT", "SPF"]:
                answer = resolver.resolve(domain, dns_type)
                for rdata in answer:
                    rdata = self._rdata_to_str(rdata)
                    if dns_type == "TXT" and not re.search("v=spf1", rdata):
                        continue
                    result.append(rdata)
                    self.ptdebug(rdata)
        except dns.resolver.NoAnswer as e:
            pass
        except dns.resolver.NoNameservers as e:
            # DNS nameservers failed - return empty result
            return []
        except dns.resolver.Timeout as e:
            raise Exception("Timeout error")
        except Exception as e:
            # Catch any other DNS errors
            self.ptdebug(f"DNS error: {e}", Out.ERROR)
            return []
        return result

    def auth_ntlm(self, smtp: smtplib.SMTP) -> NTLMResult:
        """
        Performs NTLM authentication to extract internal server
        information from server's challenge response.

        Returns:
            NTLMInfo | None: disclosed information, or None in case of failure
        """
        ntlm = None
        try:
            code, resp = smtp.docmd("AUTH NTLM")
            if code == 334:
                smtp.send(b64encode(get_NegotiateMessage_data()) + smtplib.bCRLF)
                code, resp = smtp.getreply()

                ntlm = decode_ChallengeMessage_blob(b64decode(resp))
        except:
            ntlm = None

        if ntlm is None:
            self.ptdebug(
                f"Server is not vulnerable to information disclosure via NTLM authentication",
                Out.NOTVULN,
            )
            return NTLMResult(False, None)
        else:
            self.ptdebug(
                f"Server is vulnerable to information disclosure via NTLM authentication", Out.VULN
            )
            self.ptdebug(f"  Target name: {ntlm.target_name}")
            self.ptdebug(f"  NetBios domain name: {ntlm.netbios_domain}")
            self.ptdebug(f"  NetBios computer name: {ntlm.netbios_computer}")
            self.ptdebug(f"  DNS domain name: {ntlm.dns_domain}")
            self.ptdebug(f"  DNS computer name: {ntlm.dns_computer}")
            self.ptdebug(f"  DNS tree: {ntlm.dns_tree}")
            self.ptdebug(f"  OS version: {ntlm.os_version}")

            return NTLMResult(True, ntlm)

    def test_enumeration(self, smtp: smtplib.SMTP, enumeration_vulns: dict[str, bool | None]):
        if self.args.enumerate is None:
            return None

        if self.args.enumerate == "ALL":
            self.args.enumerate = ["VRFY", "EXPN", "RCPT"]

        try:
            if "EXPN" in self.args.enumerate:
                enumeration_vulns.update({"expn": self.expn_vrfy_test("EXPN", smtp)})
            if "VRFY" in self.args.enumerate:
                enumeration_vulns.update({"vrfy": self.expn_vrfy_test("VRFY", smtp)})
            if "RCPT" in self.args.enumerate:
                enumeration_vulns.update({"rcpt": self.rcpt_test(smtp)})
        except Exception as e:
            msg = (
                f"Connection terminated with server "
                f"{self.args.target.ip}:{self.args.target.port} ({get_mode(self.args)}): {e}"
            )
            self._fail(msg)

    def test_slowdown_enumeration(
        self, smtp: smtplib.SMTP, enumeration_vulns: dict[str, bool | None]
    ):
        if self.args.enumerate is None:
            return None

        # self.prefered_enum_method = None
        self.slow_down_results = {"expn": False, "vrfy": False, "rcpt": False}
        if "EXPN" in self.args.enumerate and enumeration_vulns["expn"]:
            self.slow_down_results.update(self.expn_vrfy_slow_down_test("EXPN", smtp))
        if (
            "VRFY" in self.args.enumerate and enumeration_vulns["vrfy"]
        ):  # and not self.is_slow_down:
            self.slow_down_results.update(self.expn_vrfy_slow_down_test("VRFY", smtp))
        if (
            "RCPT" in self.args.enumerate and enumeration_vulns["rcpt"]
        ):  # and not self.is_slow_down:
            self.slow_down_results.update(self.rcpt_slow_down_test(smtp))

        self.ptdebug("Slow-Down results:", Out.INFO)
        for key, value in self.slow_down_results.items():
            self.ptdebug(f"{key}:{bool(value)}")

    def do_enumeration(
        self, smtp: smtplib.SMTP, enumeration_vulns: dict[str, bool]
    ) -> dict[str, list[str] | None]:
        enumeration_results: dict[str, list[str] | None] = {
            "expn": None,
            "vrfy": None,
            "rcpt": None,
        }
        if enumeration_vulns["expn"]:
            enumeration_results["expn"] = self.expn_vrfy_enumeration("EXPN", smtp)
        elif enumeration_vulns["vrfy"]:
            enumeration_results["vrfy"] = self.expn_vrfy_enumeration("VRFY", smtp)
        elif enumeration_vulns["rcpt"]:
            enumeration_results["rcpt"] = self.rcpt_enumeration(smtp)

        return enumeration_results

    def enumeration(self, smtp: smtplib.SMTP) -> list[EnumResult]:
        enumeration_vulns: dict[str, bool | None] = {
            "expn": None,
            "vrfy": None,
            "rcpt": None,
        }
        enumeration_results = None

        self.test_enumeration(smtp, enumeration_vulns)

        if self.args.slow_down:
            self.test_slowdown_enumeration(smtp, enumeration_vulns)

        if self.wordlist is not None:
            enumeration_results = self.do_enumeration(smtp, enumeration_vulns)

        enum_results: list[EnumResult] = []

        for method in enumeration_vulns.keys():
            if (vulnerable := enumeration_vulns[method]) is not None:
                if self.args.slow_down:
                    slow_down = self.slow_down_results[method]
                else:
                    slow_down = None

                if self.wordlist is not None:
                    wordlist_result = enumeration_results[method]
                else:
                    wordlist_result = None

                enum_results.append(EnumResult(method, vulnerable, slow_down, wordlist_result))

        return enum_results

    def initial_info(self, get_commands: bool = True) -> tuple[smtplib.SMTP, InfoResult]:
        """Connect and get banner; optionally get EHLO (commands). If PLAIN advertises STARTTLS,
        open a new connection to get EHLO after STARTTLS (keeps main connection plain for other tests)."""
        self.ptdebug("Initial server information", title=True)

        smtp, _, reply = self.connect()
        banner = reply.decode()
        self.ptdebug("Banner: " + banner, Out.INFO)

        ehlo = None
        ehlo_starttls = None
        if get_commands:
            try:
                _, ehlo_bytes = smtp.ehlo(self.fqdn)
                ehlo = ehlo_bytes.decode()
                self.ptdebug("EHLO response: " + ehlo, Out.INFO)
            except Exception as e:
                msg = (
                    f"Could not negotiate initial EHLO with "
                    f"{self.args.target.ip}:{self.args.target.port} ({get_mode(self.args)}): {e}"
                )
                self._fail(msg)

            # If on plain connection and server advertises STARTTLS, get EHLO after STARTTLS
            # via a new connection (same manual STARTTLS as test_encryption: no SNI when IP).
            if (
                ehlo
                and "STARTTLS" in ehlo.upper()
                and self.args.target.port != 465
                and not self.args.tls
            ):
                smtp_stls = None
                try:
                    _ssl_ctx = ssl._create_unverified_context()
                    smtp_stls = smtplib.SMTP(timeout=15.0)
                    status, _ = smtp_stls.connect(self.args.target.ip, self.args.target.port)
                    if status != 220:
                        raise Exception("connect failed")
                    status, _ = smtp_stls.docmd("EHLO", self.fqdn)
                    if status != 250:
                        raise Exception("EHLO failed")
                    status, _ = smtp_stls.docmd("STARTTLS")
                    if status != 220:
                        raise Exception("STARTTLS refused")
                    try:
                        _is_ip = ipaddress.ip_address(self.args.target.ip)
                        _sni = None
                    except ValueError:
                        _sni = self.args.target.ip
                    sock_ssl = _ssl_ctx.wrap_socket(smtp_stls.sock, server_hostname=_sni)
                    smtp_stls.sock = sock_ssl
                    smtp_stls.file = None
                    smtp_stls.helo_resp = None
                    smtp_stls.ehlo_resp = None
                    smtp_stls.esmtp_features = {}
                    smtp_stls.does_esmtp = False
                    status, ehlo_st_bytes = smtp_stls.docmd("EHLO", self.fqdn)
                    if status == 250:
                        ehlo_starttls = ehlo_st_bytes.decode()
                        self.ptdebug("EHLO after STARTTLS: " + ehlo_starttls, Out.INFO)
                except Exception as e:
                    self.ptdebug(f"STARTTLS EHLO failed: {e}", Out.INFO)
                finally:
                    if smtp_stls is not None:
                        try:
                            smtp_stls.close()
                        except Exception:
                            pass

        return smtp, InfoResult(banner, ehlo, ehlo_starttls)

    def test_encryption(self) -> EncryptionResult:
        """
        Test which encryption options are available on the target port:
        plaintext, STARTTLS, and implicit TLS (SMTP_SSL).
        Uses fresh connections for each test; does not use self.args.tls/starttls.

        The caller (run() or _run_all_tests()) stores the return value in
        self.results.encryption so that subsequent tests can use it to select
        the appropriate connection type (e.g. prefer STARTTLS when available).
        """
        host = self.args.target.ip
        port = self.args.target.port
        timeout = 10.0
        plaintext_ok = False
        starttls_ok = False
        tls_ok = False

        # Unverified context for availability probe only (server cert may be
        # self-signed or for different hostname). Use _create_unverified_context
        # for maximum compatibility with real-world servers.
        _ssl_ctx = ssl._create_unverified_context()
        # Port 465 is implicit TLS only (SMTPS): skip plaintext and STARTTLS (they would hang/timeout).
        tls_only_port = port == 465

        if not tls_only_port:
            # 1. STARTTLS (plain then upgrade). RFC 3207: EHLO first, then STARTTLS, then EHLO.
            try:
                smtp = smtplib.SMTP(timeout=timeout)
                try:
                    status, _ = smtp.connect(host, port)
                    if status == 220:
                        status, _ = smtp.docmd("EHLO", self.fqdn)
                        if status == 250:
                            status, _ = smtp.docmd("STARTTLS")
                            if status == 220:
                                try:
                                    _is_ip = ipaddress.ip_address(host)
                                    _sni = None
                                except ValueError:
                                    _sni = host
                                sock_ssl = _ssl_ctx.wrap_socket(
                                    smtp.sock, server_hostname=_sni
                                )
                                smtp.sock = sock_ssl
                                smtp.file = None
                                smtp.helo_resp = None
                                smtp.ehlo_resp = None
                                smtp.esmtp_features = {}
                                smtp.does_esmtp = False
                                status, _ = smtp.docmd("EHLO", self.fqdn)
                                starttls_ok = status == 250
                finally:
                    smtp.close()
            except Exception as e:
                self.ptdebug(f"STARTTLS test failed: {e}", Out.INFO)

            time.sleep(2)

            # 2. Plaintext (no TLS)
            try:
                smtp = smtplib.SMTP(timeout=timeout)
                try:
                    status, _ = smtp.connect(host, port)
                    if status == 220:
                        status, _ = smtp.docmd("EHLO", self.fqdn)
                        plaintext_ok = status == 250
                finally:
                    smtp.close()
            except Exception:
                pass

            time.sleep(2)

        # 3. Implicit TLS (port 465 / SMTPS). Connect manually so we control SNI:
        # when connecting by IP use server_hostname=None (many servers have hostname-only certs).
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            try:
                try:
                    ipaddress.ip_address(host)
                    _sni = None
                except ValueError:
                    _sni = host
                sock_ssl = _ssl_ctx.wrap_socket(sock, server_hostname=_sni)
                smtp = smtplib.SMTP(timeout=timeout)
                try:
                    smtp.sock = sock_ssl
                    smtp.file = None
                    (status, _) = smtp.getreply()
                    if status == 220:
                        status, _ = smtp.docmd("EHLO", self.fqdn)
                        tls_ok = status == 250
                finally:
                    smtp.close()
            finally:
                try:
                    sock_ssl.close()
                except Exception:
                    pass
        except Exception:
            pass

        return EncryptionResult(plaintext_ok, starttls_ok, tls_ok)

    def _try_login(self, creds: Creds) -> Creds | None:
        smtp, *_ = self.connect()

        try:
            smtp.login(creds.user, creds.passw)
            result = creds
        except:
            result = None
        finally:
            smtp.close()
            return result

    # endregion

    # region output
    def output(self) -> None:
        properties: dict[str, None | str | int | list[str]] = self.ptjsonlib.json_object["results"][
            "properties"
        ]

        # 1. Banner (separate section)
        if self.results.banner_requested:
            if (info_error := self.results.info_error) is not None:
                self.ptprint("Banner", Out.INFO)
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} {info_error}", Out.TEXT)
                properties["infoError"] = info_error
            elif (info := self.results.info) and info.banner is not None:
                self.ptprint("Banner", Out.INFO)
                sid = identify_service(info.banner)
                if sid is None:
                    icon = get_colored_text("[✓]", color="NOTVULN")
                elif sid.version is not None:
                    icon = get_colored_text("[✗]", color="VULN")
                else:
                    icon = get_colored_text("[!]", color="WARNING")
                self.ptprint(f"    {icon} {info.banner}", Out.TEXT)
                properties["banner"] = info.banner
                # Service identification from banner (product, version, CPE)
                if sid is not None:
                    self.ptprint("Service Identification", Out.INFO)
                    self.ptprint(f"    Product:  {sid.product}", Out.TEXT)
                    self.ptprint(
                        f"    Version:  {sid.version if sid.version else 'unknown'}",
                        Out.TEXT,
                    )
                    self.ptprint(f"    CPE:      {sid.cpe}", Out.TEXT)
                    properties["serviceIdentification"] = {
                        "product": sid.product,
                        "version": sid.version,
                        "cpe": sid.cpe,
                    }

        # 2. EHLO extensions (PLAIN and/or STARTTLS when both available)
        def _print_ehlo_parsed(ehlo_raw: str, connection_encrypted: bool) -> None:
            parsed = _parse_ehlo_commands(ehlo_raw, connection_encrypted=connection_encrypted)
            for display_str, level in parsed:
                if level == "ERROR":
                    icon = get_colored_text("[✗]", color="VULN")
                elif level == "WARNING":
                    icon = get_colored_text("[!]", color="WARNING")
                else:
                    icon = get_colored_text("[✓]", color="NOTVULN")
                self.ptprint(f"    {icon} {display_str}", Out.TEXT)

        if self.results.commands_requested:
            if (info_error := self.results.info_error) is not None:
                self.ptprint("EHLO extensions", Out.INFO)
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} {info_error}", Out.TEXT)
                if "infoError" not in properties:
                    properties["infoError"] = info_error
            elif (info := self.results.info) and info.ehlo is not None:
                ehlo_starttls = getattr(info, "ehlo_starttls", None)
                if ehlo_starttls:
                    # Two sections: PLAIN then STARTTLS (different risk: AUTH OK over TLS)
                    self.ptprint("EHLO extensions (PLAIN)", Out.INFO)
                    if info.ehlo:
                        _print_ehlo_parsed(info.ehlo, connection_encrypted=False)
                    self.ptprint("EHLO extensions (STARTTLS)", Out.INFO)
                    _print_ehlo_parsed(ehlo_starttls, connection_encrypted=True)
                    properties["ehloCommand"] = info.ehlo
                    properties["ehloCommandStarttls"] = ehlo_starttls
                else:
                    # Single section: label by connection type
                    connection_encrypted = (
                        self.args.target.port == 465 or self.args.tls or self.args.starttls
                    )
                    section_label = " (TLS)" if connection_encrypted else " (PLAIN)"
                    self.ptprint(f"EHLO extensions{section_label}", Out.INFO)
                    if info.ehlo:
                        _print_ehlo_parsed(info.ehlo, connection_encrypted=connection_encrypted)
                    # If server advertised STARTTLS but we couldn't get second EHLO, show hint
                    if (
                        not connection_encrypted
                        and "STARTTLS" in (info.ehlo or "").upper()
                        and not getattr(info, "ehlo_starttls", None)
                    ):
                        self.ptprint(
                            "    [*] STARTTLS EHLO not available (second connection or upgrade failed; try -d for debug)",
                            Out.TEXT,
                        )
                    properties["ehloCommand"] = info.ehlo

        # 2. Encryption
        if (encryption_error := self.results.encryption_error) is not None:
            self.ptprint("Encryption", Out.INFO)
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} Encryption test failed: {encryption_error}", Out.TEXT)
            properties["encryptionError"] = encryption_error
        elif (enc := self.results.encryption) is not None:
            self.ptprint("Encryption", Out.INFO)
            plaintext_only = enc.plaintext_ok and not enc.starttls_ok and not enc.tls_ok
            any_ok = enc.plaintext_ok or enc.starttls_ok or enc.tls_ok
            if plaintext_only:
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} Plaintext only", Out.TEXT)
            elif any_ok:
                if enc.plaintext_ok:
                    icon = get_colored_text("[✓]", color="NOTVULN")
                    self.ptprint(f"    {icon} Plaintext", Out.TEXT)
                if enc.starttls_ok:
                    icon = get_colored_text("[✓]", color="NOTVULN")
                    self.ptprint(f"    {icon} STARTTLS", Out.TEXT)
                if enc.tls_ok:
                    icon = get_colored_text("[✓]", color="NOTVULN")
                    self.ptprint(f"    {icon} TLS", Out.TEXT)
            else:
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(
                    f"    {icon} No connection mode available (plaintext, STARTTLS, TLS failed)",
                    Out.TEXT,
                )
            properties["encryption"] = {
                "plaintext": enc.plaintext_ok,
                "starttls": enc.starttls_ok,
                "tls": enc.tls_ok,
            }

        # 3. Open relay
        if (open_relay_error := self.results.open_relay_error) is not None:
            self.ptprint("Open relay", Out.INFO)
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} Open relay test failed: {open_relay_error}", Out.TEXT)
            properties["openRelayError"] = open_relay_error
        elif (open_relay := self.results.open_relay) is not None:
            self.ptprint("Open relay", Out.INFO)
            if open_relay:
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} Open relay is allowed", Out.TEXT)
                self.ptjsonlib.add_vulnerability(VULNS.OpenRelay.value, "Open relay")
            else:
                icon = get_colored_text("[✓]", color="NOTVULN")
                self.ptprint(f"    {icon} Open relay is denied", Out.TEXT)

        # 3a. Catch All mailbox
        if (catch_all := self.results.catch_all) is not None:
            self.ptprint("Catch All mailbox", Out.INFO)
            info_icon = get_colored_text("[*]", color="INFO")
            if catch_all == "configured":
                self.ptprint(f"    {info_icon} Configured", Out.TEXT)
            elif catch_all == "not_configured":
                self.ptprint(f"    {info_icon} Not Configured", Out.TEXT)
            else:
                self.ptprint(f"    {info_icon} Indeterminate", Out.TEXT)
            properties["catchAll"] = catch_all

        # 3b. RCPT TO limit (per message)
        rcptmax_advertised = None
        if (info := getattr(self.results, "info", None)) and getattr(info, "ehlo", None):
            rcptmax_advertised = _parse_rcptmax_from_ehlo(info.ehlo)
        if (rcpt_limit_err := self.results.rcpt_limit_error) is not None:
            self.ptprint("RCPT TO limit", Out.INFO)
            if rcptmax_advertised is not None:
                info_icon = get_colored_text("[*]", color="INFO")
                self.ptprint(
                    f"    {info_icon} Advertised in EHLO (RFC 9422): RCPTMAX={rcptmax_advertised}",
                    Out.TEXT,
                )
                properties["rcptLimitAdvertised"] = rcptmax_advertised
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} Test failed: {rcpt_limit_err}", Out.TEXT)
            properties["rcptLimitError"] = rcpt_limit_err
        elif (rlim := self.results.rcpt_limit) is not None:
            self.ptprint("RCPT TO limit", Out.INFO)
            info_icon = get_colored_text("[*]", color="INFO")
            if rcptmax_advertised is not None:
                self.ptprint(
                    f"    {info_icon} Advertised in EHLO (RFC 9422): RCPTMAX={rcptmax_advertised}",
                    Out.TEXT,
                )
                properties["rcptLimitAdvertised"] = rcptmax_advertised
            if getattr(rlim, "rejected_addresses", False):
                self.ptprint(
                    f"    {info_icon} Could not test: server rejects test addresses (not a count limit)",
                    Out.TEXT,
                )
                if rlim.server_response:
                    for line in rlim.server_response.replace("\r", "").splitlines():
                        self.ptprint(f"        {line}", Out.TEXT)
                self.ptprint(
                    f"    {info_icon} Try -d/--domain <domain> to use a valid recipient domain.",
                    Out.TEXT,
                )
                properties["rcptLimit"] = {"rejectedAddresses": True, "serverResponse": rlim.server_response}
            elif rlim.limit_triggered:
                icon = get_colored_text("[✓]", color="NOTVULN")
                self.ptprint(f"    {icon} Limit enforced after {rlim.max_accepted} recipients", Out.TEXT)
                if rlim.server_response:
                    for line in rlim.server_response.replace("\r", "").splitlines():
                        self.ptprint(f"        {line}", Out.TEXT)
                properties["rcptLimit"] = {"maxAccepted": rlim.max_accepted, "limitTriggered": True}
            else:
                if rlim.max_accepted == 0:
                    self.ptprint(
                        f"    {info_icon} Could not test: no recipients accepted",
                        Out.TEXT,
                    )
                    if rlim.server_response:
                        for line in rlim.server_response.replace("\r", "").splitlines():
                            self.ptprint(f"        {line}", Out.TEXT)
                    self.ptprint(
                        f"    {info_icon} Try -d/--domain <domain> to use a valid recipient domain.",
                        Out.TEXT,
                    )
                    properties["rcptLimit"] = {"maxAccepted": 0, "limitTriggered": False, "couldNotTest": True}
                else:
                    icon = get_colored_text("[✗]", color="VULN")
                    self.ptprint(
                        f"    {icon} No limit or too high: {rlim.max_accepted} recipients accepted",
                        Out.TEXT,
                    )
                    properties["rcptLimit"] = {"maxAccepted": rlim.max_accepted, "limitTriggered": False}

        # 4. Blacklist information
        if (blacklist_error := self.results.blacklist_error) is not None:
            self.ptprint("Blacklist information", Out.INFO)
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} Blacklist test failed: {blacklist_error}", Out.TEXT)
            properties["blacklistError"] = blacklist_error
        elif self.results.blacklist_private_ip_skipped:
            self.ptprint("Blacklist information", Out.INFO)
            # Print as plain text to control spacing after the [*] icon
            info_icon = get_colored_text("[*]", color="INFO")
            self.ptprint(
                f"    {info_icon}Private/internal IP - blacklist check not applicable (addresses in private ranges are not listed on public blacklists)",
                Out.TEXT,
            )
        elif blacklist := self.results.blacklist:
            self.ptprint("Blacklist information", Out.INFO)
            if not blacklist.listed:
                icon = get_colored_text("[✓]", color="NOTVULN")
                self.ptprint(f"    {icon} Clean", Out.TEXT)
            else:
                icon = get_colored_text("[✗]", color="VULN")
                json_lines: list[str] = []
                if (results := blacklist.results) is not None:
                    for r in results:
                        r_str = f'{r.blacklist.strip()}: "{r.reason}" (TTL={r.ttl})'
                        self.ptprint(f"    {icon} {r_str}", Out.TEXT)
                        json_lines.append(r_str)

                    if len(json_lines) > 0:
                        self.ptjsonlib.add_vulnerability(
                            VULNS.Blacklist.value,
                            f"blacklists containing target {self.target}",
                            "\n".join(json_lines),
                        )

        # 5. SPF records
        if self.results.spf_requires_domain:
            self.ptprint("SPF records", Out.INFO)
            info_icon = get_colored_text("[*]", color="INFO")
            self.ptprint(
                f"    {info_icon} Test requires target specified by a domain name",
                Out.TEXT,
            )
        elif (spf_error := self.results.spf_error) is not None:
            self.ptprint("SPF records", Out.INFO)
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} SPF test failed: {spf_error}", Out.TEXT)
            properties["spfError"] = spf_error
        elif (spf_records := self.results.spf_records) is not None:
            self.ptprint("SPF records", Out.INFO)

            json_lines = []
            for ns, records in spf_records.items():
                info_icon = get_colored_text("[*]", color="INFO")
                self.ptprint(f"    {info_icon} Nameserver {ns}", Out.TEXT)
                for r in records:
                    self.ptprint(f"        {r}")
                    json_lines.append(f"[{ns}] {r}")

            if len(json_lines) > 0:
                properties["spfRecords"] = "\n".join(json_lines)

        # 6. User enumeration methods
        if (enum_error := self.results.enum_error) is not None:
            self.ptprint("User enumeration methods", Out.INFO)
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} Enumeration test failed: {enum_error}", Out.TEXT)
            properties["enumerationError"] = enum_error
        elif (enum_results := self.results.enum_results) is not None:
            self.ptprint("User enumeration methods", Out.INFO)

            if self.args.enumerate is None:
                requested_set = {"EXPN", "VRFY", "RCPT"}
            elif isinstance(self.args.enumerate, list):
                requested_set = {m.upper() for m in self.args.enumerate if m}
            else:
                requested_set = {self.args.enumerate.upper()} if self.args.enumerate else {"EXPN", "VRFY", "RCPT"}

            filtered = [e for e in enum_results if e.method.upper() in requested_set]

            for e in filtered:
                if e.slowdown is not None:
                    slowdown = " (rate limited)" if e.slowdown else " (not rate limited)"
                else:
                    slowdown = ""
                status = "is enabled" if e.vulnerable else "is deny"
                icon = get_colored_text("[✗]", color="VULN") if e.vulnerable else get_colored_text("[✓]", color="NOTVULN")
                method_upper = e.method.upper()
                out_str = f'{icon} {method_upper} method {status}{slowdown}'
                self.ptprint(f"    {out_str}", Out.TEXT)

            json_lines = []
            for e in filtered:
                out_str = f'{get_colored_text("[✗]" if e.vulnerable else "[✓]", color="VULN" if e.vulnerable else "NOTVULN")} {e.method.upper()} method {"is enabled" if e.vulnerable else "is deny"}'
                if e.vulnerable:
                    json_lines.append(out_str)
                if e.vulnerable and (results := e.results) is not None:
                    sorted_results = sorted(results, key=str)
                    email_count = sum(1 for r in sorted_results if "@" in str(r))
                    out_str = f"Enumerated {email_count} users"
                    self.ptprint(out_str, Out.INFO)
                    json_lines.append(out_str)
                    for r in sorted_results:
                        self.ptprint(f"    {r}")
                        json_lines.append(r)

            if len(json_lines) > 0:
                req = f"enumeration methods: {self.args.enumerate}"
                if self.args.wordlist is not None:
                    req += f"\nwordlist used: {self.args.wordlist}"

                self.ptjsonlib.add_vulnerability(VULNS.UserEnum.value, req, "\n".join(json_lines))

        # 6. NTLM information
        if (ntlm_error := self.results.ntlm_error) is not None:
            self.ptprint("NTLM information", Out.INFO)
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} NTLM test failed: {ntlm_error}", Out.TEXT)
            properties["ntlmError"] = ntlm_error
        elif ntlm := self.results.ntlm:
            self.ptprint("NTLM information", Out.INFO)
            if not ntlm.success:
                icon = get_colored_text("[✓]", color="NOTVULN")
                self.ptprint(f"    {icon} Not available", Out.TEXT)
                properties["ntlmInfoStatus"] = "failed"
            elif ntlm.ntlm is not None:
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} NTLM information", Out.TEXT)
                properties["ntlmInfoStatus"] = "ok"

                out_lines: list[str] = []
                out_lines.append(f"Target name: {ntlm.ntlm.target_name}")
                out_lines.append(f"NetBios domain name: {ntlm.ntlm.netbios_domain}")
                out_lines.append(f"NetBios computer name: {ntlm.ntlm.netbios_computer}")
                out_lines.append(f"DNS domain name: {ntlm.ntlm.dns_domain}")
                out_lines.append(f"DNS computer name: {ntlm.ntlm.dns_computer}")
                out_lines.append(f"DNS tree: {ntlm.ntlm.dns_tree}")
                out_lines.append(f"OS version: {ntlm.ntlm.os_version}")

                for line in out_lines:
                    for part in (line or "").replace("\r", "").splitlines():
                        self.ptprint(f"        {part}", Out.TEXT)

                self.ptjsonlib.add_vulnerability(
                    VULNS.NTLM.value, "ntlm authentication", "\n".join(out_lines)
                )

        # 7. Connections
        if (max_connections_error := self.results.max_connections_error) is not None:
            self.ptprint("Connections", Out.INFO)
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} Max connections test failed: {max_connections_error}", Out.TEXT)
            properties["maxConnectionsError"] = max_connections_error
        elif max_con := self.results.max_connections:
            if max_con.max is None:
                self.ptprint("Maximum connections: no limit found", Out.VULN)
                properties["maxConnections"] = None
            else:
                self.ptprint("Connections", Out.INFO)
                
                # Max connections per IP evaluation
                if max_con.max < 50:
                    icon = get_colored_text("[✓]", color="NOTVULN")
                    status_text = ""
                elif max_con.max < 100:
                    icon = get_colored_text("[!]", color="WARNING")
                    status_text = " (high value)"
                else:  # >= 100
                    icon = get_colored_text("[✗]", color="VULN")
                    status_text = " (high value)"
                
                self.ptprint(f"    {icon} Max connections per IP: {max_con.max}{status_text}", Out.TEXT)
                properties["maxConnections"] = max_con.max

                # Timeout evaluation
                if max_con.ban_minutes is None:
                    icon = get_colored_text("[✓]", color="NOTVULN")
                    self.ptprint(f"    {icon} Timeout: not detected", Out.TEXT)
                    properties["banDuration"] = None
                else:
                    if max_con.ban_minutes < 10:
                        icon = get_colored_text("[✓]", color="NOTVULN")
                        status_text = ""
                    else:  # >= 10
                        icon = get_colored_text("[✗]", color="VULN")
                        status_text = " (high value)"
                    
                    # Format timeout: show as "X.X min"
                    timeout_str = f"{max_con.ban_minutes:.1f} min"
                    self.ptprint(f"    {icon} Timeout: {timeout_str}{status_text}", Out.TEXT)
                    properties["banDuration"] = max_con.ban_minutes

        # Login bruteforce
        if (creds := self.results.creds) is not None:
            self.ptprint(f"Login bruteforce: {len(creds)} valid credentials", Out.INFO)

            if len(creds) > 0:
                json_lines: list[str] = []
                for cred in creds:
                    cred_str = f"user: {cred.user}, password: {cred.passw}"

                    self.ptprint(f"    {cred_str}")
                    json_lines.append(cred_str)

                if self.args.user is not None:
                    user_str = f"username: {self.args.user}"
                else:
                    user_str = f"usernames: {self.args.users}"

                if self.args.password is not None:
                    passw_str = f"password: {self.args.password}"
                else:
                    passw_str = f"passwords: {self.args.passwords}"

                self.ptjsonlib.add_vulnerability(
                    VULNS.WeakCreds.value,
                    f"{user_str}\n{passw_str}",
                    "\n".join(json_lines),
                )

        self.ptjsonlib.set_status("finished", "")
        self.ptprint(self.ptjsonlib.get_result_json(), json=True)


# endregion
