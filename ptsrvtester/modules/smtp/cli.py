import argparse


try:
    from ntlm_auth.ntlm import NtlmContext
except ImportError:
    NtlmContext = None

from ..utils.ptprinthelper import get_colored_text
from ..utils.helpers import Target, ArgsWithBruteforce, add_bruteforce_args

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False


from .helpers import *
from .results import *
from .registry import *

__all__ = ['SMTPArgs']



class SMTPArgs(ArgsWithBruteforce):
    tests: str | None
    target: Target
    tls: bool
    starttls: bool
    ntlm: bool
    mail_from: str | None
    rcpt_to: str | None
    fqdn: str | None
    enumerate: list[str] | str | None
    blacklist_test: bool
    rate_limit: bool
    noop_flood1: bool
    noop_flood2: int | None
    slow_down: bool
    spf_test: bool
    open_relay: bool
    interactive: bool
    isencrypt: bool
    role_identify: bool
    smtp_role: str | None
    probe_accepted_domain: bool
    rcpt_duplicate: int | None
    send: bool
    smtp_subject: str | None
    smtp_data: str | None

    @staticmethod
    def get_help():
        # Test selection table (-ts): one code + one-line description per test.
        options: list[list[str]] = [
            ["-ts", "--tests", "<test>", "One or more tests, comma-separated (e.g. BANNER,AV); ALL runs everything:"],
        ]
        for group_title, codes in SMTP_TEST_GROUPS:
            options.append(["", "", "", ""])
            options.append(["", "", get_colored_text(group_title, "TITLE")])
            for code in codes:
                options.append(["", "", code, SMTP_TESTS[code]["desc"]])

        # Global options (test-specific modifiers live in `smtp -ts <TEST> -h`).
        options += [
            ["", "", "", ""],
            [get_colored_text("Connection", "TITLE")],
            ["", "--tls", "", "Use implicit SSL/TLS (default port 465)"],
            ["", "--starttls", "", "Use explicit STARTTLS (default port 587)"],
            ["-f", "--fqdn", "<fqdn>", "FQDN for EHLO/HELO (default: from target or hostname)"],
            ["", "", "", ""],
            [get_colored_text("Message (outbound tests)", "TITLE")],
            ["", "--send", "", "Actually deliver test messages (DATA); required by delivery tests"],
            ["-m", "--mail-from", "<email>", "Envelope sender (MAIL FROM)"],
            ["-r", "--rcpt-to", "<email>", "Recipient (To)"],
            ["-cc", "--cc", "<emails>", "CC recipients (comma-separated)"],
            ["-fn", "--from-name", "<name>", "Display name in From header"],
            ["", "--subject", "<text>", f"Message subject (default: {DEFAULT_SMTP_SUBJECT!r})"],
            ["", "--data", "<text>", f"Message body (default: {DEFAULT_SMTP_DATA!r})"],
            ["", "", "", ""],
            [get_colored_text("Credentials", "TITLE")],
            ["-u", "--user", "<name> …", "Username(s) for BRUTE / ENUM"],
            ["-U", "--users", "<wordlist>", "Username wordlist"],
            ["-p", "--password", "<password>", "Password for BRUTE"],
            ["-P", "--passwords", "<wordlist>", "Password wordlist"],
            ["", "", "", ""],
            [get_colored_text("Targeting & misc", "TITLE")],
            ["-t", "--threads", "<n>", "Threads for enumeration (default: 1)"],
            ["-d", "--domain", "<domain>", "Recipient domain for RCPT limit tests"],
            ["-R", "--role", "<mta|submission>", "Expected server role"],
            ["", "", "", ""],
            [get_colored_text("Output", "TITLE")],
            ["-j", "--json", "", "Output in JSON format"],
            ["-vv", "--verbose", "", "Enable verbose mode"],
            ["-v", "--version", "", "Show version and exit"],
            ["-h", "--help", "", "Show this help; 'smtp -ts <TEST> -h' for test options"],
        ]

        return [
            {"description": ["SMTP Testing Module"]},
            {"usage": ["ptsrvtester smtp -ts <test>[,<test>...] <options> <target>"]},
            {"usage_example": [
                "ptsrvtester smtp -ts BANNER,EHLO mail.example.com:25",
                "ptsrvtester smtp -ts ALL mail.example.com:25",
                "ptsrvtester smtp -ts OPENREL mail.example.com:25",
                "ptsrvtester smtp -ts BOUNCE -m attacker@example.com -r foo@foo.com smtp.example.com:25",
                "ptsrvtester smtp -ts BOMB -r victim@example.com smtp.example.com:587",
                "ptsrvtester smtp -ts AV,SSRF,ZIPXXE -r victim@example.com --ssrf-canary-url http://cb --zipxxe-canary-url http://cb smtp.example.com:25",
                "ptsrvtester smtp -ts ENUM -e ALL -U wordlist.txt mail.example.com:25",
                "ptsrvtester smtp -ts SPOOF -r victim@example.com smtp.example.com:25",
                "ptsrvtester smtp -ts BCC -r to@example.com --cc cc@example.com --bcc bcc@example.com smtp.example.com:25",
                "ptsrvtester smtp -ts AV -h",
            ]},
            {"options": options},
        ]

    @staticmethod
    def get_test_help(codes):
        """Per-test help object (used by `smtp -ts <TEST> -h`)."""
        return _smtp_test_help(codes)

    def add_subparser(self, name: str, subparsers) -> None:
        examples = """example usage:
  ptsrvtester smtp -h
  ptsrvtester smtp -ts BANNER,EHLO mail.example.com:25
  ptsrvtester smtp -ts ALL mail.example.com:25
  ptsrvtester smtp -ts ENUM -e ALL -U wordlist.txt mail.example.com:25
  ptsrvtester smtp -ts BOUNCE -m attacker@example.com -r foo@foo.com smtp.example.com:25
  ptsrvtester smtp -ts BOMB -r victim@example.com smtp.example.com:587
  ptsrvtester smtp -ts AV -r victim@example.com smtp.example.com:587
  ptsrvtester smtp -ts SSRF -r victim@example.com --ssrf-canary-url https://xyz.oast.fun/ssrf smtp.example.com:587
  ptsrvtester smtp -ts AV,SSRF,ZIPXXE -r victim@example.com --ssrf-canary-url http://cb --zipxxe-canary-url http://cb smtp.example.com:25
  ptsrvtester smtp -ts SPOOF -r victim@example.com -u user -p pass smtp.example.com:587
  ptsrvtester smtp -ts BCC -r to@example.com --cc cc@example.com --bcc bcc@example.com smtp.example.com:25
  ptsrvtester smtp -ts AV -h"""

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
        parser.add_argument("-f", "--fqdn", type=str, metavar="fqdn", help="FQDN for EHLO/HELO (default: from target or system hostname)")

        direct = parser.add_argument_group(
            "DIRECT SCANNING", "Operations that communicate directly with the target server"
        )
        direct.add_argument(
            "-ts",
            "--tests",
            type=str,
            default=None,
            metavar="<test>",
            dest="tests",
            help="Comma-separated test codes (e.g. BANNER,AV) or ALL; 'smtp -ts <TEST> -h' for test options",
        )
        direct.add_argument(
            "-m", "--mail-from", type=str,
            help=(
                "Sender address (MAIL FROM); used by BOMB, AV, BOUNCE (default: bombtest/avtest@{fqdn} when not set). "
                "Required for RCPTLIM with --send (envelope MAIL FROM for delivery). "
                "Optional with RCPTLIM: envelope MAIL FROM for RCPT probes and accept-all pre-probe "
                "(default <> when omitted)."
            ),
        )
        direct.add_argument(
            "-r", "--rcpt-to", type=str,
            help="Recipient address (RCPT TO); required for BOMB, AV, SSRF, ZIPXXE, SPOOF, BOUNCE, RCPTDUP",
        )
        direct.add_argument(
            "-fn",
            "--from-name",
            type=str,
            metavar="name",
            dest="from_name",
            default=None,
            help="Sender display name in From header; used by BOMB, AV, SSRF, ZIPXXE (no validation)",
        )
        direct.add_argument(
            "-cc",
            "--cc",
            type=str,
            metavar="emails",
            dest="cc",
            default=None,
            help="Cc recipients, comma-separated; used by BOMB, AV, SSRF; required for BCC (no validation)",
        )
        direct.add_argument(
            "--subject",
            type=str,
            metavar="text",
            dest="smtp_subject",
            default=None,
            help=f"Subject line for outbound test messages (default: {DEFAULT_SMTP_SUBJECT!r})",
        )
        direct.add_argument(
            "--send",
            action="store_true",
            dest="send",
            default=False,
            help=(
                "Actually deliver the test message(s) via DATA. Required for delivery tests "
                "(BCC, SPOOF, BOUNCE, BOMB, FLOOD, AV, SSRF, ZIPXXE, ALIAS); also enables the "
                "optional DATA step for RCPTLIM and RCPTDUP. Without it these tests are refused "
                "or run without sending."
            ),
        )
        direct.add_argument(
            "--data",
            type=str,
            metavar="text",
            dest="smtp_data",
            default=None,
            help=f"Plain-text body for outbound test messages (default: {DEFAULT_SMTP_DATA!r})",
        )
        direct.add_argument(
            "--spoof-variants",
            type=str,
            metavar="v1,v2,...",
            dest="spoofhdr_variants",
            default=None,
            help="Spoof headers variants: from,reply_to,return_path (default: all); -r recipient, -m envelope (MAIL FROM)",
        )
        direct.add_argument(
            "--spoof-timeout",
            type=float,
            default=30.0,
            metavar="sec",
            dest="spoofhdr_timeout",
            help="Timeout per message for Spoof headers test (default: 30)",
        )
        direct.add_argument(
            "-bcc",
            "--bcc",
            type=str,
            metavar="<emails>",
            dest="bcc_test",
            default=None,
            help="Bcc recipients, comma-separated (used by -ts BCC)",
        )
        direct.add_argument(
            "--bcc-timeout",
            type=float,
            default=30.0,
            metavar="sec",
            dest="bcc_timeout",
            help="Timeout for Bcc test (default: 30)",
        )
        direct.add_argument(
            "--alias-variants",
            type=str,
            metavar="v1,v2,...",
            dest="alias_variants",
            default=None,
            help="Alias variants: case,dotted,plus,percent,bang_simple,bang_nested (default: all)",
        )
        direct.add_argument(
            "--alias-timeout",
            type=float,
            default=30.0,
            metavar="sec",
            dest="alias_timeout",
            help="Timeout per variant for Alias test (default: 30)",
        )
        direct.add_argument(
            "-t",
            "--threads",
            type=int,
            default=1,
            metavar="threads",
            dest="enum_threads",
            help="Threads for enumeration (default: 1)",
        )
        direct.add_argument(
            "--enum-reconnect-after",
            type=int,
            default=None,
            metavar="N",
            dest="enum_reconnect_after",
            help="Reconnect after a successful find and after N consecutive failed attempts "
                 "during enumeration. Combats teergrube (server-side accumulated delays). "
                 "Without this flag no extra reconnects are performed (default: disabled).",
        )
        direct.add_argument(
            "-e",
            "--enumerate",
            "--enum-methods",
            type=str,
            choices=["VRFY", "EXPN", "RCPT", "ALL"],
            nargs="?",
            const="ALL",
            default=None,
            dest="enumerate",
            help="User enumeration [VRFY/EXPN/RCPT/ALL] (default: ALL)",
        )
        direct.add_argument(
            "-sd",
            "--slow-down",
            action="store_true",
            help="Test against slow-down protection during enumeration (requires -e)",
        )
        direct.add_argument(
            "-rt", "--rate-limit",
            nargs="?",
            type=int,
            const=RATE_LIMIT_DEFAULT_ATTEMPTS,
            default=None,
            metavar="N",
            help=(
                "Rate limiting test (N = max simultaneous connections to attempt, "
                f"default: {RATE_LIMIT_DEFAULT_ATTEMPTS})"
            ),
        )
        direct.add_argument(
            "-nf2", "--noop-flood2",
            nargs="?",
            type=int,
            const=NOOP_FLOOD2_DEFAULT_CONNECTIONS,
            default=None,
            metavar="N",
            dest="noop_flood2",
            help=(
                "NOOP flooding DoS test across N parallel connections (default: "
                f"{NOOP_FLOOD2_DEFAULT_CONNECTIONS}). Each thread hammers the server with NOOPs "
                "for a fixed window; reports per-command reaction time and error rate."
            ),
        )
        direct.add_argument(
            "-rl", "--recipient-limit",
            nargs="?",
            type=int,
            const=1000,
            default=None,
            metavar="N",
            dest="rcpt_limit",
            help=(
                "Test RCPT TO per-message limit (without -u/-U generates 1000 random recipients; "
                "-m/--mail-from optional as envelope MAIL FROM, default <>). "
                f"N = max RCPT attempts per session (default: {RCPT_LIMIT_DEFAULT_ATTEMPTS})."
            ),
        )
        direct.add_argument(
            "--rl-no-precheck",
            action="store_true",
            dest="rl_no_precheck",
            help=(
                "Skip the role/open-relay/AUTH pre-check before -rl and run the RCPT TO probe directly "
                "(use for regression testing or when the server context is already known)"
            ),
        )
        direct.add_argument(
            "-rdd",
            "--rcpt-duplicate",
            nargs="?",
            type=int,
            const=RCPT_DUP_DEFAULT,
            default=None,
            metavar="N",
            dest="rcpt_duplicate",
            help=(
                "Send RCPT TO repeatedly for the same recipient in one MAIL transaction "
                f"(N times, default {RCPT_DUP_DEFAULT}, max {RCPT_DUP_MAX}; requires -r/--rcpt-to). "
                "SMTP acceptance does not prove N mailbox deliveries — use --send for a minimal "
                "message and verify the inbox manually."
            ),
        )
        direct.add_argument(
            "-d", "--domain",
            type=str,
            metavar="domain",
            default=None,
            help="Recipient domain for RCPT TO limit test (default: from server banner/EHLO)",
        )
        direct.add_argument(
            "-R",
            "--role",
            type=_normalize_smtp_role,
            default=None,
            metavar="{mta,submission}",
            dest="smtp_role",
            help="Role of SMTP server (MTA or Submission); overrides port-based MTA/Submission hint",
        )

        add_bruteforce_args(parser, user_nargs="+", mutually_exclusive_user_and_users=False)

        stress = parser.add_argument_group(
            "BOMB / ANTIVIRUS / SSRF / FLOOD / ZIPXXE",
            "Stress and content tests; combine flags (order: BOMB → ANTIVIRUS → SSRF → FLOOD → ZIPXXE).",
        )
        stress.add_argument(
            "--bomb-count",
            type=int,
            default=100,
            metavar="n",
            dest="bomb_count",
            help="Number of messages to send (default: 100)",
        )
        stress.add_argument(
            "--bomb-timeout",
            type=float,
            default=60.0,
            metavar="sec",
            dest="bomb_timeout",
            help="Max time for entire BOMB test in seconds (default: 60)",
        )
        stress.add_argument(
            "--bomb-delay",
            type=float,
            default=0.0,
            metavar="sec",
            dest="bomb_delay",
            help="Delay between messages in seconds (default: 0)",
        )
        stress.add_argument(
            "--bomb-threads",
            type=int,
            default=1,
            metavar="n",
            dest="bomb_threads",
            help="Parallel threads for flooding (default: 1)",
        )
        stress.add_argument(
            "--bomb-randomize",
            action="store_true",
            dest="bomb_randomize",
            help="Add unique ID to each message (bypass antispam duplicate detection)",
        )
        stress.add_argument(
            "--av-categories",
            type=str,
            metavar="cat1,cat2,...",
            dest="antivirus_categories",
            default=None,
            help="Comma-separated categories (default: all except zip_bomb). Available: eicar, double_ext, executable, nested_archive, encoded_content, html_sanitization, xxe, mime_malformed. Use --av-zip-bomb for zip_bomb.",
        )
        stress.add_argument(
            "--av-zip-bomb",
            action="store_true",
            dest="antivirus_zip_bomb",
            help="Include zip_bomb category (DoS risk! Use with caution)",
        )
        stress.add_argument(
            "--av-timeout",
            type=float,
            default=30.0,
            metavar="sec",
            dest="antivirus_timeout",
            help="Timeout per message for antivirus test in seconds (default: 30)",
        )
        stress.add_argument(
            "--av-skip-absent",
            action="store_true",
            dest="antivirus_skip_absent",
            help="Skip categories that have no definition files",
        )
        stress.add_argument(
            "--ssrf-canary-url",
            type=str,
            metavar="URL",
            dest="ssrf_canary_url",
            default=None,
            help="Canary/callback URL to embed in test emails (required for SSRF; use Interactsh, ngrok, Burp Collaborator)",
        )
        stress.add_argument(
            "--ssrf-variants",
            type=str,
            metavar="v1,v2,...",
            dest="ssrf_variants",
            default=None,
            help="SSRF variants: plain, html_link, html_img, html_iframe, multipart, ssrf_malformed, ssrf_nested (default: all)",
        )
        stress.add_argument(
            "--ssrf-internal-urls",
            action="store_true",
            dest="ssrf_internal_urls",
            help="Also send messages with http://127.0.0.1, localhost, 10.0.0.1 (detection on MTA host only)",
        )
        stress.add_argument(
            "--ssrf-timeout",
            type=float,
            default=30.0,
            metavar="sec",
            dest="ssrf_timeout",
            help="Timeout per message for SSRF test (default: 30)",
        )
        stress.add_argument(
            "--flood-count",
            type=int,
            default=150,
            metavar="n",
            dest="flood_count",
            help="Messages for queue stress (default: 150, max 500). Stops on 421 (panic).",
        )
        stress.add_argument(
            "--flood-timeout",
            type=float,
            default=90.0,
            metavar="sec",
            dest="flood_timeout",
            help="Max time for queue stress in seconds (default: 90)",
        )
        stress.add_argument(
            "--flood-skip-size-test",
            action="store_true",
            dest="flood_skip_size_test",
            help="Skip MAIL FROM SIZE=oversized test (SIZE_ENFORCEMENT phase)",
        )
        stress.add_argument(
            "--zipxxe-canary-url",
            type=str,
            metavar="URL",
            dest="zipxxe_canary_url",
            default=None,
            help="Canary URL for XXE variants (required for xxe_zip, xxe_docx; use Interactsh, ngrok, Burp Collaborator)",
        )
        stress.add_argument(
            "--zipxxe-variants",
            type=str,
            metavar="v1,v2,...",
            dest="zipxxe_variants",
            default=None,
            help="ZIPXXE variants: billion_laughs_attach,billion_laughs_body,xxe_zip,xxe_docx,xxe_body (default: all). Use --zipxxe-canary-url for xxe_*.",
        )
        stress.add_argument(
            "--zipxxe-zip-bomb",
            action="store_true",
            dest="zipxxe_zip_bomb",
            help="Include zip_bomb variant (minimal ~200KB; DoS risk!)",
        )
        stress.add_argument(
            "--zipxxe-zip-bomb-full",
            action="store_true",
            dest="zipxxe_zip_bomb_full",
            help="Include zip_bomb_full variant (~100KB→~100MB expansion; extreme DoS risk!)",
        )
        stress.add_argument(
            "--zipxxe-timeout",
            type=float,
            default=30.0,
            metavar="sec",
            dest="zipxxe_timeout",
            help="Timeout per message for ZIPXXE test (default: 30)",
        )


# endregion
