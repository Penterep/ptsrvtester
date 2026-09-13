"""IMAP CLI — argparse namespace and help (selection is discovery-based)."""
from __future__ import annotations

import argparse

from .capa import valid_target_imap
from .helpers import ArgsWithBruteforce, Target, add_bruteforce_args, check_if_brute, one_cli_user
from .ptprinthelper import get_colored_text
from .registry import IMAP_TEST_GROUPS, IMAP_TESTS, imap_test_help
from ptsrvtester.protocols._shared.utils.cli import rate_limit_help_rows
from .results import (
    _IMAP_LOAD_APPEND_MAX_DEFAULT,
    _IMAP_LOAD_SEARCH_MAX_DEFAULT,
    _IMAP_USRENUM_DEFAULT_PASSWORD,
)

__all__ = ["IMAPArgs"]


class IMAPArgs(ArgsWithBruteforce):
    target: Target
    tls: bool
    starttls: bool
    tests: str | None
    module_threads: int
    mailbox: str
    canary_url: str | None
    xxe_timeout: float
    zipbomb_variant_small: bool
    zipbomb_variant_medium: bool
    zipbomb_variant_huge: bool
    imap_usrenum_password: str | None
    imap_usrenum_max: int
    imap_resource_load_append_max: int
    imap_resource_load_search_max: int
    imap_mailbox_iso_foreign_user: str

    @staticmethod
    def get_help():
        options: list[list[str]] = [
            ["-ts", "--tests", "<test>", "One or more tests, comma-separated (e.g. BANNER,CAPA); ALL = default suite:"],
        ]
        for group_title, codes in IMAP_TEST_GROUPS:
            options.append(["", "", "", ""])
            options.append(["", "", get_colored_text(group_title, "TITLE")])
            for code in codes:
                options.append(["", "", code, IMAP_TESTS[code]["desc"]])

        options += [
            ["", "", "", ""],
            [get_colored_text("Connection", "TITLE")],
            ["-tg", "--target", "<host>", "Target IP[:PORT] or HOST[:PORT]"],
            ["", "--tls", "", "Use implicit SSL/TLS (default port 993)"],
            ["", "--starttls", "", "Use explicit STARTTLS (default port 143)"],
            ["", "", "", ""],
            [get_colored_text("Credentials (BRUTE / authenticated tests)", "TITLE")],
            ["-u", "--user", "<name> …", "Username(s) for BRUTE / USRENUM"],
            ["-U", "--users", "<wordlist>", "Username wordlist"],
            ["-p", "--password", "<password>", "Single password"],
            ["-P", "--passwords", "<wordlist>", "Password wordlist"],
            ["", "--mailbox", "<name>", "IMAP Folder"],
            ["", "--spray", "", "Try one password against all users"],
            ["", "--brute-threads", "<n>", "Threads for bruteforce (default: 10)"],
            *rate_limit_help_rows(get_colored_text),
            ["", "", "", ""],
            [get_colored_text("Output", "TITLE")],
            ["-j", "--json", "", "Output in JSON format"],
            ["-vv", "--verbose", "", "Enable verbose mode"],
            ["-h", "--help", "", "Show this help; 'imap -ts <TEST> -h' for test options"],
        ]

        return [
            {"description": ["IMAP Testing Module"]},
            {"usage": ["ptsrvtester imap -ts <test>[,<test>...] <options> -tg <target>"]},
            {"usage_example": [
                "ptsrvtester imap -ts BANNER,CAPA -tg 127.0.0.1",
                "ptsrvtester imap -ts ALL -tg 127.0.0.1",
                "ptsrvtester imap -ts ALL --tls -tg 127.0.0.1:993",
                "ptsrvtester imap -ts AUTHLIST -tg 127.0.0.1:143",
                "ptsrvtester imap -ts SNIFF -u user -p pass -tg 127.0.0.1:143",
                "ptsrvtester imap -ts EICAR -u user -p pass -tg 127.0.0.1:143",
                "ptsrvtester imap -ts XXESSRF -u user -p pass --canary-url http://cb -tg 127.0.0.1:143",
                "ptsrvtester imap -ts XXEEXP -u user -p pass -tg 127.0.0.1:143",
                "ptsrvtester imap -ts ZIPBOMB -u user -p pass -tg 127.0.0.1:143",
                "ptsrvtester imap -ts ZIPBOMB -u user -p pass --variant-huge -tg 127.0.0.1:143",
                "ptsrvtester imap -ts USRENUM -U users.txt -t 4 -tg 127.0.0.1:143",
                "ptsrvtester imap -ts USRENUM -u admin harry tereza -tg 127.0.0.1:143",
                "ptsrvtester imap -ts TLSAUDIT -tg mail.example.com:993",
                "ptsrvtester imap -ts RATELIMIT -tg 127.0.0.1",
                "ptsrvtester imap -ts BRUTE -u admin -P passwords.txt -tg 127.0.0.1:143",
                "ptsrvtester imap -ts USRENUM -h",
            ]},
            {"options": options},
        ]

    @staticmethod
    def get_test_help(codes):
        return imap_test_help(codes)

    def add_subparser(self, name: str, subparsers) -> None:
        examples = """example usage:
  ptsrvtester imap -h
  ptsrvtester imap -ts BANNER,CAPA -tg 127.0.0.1
  ptsrvtester imap -ts ALL -tg 127.0.0.1
  ptsrvtester imap -ts ALL --tls -tg 127.0.0.1:993
  ptsrvtester imap -ts AUTHLIST -tg 127.0.0.1:143
  ptsrvtester imap -ts SNIFF -u user -p pass -tg 127.0.0.1:143
  ptsrvtester imap -ts CONNLIM --count 50 -t 10 --duration 60 -tg mail.example.com
  ptsrvtester imap -ts EICAR -u user -p pass -tg 127.0.0.1:143
  ptsrvtester imap -ts XXESSRF -u user -p pass --canary-url http://cb -tg 127.0.0.1:143
  ptsrvtester imap -ts XXEEXP -u user -p pass -tg 127.0.0.1:143
  ptsrvtester imap -ts ZIPBOMB -u user -p pass -tg 127.0.0.1:143
  ptsrvtester imap -ts ZIPBOMB -u user -p pass --variant-huge -tg 127.0.0.1:143
  ptsrvtester imap -ts RESLOAD -u user -p pass -tg 127.0.0.1:143
  ptsrvtester imap -ts MBOXISO -u user -p pass -tg 127.0.0.1:143
  ptsrvtester imap -ts TLSAUDIT -tg mail.example.com:993
  ptsrvtester imap -ts USRENUM -U users.txt -t 4 -tg 127.0.0.1:143
  ptsrvtester imap -ts USRENUM -u admin harry tereza -tg 127.0.0.1:143
  ptsrvtester imap -ts USRENUMPLAIN -U users.txt -tg 127.0.0.1:143
  ptsrvtester -j imap -ts BRUTE -u admin -P passwords.txt --brute-threads 20 -tg 127.0.0.1:143
  ptsrvtester imap -ts USRENUM -h"""

        parser = subparsers.add_parser(
            name,
            add_help=True,
            epilog=examples,
            formatter_class=argparse.RawTextHelpFormatter,
        )
        parser.add_argument(
            "-tg", "--target",
            type=valid_target_imap,
            required=True,
            metavar="<host>",
            dest="target",
            help="IP[:PORT] or HOST[:PORT] (e.g. 127.0.0.1 or mail.example.com:143)",
        )
        parser.add_argument("--tls", action="store_true", help="use implicit SSL/TLS")
        parser.add_argument("--starttls", action="store_true", help="use explicit STARTTLS")
        parser.add_argument(
            "-ts", "--tests", type=str, default=None, metavar="<test>", dest="tests",
            help="Comma-separated test codes (e.g. BANNER,CAPA) or ALL; 'imap -ts <TEST> -h' for test options",
        )
        parser.add_argument(
            "--module-threads", type=int, default=1, metavar="n", dest="module_threads",
            help=argparse.SUPPRESS,
        )

        parser.add_argument(
            "--mailbox",
            default="INBOX",
            metavar="NAME",
            dest="mailbox",
            help="IMAP Folder",
        )

        mods = parser.add_argument_group("TEST OPTIONS")
        mods.add_argument("--canary-url", metavar="URL", dest="canary_url", default=None,
                          help="XXESSRF: canary/callback URL (required)")
        mods.add_argument("--timeout", type=float, default=30.0, metavar="SEC", dest="xxe_timeout",
                          help=argparse.SUPPRESS)
        mods.add_argument("--variant-small", action="store_true", dest="zipbomb_variant_small",
                          help=argparse.SUPPRESS)
        mods.add_argument("--variant-medium", action="store_true", dest="zipbomb_variant_medium",
                          help=argparse.SUPPRESS)
        mods.add_argument("--variant-huge", action="store_true", dest="zipbomb_variant_huge",
                          help=argparse.SUPPRESS)
        mods.add_argument("--usrenum-password", metavar="STR", dest="imap_usrenum_password", default=None,
                          help=f"USRENUM/USRENUMPLAIN: wrong password (default {_IMAP_USRENUM_DEFAULT_PASSWORD!r})")
        mods.add_argument("--usrenum-max", type=int, default=0, metavar="N", dest="imap_usrenum_max",
                          help="USRENUM/USRENUMPLAIN: limit names from wordlist (0 = no limit)")
        mods.add_argument("--resource-load-append-max", type=int, default=_IMAP_LOAD_APPEND_MAX_DEFAULT,
                          metavar="N", dest="imap_resource_load_append_max",
                          help=f"RESLOAD: max APPEND operations (default {_IMAP_LOAD_APPEND_MAX_DEFAULT})")
        mods.add_argument("--resource-load-search-max", type=int, default=_IMAP_LOAD_SEARCH_MAX_DEFAULT,
                          metavar="N", dest="imap_resource_load_search_max",
                          help=f"RESLOAD: max UID SEARCH ALL (default {_IMAP_LOAD_SEARCH_MAX_DEFAULT}; 0 skips)")
        mods.add_argument("--mailbox-iso-foreign-user", default="user2", metavar="NAME",
                          dest="imap_mailbox_iso_foreign_user",
                          help="MBOXISO: token for cross-user heuristics (default user2)")
        parser.add_argument(
            "--count",
            nargs="?",
            type=int,
            const=None,
            default=None,
            metavar="N",
            dest="noop2_count",
            help=argparse.SUPPRESS,  # Shown in test-specific help via registry
        )
        parser.add_argument(
            "-t", "--threads",
            type=int,
            default=None,
            metavar="N",
            dest="noop2_threads",
            help=argparse.SUPPRESS,  # Shown in NOOP2 / CONNLIM / TLSAUDIT / USRENUM / USRENUMPLAIN test help
        )
        parser.add_argument(
            "--duration",
            type=float,
            default=None,
            metavar="SEC",
            dest="noop1_duration",
            help=argparse.SUPPRESS,
        )
        parser.add_argument(
            "--delay",
            type=float,
            default=None,
            metavar="SEC",
            dest="noop1_delay",
            help=argparse.SUPPRESS,
        )

        add_bruteforce_args(parser, user_nargs="+")


def _selected_codes(args) -> list[str]:
    raw = getattr(args, "tests", None) or ""
    return [c.strip().upper() for c in raw.split(",") if c.strip()]


def validate_imap_selection(args) -> None:
    """Raise if selected tests lack required modifiers / credentials."""
    codes = _selected_codes(args)
    th = getattr(args, "noop2_threads", None)
    if th is not None and int(th) < 1:
        raise argparse.ArgumentError(None, "-t/--threads must be >= 1")
    if not codes or "ALL" in codes:
        return

    if "BRUTE" in codes and not check_if_brute(args):
        raise argparse.ArgumentError(
            None, "BRUTE requires -u/--user or -U/--users; -p/--password or -P/--passwords",
        )

    if ("USRENUM" in codes or "USRENUMPLAIN" in codes) and not (
        getattr(args, "user", None) or getattr(args, "users", None)
    ):
        raise argparse.ArgumentError(
            None, "USRENUM / USRENUMPLAIN requires -u/--user or -U/--users",
        )

    need_single_login = {"EICAR", "RESLOAD", "MBOXISO", "XXESSRF", "XXEEXP", "ZIPBOMB"} & set(codes)
    if need_single_login:
        p = getattr(args, "password", None)
        if (
            one_cli_user(getattr(args, "user", None)) is None
            or not p
            or getattr(args, "users", None)
            or getattr(args, "passwords", None)
        ):
            raise argparse.ArgumentError(
                None, f"{', '.join(sorted(need_single_login))} requires -u/--user and -p/--password (no wordlists)",
            )

    if "XXESSRF" in codes:
        canary = getattr(args, "canary_url", None) or ""
        if not str(canary).strip():
            raise argparse.ArgumentError(
                None, "XXESSRF requires --canary-url (canary/callback URL)",
            )

    if "USRENUM" in codes or "USRENUMPLAIN" in codes:
        if int(getattr(args, "imap_usrenum_max", 0) or 0) < 0:
            raise argparse.ArgumentError(None, "--usrenum-max must be >= 0")

    if "RESLOAD" in codes:
        am = int(getattr(args, "imap_resource_load_append_max", 0) or 0)
        sm = int(getattr(args, "imap_resource_load_search_max", 0) or 0)
        if am < 1:
            raise argparse.ArgumentError(None, "--resource-load-append-max must be >= 1")
        if sm < 0:
            raise argparse.ArgumentError(None, "--resource-load-search-max must be >= 0")
        if am > 5000:
            raise argparse.ArgumentError(None, "--resource-load-append-max must be <= 5000 (safety cap)")

    if "MBOXISO" in codes:
        fu = (getattr(args, "imap_mailbox_iso_foreign_user", None) or "user2").strip()
        if not fu:
            raise argparse.ArgumentError(None, "--mailbox-iso-foreign-user must be non-empty after trim")
        if len(fu) > 64:
            raise argparse.ArgumentError(None, "--mailbox-iso-foreign-user must be <= 64 characters")
        for bad in ("\r", "\n", "\x00", '"'):
            if bad in fu:
                raise argparse.ArgumentError(
                    None, "--mailbox-iso-foreign-user must not contain CR, LF, NUL, or double-quote",
                )

    mb = (getattr(args, "mailbox", None) or "INBOX").strip()
    if not mb:
        raise argparse.ArgumentError(None, "--mailbox must be non-empty after trim")
