"""IMAP CLI — argparse namespace and help (selection is discovery-based)."""
from __future__ import annotations

import argparse

from .capa import valid_target_imap
from .helpers import ArgsWithBruteforce, Target, add_bruteforce_args, check_if_brute
from .ptprinthelper import get_colored_text
from .registry import IMAP_TEST_GROUPS, IMAP_TESTS, imap_test_help
from ptsrvtester.protocols._shared.utils.cli import rate_limit_help_rows
from .results import (
    CONN_LIMIT_DEFAULT_ATTEMPTS,
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
    eicar_mailbox: str
    zipxxe_canary_url: str | None
    zipxxe_variants: str | None
    zipxxe_zip_bomb: bool
    zipxxe_zip_bomb_full: bool
    zipxxe_mailbox: str
    zipxxe_timeout: float
    conn_limits_max: int | None
    imap_usrenum_password: str | None
    imap_usrenum_max: int
    imap_usrenum_threads: int
    imap_resource_load_mailbox: str
    imap_resource_load_append_max: int
    imap_resource_load_search_max: int
    imap_mailbox_iso_foreign_user: str
    imap_mailbox_iso_mailbox: str

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
            ["-u", "--user", "<name>", "Single username"],
            ["-U", "--users", "<wordlist>", "Username wordlist"],
            ["-p", "--password", "<password>", "Single password"],
            ["-P", "--passwords", "<wordlist>", "Password wordlist"],
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
                "ptsrvtester imap -ts ENCRYPT,SNIFF -tg 127.0.0.1:143",
                "ptsrvtester imap -ts EICAR -u user -p pass -tg 127.0.0.1:143",
                "ptsrvtester imap -ts ZIPXXE -u user -p pass --zipxxe-canary-url http://cb -tg 127.0.0.1:143",
                "ptsrvtester imap -ts USRENUM -U users.txt --usrenum-threads 4 -tg 127.0.0.1:143",
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
  ptsrvtester imap -ts ENCRYPT,SNIFF -tg 127.0.0.1:143
  ptsrvtester imap -ts CONNLIM --cl-max 50 -tg mail.example.com
  ptsrvtester imap -ts EICAR -u user -p pass -tg 127.0.0.1:143
  ptsrvtester imap -ts ZIPXXE -u user -p pass --zipxxe-canary-url http://cb -tg 127.0.0.1:143
  ptsrvtester imap -ts RESLOAD -u user -p pass -tg 127.0.0.1:143
  ptsrvtester imap -ts MBOXISO -u user -p pass -tg 127.0.0.1:143
  ptsrvtester imap -ts TLSAUDIT -tg mail.example.com:993
  ptsrvtester imap -ts USRENUM -U users.txt --usrenum-threads 4 -tg 127.0.0.1:143
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

        mods = parser.add_argument_group("TEST OPTIONS")
        mods.add_argument("--eicar-mailbox", default="INBOX", metavar="NAME", dest="eicar_mailbox",
                          help="EICAR: mailbox name for APPEND (default INBOX)")
        mods.add_argument("--zipxxe-canary-url", metavar="URL", dest="zipxxe_canary_url", default=None,
                          help="ZIPXXE: canary URL for xxe_zip / xxe_docx / xxe_body")
        mods.add_argument("--zipxxe-variants", metavar="LIST", dest="zipxxe_variants", default=None,
                          help="ZIPXXE variants: billion_laughs_attach,billion_laughs_body,xxe_zip,xxe_docx,xxe_body (default: all). Use --zipxxe-canary-url for xxe_*.")
        mods.add_argument("--zipxxe-zip-bomb", action="store_true", dest="zipxxe_zip_bomb",
                          help="ZIPXXE: include zip_bomb (minimal ~200KB; DoS risk)")
        mods.add_argument("--zipxxe-zip-bomb-full", action="store_true", dest="zipxxe_zip_bomb_full",
                          help="ZIPXXE: include zip_bomb_full (~100KB→~100MB; extreme DoS risk)")
        mods.add_argument("--zipxxe-mailbox", default="INBOX", metavar="NAME", dest="zipxxe_mailbox",
                          help="ZIPXXE: mailbox name for APPEND (default INBOX)")
        mods.add_argument("--zipxxe-timeout", type=float, default=30.0, metavar="SEC", dest="zipxxe_timeout",
                          help="ZIPXXE: timeout per message (default: 30)")
        mods.add_argument("--cl-max", type=int, default=None, metavar="N", dest="conn_limits_max",
                          help=f"CONNLIM: max concurrent connections in ramp-up (default {CONN_LIMIT_DEFAULT_ATTEMPTS})")
        mods.add_argument("--usrenum-password", metavar="STR", dest="imap_usrenum_password", default=None,
                          help=f"USRENUM/USRENUMPLAIN: wrong password (default {_IMAP_USRENUM_DEFAULT_PASSWORD!r})")
        mods.add_argument("--usrenum-max", type=int, default=0, metavar="N", dest="imap_usrenum_max",
                          help="USRENUM/USRENUMPLAIN: limit names from wordlist (0 = no limit)")
        mods.add_argument("--usrenum-threads", type=int, default=1, metavar="N", dest="imap_usrenum_threads",
                          help="USRENUM/USRENUMPLAIN: parallel TCP sessions (default 1)")
        mods.add_argument("--resource-load-mailbox", default="INBOX", metavar="NAME",
                          dest="imap_resource_load_mailbox",
                          help="RESLOAD: mailbox for APPEND phase (default INBOX)")
        mods.add_argument("--resource-load-append-max", type=int, default=_IMAP_LOAD_APPEND_MAX_DEFAULT,
                          metavar="N", dest="imap_resource_load_append_max",
                          help=f"RESLOAD: max APPEND operations (default {_IMAP_LOAD_APPEND_MAX_DEFAULT}; hard cap 5000)")
        mods.add_argument("--resource-load-search-max", type=int, default=_IMAP_LOAD_SEARCH_MAX_DEFAULT,
                          metavar="N", dest="imap_resource_load_search_max",
                          help=f"RESLOAD: max UID SEARCH ALL (default {_IMAP_LOAD_SEARCH_MAX_DEFAULT}; 0 skips)")
        mods.add_argument("--mailbox-iso-foreign-user", default="user2", metavar="NAME",
                          dest="imap_mailbox_iso_foreign_user",
                          help="MBOXISO: token for cross-user heuristics (default user2)")
        mods.add_argument("--mailbox-iso-mailbox", default="INBOX", metavar="NAME",
                          dest="imap_mailbox_iso_mailbox",
                          help="MBOXISO: own baseline mailbox (default INBOX)")

        add_bruteforce_args(parser)


def _selected_codes(args) -> list[str]:
    raw = getattr(args, "tests", None) or ""
    return [c.strip().upper() for c in raw.split(",") if c.strip()]


def validate_imap_selection(args) -> None:
    """Raise if selected tests lack required modifiers / credentials."""
    codes = _selected_codes(args)
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

    need_single_login = {"EICAR", "RESLOAD", "MBOXISO", "ZIPXXE"} & set(codes)
    if need_single_login:
        u = getattr(args, "user", None)
        p = getattr(args, "password", None)
        if not u or not p or getattr(args, "users", None) or getattr(args, "passwords", None):
            raise argparse.ArgumentError(
                None, f"{', '.join(sorted(need_single_login))} requires -u/--user and -p/--password (no wordlists)",
            )

    if "ZIPXXE" in codes:
        variants_arg = getattr(args, "zipxxe_variants", None)
        zipxxe_variants = [
            v.strip().lower()
            for v in (variants_arg or "billion_laughs_attach,billion_laughs_body,xxe_zip,xxe_docx,xxe_body").split(",")
            if v.strip()
        ]
        if getattr(args, "zipxxe_zip_bomb", False):
            zipxxe_variants.append("zip_bomb")
        if getattr(args, "zipxxe_zip_bomb_full", False):
            zipxxe_variants.append("zip_bomb_full")
        if any(v in {"xxe_zip", "xxe_docx", "xxe_body"} for v in zipxxe_variants):
            canary = getattr(args, "zipxxe_canary_url", None) or ""
            if not str(canary).strip():
                raise argparse.ArgumentError(
                    None,
                    "ZIPXXE with xxe_zip/xxe_docx/xxe_body requires --zipxxe-canary-url (canary/callback URL)",
                )
        mb = (getattr(args, "zipxxe_mailbox", None) or "INBOX").strip()
        if not mb:
            raise argparse.ArgumentError(None, "--zipxxe-mailbox must be non-empty after trim")

    if "USRENUM" in codes or "USRENUMPLAIN" in codes:
        if int(getattr(args, "imap_usrenum_threads", 1) or 1) < 1:
            raise argparse.ArgumentError(None, "--usrenum-threads must be >= 1")
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
        mb = (getattr(args, "imap_mailbox_iso_mailbox", None) or "INBOX").strip()
        if not mb:
            raise argparse.ArgumentError(None, "--mailbox-iso-mailbox must be non-empty after trim")
