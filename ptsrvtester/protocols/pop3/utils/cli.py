"""POP3 CLI — argparse namespace and help (selection is discovery-based)."""
from __future__ import annotations

import argparse

from .capa import valid_target_pop3
from .helpers import ArgsWithBruteforce, Target, add_bruteforce_args, check_if_brute
from .ptprinthelper import get_colored_text
from .registry import POP3_TEST_GROUPS, POP3_TESTS, pop3_test_help
from ptsrvtester.protocols._shared.utils.cli import rate_limit_help_rows

__all__ = ["POP3Args"]


class POP3Args(ArgsWithBruteforce):
    target: Target
    tls: bool
    starttls: bool
    tests: str | None
    module_threads: int

    @staticmethod
    def get_help():
        options: list[list[str]] = [
            ["-ts", "--tests", "<test>", "One or more tests, comma-separated (e.g. BANNER,CAPA); ALL = default suite:"],
        ]
        for group_title, codes in POP3_TEST_GROUPS:
            options.append(["", "", "", ""])
            options.append(["", "", get_colored_text(group_title, "TITLE")])
            for code in codes:
                options.append(["", "", code, POP3_TESTS[code]["desc"]])

        options += [
            ["", "", "", ""],
            [get_colored_text("Connection", "TITLE")],
            ["-tg", "--target", "<host>", "Target IP[:PORT] or HOST[:PORT]"],
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
            *rate_limit_help_rows(get_colored_text),
            ["", "", "", ""],
            [get_colored_text("Output", "TITLE")],
            ["-j", "--json", "", "Output in JSON format"],
            ["-vv", "--verbose", "", "Enable verbose mode"],
            ["-h", "--help", "", "Show this help; 'pop3 -ts <TEST> -h' for test options"],
        ]

        return [
            {"description": ["POP3 Testing Module"]},
            {"usage": ["ptsrvtester pop3 -ts <test>[,<test>...] <options> -tg <target>"]},
            {"usage_example": [
                "ptsrvtester pop3 -ts BANNER,CAPA -tg 127.0.0.1",
                "ptsrvtester pop3 -ts ALL -tg 127.0.0.1",
                "ptsrvtester pop3 -ts ENCRYPT -tg 127.0.0.1",
                "ptsrvtester pop3 -ts ALL --tls -tg 127.0.0.1:995",
                "ptsrvtester pop3 -ts ANON,HELPINFO -tg 127.0.0.1",
                "ptsrvtester pop3 -ts RATELIMIT -tg 127.0.0.1",
                "ptsrvtester pop3 -ts BRUTE -u admin -P passwords.txt -tg 127.0.0.1:110",
                "ptsrvtester pop3 -ts BRUTE -h",
            ]},
            {"options": options},
        ]

    @staticmethod
    def get_test_help(codes):
        return pop3_test_help(codes)

    def add_subparser(self, name: str, subparsers) -> None:
        examples = """example usage:
  ptsrvtester pop3 -h
  ptsrvtester pop3 -ts BANNER,CAPA -tg 127.0.0.1
  ptsrvtester pop3 -ts ALL -tg 127.0.0.1
  ptsrvtester pop3 -ts ENCRYPT -tg 127.0.0.1
  ptsrvtester pop3 -ts ALL --tls -tg 127.0.0.1:995
  ptsrvtester -j pop3 -ts BRUTE -u admin -P passwords.txt --brute-threads 20 -tg 127.0.0.1:110
  ptsrvtester pop3 -ts BRUTE -h"""

        parser = subparsers.add_parser(
            name,
            add_help=True,
            epilog=examples,
            formatter_class=argparse.RawTextHelpFormatter,
        )
        parser.add_argument(
            "-tg", "--target",
            type=valid_target_pop3,
            required=True,
            metavar="<host>",
            dest="target",
            help="IP[:PORT] or HOST[:PORT] (e.g. 127.0.0.1 or mail.example.com:110)",
        )
        parser.add_argument("--tls", action="store_true", help="use implicit SSL/TLS")
        parser.add_argument("--starttls", action="store_true", help="use explicit STLS")
        parser.add_argument(
            "-ts", "--tests", type=str, default=None, metavar="<test>", dest="tests",
            help="Comma-separated test codes (e.g. BANNER,CAPA) or ALL; 'pop3 -ts <TEST> -h' for test options",
        )
        # Serial module execution by default (JSON report + shared server_info).
        parser.add_argument(
            "--module-threads", type=int, default=1, metavar="n", dest="module_threads",
            help=argparse.SUPPRESS,
        )
        add_bruteforce_args(parser)


def validate_brute_selection(args) -> None:
    """Raise if BRUTE was explicitly selected without credentials."""
    raw = getattr(args, "tests", None) or ""
    codes = [c.strip().upper() for c in raw.split(",") if c.strip()]
    if "BRUTE" in codes and "ALL" not in codes and not check_if_brute(args):
        raise argparse.ArgumentError(
            None, "BRUTE requires -u/--user or -U/--users; -p/--password or -P/--passwords",
        )
