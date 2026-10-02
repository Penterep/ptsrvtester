"""FTP CLI — argparse namespace and help (selection is discovery-based)."""
from __future__ import annotations

import argparse

from .ftp_types import valid_target_bounce, valid_target_ftp
from .helpers import ArgsWithBruteforce, Target, add_bruteforce_args, check_if_brute
from .ptprinthelper import get_colored_text
from .registry import FTP_TEST_GROUPS, FTP_TESTS, ftp_test_help
from ptsrvtester.protocols._shared.utils.cli import rate_limit_help_rows

__all__ = ["FTPArgs"]


class FTPArgs(ArgsWithBruteforce):
    target: Target
    active: bool
    tls: bool
    starttls: bool
    tests: str | None
    module_threads: int
    anonymous: bool
    access_list: bool
    bounce: Target | None
    bounce_file: str | None
    paths_wordlist: str | None
    enum_files: str | None
    enum_depth: int
    base_path: str
    pasv_port_audit_samples: int
    pasv_port_audit_max_span: int
    conn_limit_count: int | None
    conn_limit_duration: float | None
    active_audit_low_ports: str
    user_enum_wordlist: str | None
    user_enum_password: str
    user_enum_keep_alive: bool
    user_enum_timing: bool
    user_enum_max: int
    eicar_post_stor_delay: float
    ftp_dos_timeout: float
    ftp_dos_large: bool

    @staticmethod
    def get_help():
        options: list[list[str]] = [
            ["-ts", "--tests", "<test>", "One or more tests, comma-separated (e.g. BANNER,ANON); ALL = default suite:"],
        ]
        for group_title, codes in FTP_TEST_GROUPS:
            options.append(["", "", "", ""])
            options.append(["", "", get_colored_text(group_title, "TITLE")])
            for code in codes:
                options.append(["", "", code, FTP_TESTS[code]["desc"]])
        options += [
            ["", "", "", ""],
            [get_colored_text("Connection", "TITLE")],
            ["-tg", "--target", "<host>", "Target IP[:PORT] or HOST[:PORT]"],
            ["", "--active", "", "Use active data mode (passive by default)"],
            ["", "--tls", "", "Use implicit SSL/TLS (default port 990)"],
            ["", "--starttls", "", "Use explicit AUTH TLS"],
            ["-A", "--anonymous", "", "Use anonymous login for authenticated tests"],
            ["", "", "", ""],
            [get_colored_text("Credentials (BRUTE / authenticated tests)", "TITLE")],
            ["-u", "--user", "<name> …", "Username(s) for BRUTE / USRENUM / authenticated tests"],
            ["-U", "--users", "<wordlist>", "Username wordlist"],
            ["-p", "--password", "<password>", "Single password"],
            ["-P", "--passwords", "<wordlist>", "Password wordlist"],
            ["", "--spray", "", "Try one password against all users"],
            ["-t", "--threads", "<n>", "Threads (BRUTE default: 10, ENUMPATH default: 5, USRENUM default: 1)"],
            *rate_limit_help_rows(get_colored_text),
            ["", "", "", ""],
            [get_colored_text("Output", "TITLE")],
            ["-j", "--json", "", "Output in JSON format"],
            ["-vv", "--verbose", "", "Enable verbose mode"],
            ["-h", "--help", "", "Show this help; 'ftp -ts <TEST> -h' for test options"],
        ]
        return [
            {"description": ["FTP Testing Module"]},
            {"usage": ["ptsrvtester ftp -ts <test>[,<test>...] <options> -tg <target>"]},
            {"usage_example": [
                "ptsrvtester ftp -ts BANNER,CMD -tg 127.0.0.1",
                "ptsrvtester ftp -ts ALL -tg 127.0.0.1",
                "ptsrvtester ftp -ts ENCRYPT -tg 127.0.0.1",
                "ptsrvtester ftp -ts ANON,ACCESS -l -tg 127.0.0.1",
                "ptsrvtester ftp -ts BRUTE -u admin harry -P passwords.txt -tg 127.0.0.1:21",
                "ptsrvtester ftp -ts USRENUM -u user admin nobody -tg 127.0.0.1",
                "ptsrvtester ftp -ts ENUMPATH -w paths.txt -u user -p pass -tg 127.0.0.1",
                "ptsrvtester ftp -ts EICAR -A -tg 127.0.0.1",
                "ptsrvtester ftp -ts CONNLIM,DOS -u user -p pass -tg 127.0.0.1",
                "ptsrvtester ftp -ts RATELIMIT -tg 127.0.0.1",
                "ptsrvtester ftp -ts USRENUM -h",
            ]},
            {"options": options},
        ]

    @staticmethod
    def get_test_help(codes):
        return ftp_test_help(codes)

    def add_subparser(self, name: str, subparsers) -> None:
        examples = """example usage:
  ptsrvtester ftp -h
  ptsrvtester ftp -ts BANNER,CMD -tg 127.0.0.1
  ptsrvtester ftp -ts ALL -tg 127.0.0.1
  ptsrvtester ftp -ts ENCRYPT -tg 127.0.0.1
  ptsrvtester ftp -ts ANON,ACCESS -l -tg 127.0.0.1
  ptsrvtester ftp -ts EICAR -A -tg 127.0.0.1
  ptsrvtester ftp -ts BRUTE -u admin -P passwords.txt -tg 127.0.0.1:21
  ptsrvtester ftp -ts USRENUM -u user admin nobody -tg 127.0.0.1
  ptsrvtester ftp -ts USRENUM -h"""

        parser = subparsers.add_parser(
            name, add_help=True, epilog=examples,
            formatter_class=argparse.RawTextHelpFormatter,
        )
        parser.add_argument(
            "-tg", "--target", type=valid_target_ftp, required=True,
            metavar="<host>", dest="target",
            help="IP[:PORT] or HOST[:PORT] (e.g. 127.0.0.1 or ftp.example.com:21)",
        )
        parser.add_argument("--active", action="store_true", help="use active mode (passive by default)")
        tls = parser.add_mutually_exclusive_group()
        tls.add_argument("--tls", action="store_true", help="use implicit SSL/TLS")
        tls.add_argument("--starttls", action="store_true", help="use explicit AUTH TLS")
        parser.add_argument(
            "-A", "--anonymous", action="store_true", dest="anonymous",
            help="use anonymous login for authenticated tests (ACCESS, EICAR, …)",
        )
        parser.add_argument(
            "-ts", "--tests", type=str, default=None, metavar="<test>", dest="tests",
            help="Comma-separated test codes or ALL; 'ftp -ts <TEST> -h' for test options",
        )
        parser.add_argument(
            "--module-threads", type=int, default=1, metavar="n", dest="module_threads",
            help=argparse.SUPPRESS,
        )

        mods = parser.add_argument_group("TEST OPTIONS")
        mods.add_argument("-l", "--access-list", action="store_true", help="ACCESS: display root directory listing")
        mods.add_argument("-B", "--bounce", type=valid_target_bounce, help="ACCESS: FTP bounce to IP:PORT / HOST:PORT")
        mods.add_argument("--bounce-file", type=str, help="ACCESS: file with request for bounce")
        mods.add_argument("-w", "--paths-wordlist", type=str, dest="paths_wordlist", help="ENUMPATH: directory names, one per line")
        mods.add_argument("--files", type=str, dest="enum_files", metavar="<file>", help="ENUMPATH: file names to try inside each directory entered")
        mods.add_argument("--depth", type=int, default=1, dest="enum_depth", metavar="<n>", help="ENUMPATH: how many directory levels to walk (default: 1)")
        mods.add_argument("--base-path", type=str, default="", dest="base_path", help="ENUMPATH: start directory")
        mods.add_argument("--pasv-port-audit-samples", type=int, default=8, dest="pasv_port_audit_samples", metavar="<n>")
        mods.add_argument("--pasv-port-audit-max-span", type=int, default=8192, dest="pasv_port_audit_max_span", metavar="<n>")
        mods.add_argument("--count", type=int, default=None, dest="conn_limit_count", metavar="<n>", help=argparse.SUPPRESS)
        mods.add_argument("--duration", type=float, default=None, dest="conn_limit_duration", metavar="<sec>", help=argparse.SUPPRESS)
        mods.add_argument("--active-audit-low-ports", type=str, default="80,443,21", dest="active_audit_low_ports")
        mods.add_argument("--user-enum-wordlist", type=str, dest="user_enum_wordlist", metavar="<file>")
        mods.add_argument("--user-enum-password", type=str, default="PtsrvUEnumWrongPass!77~", dest="user_enum_password", metavar="<str>")
        mods.add_argument("--user-enum-keep-alive", action="store_true", dest="user_enum_keep_alive")
        mods.add_argument("--user-enum-timing", action="store_true", dest="user_enum_timing")
        mods.add_argument("--user-enum-max", type=int, default=0, dest="user_enum_max", metavar="<n>")
        mods.add_argument("--eicar-post-stor-delay", type=float, default=0.5, dest="eicar_post_stor_delay", metavar="<sec>")
        mods.add_argument("--ftp-dos-timeout", type=float, default=30.0, dest="ftp_dos_timeout", metavar="<sec>")
        mods.add_argument("--ftp-dos-large", action="store_true", dest="ftp_dos_large")
        add_bruteforce_args(parser, user_nargs="+")


def _codes(args) -> list[str]:
    raw = getattr(args, "tests", None) or ""
    return [c.strip().upper() for c in raw.split(",") if c.strip()]


def _has_creds(args) -> bool:
    return bool(getattr(args, "anonymous", False) or check_if_brute(args))


def validate_ftp_selection(args) -> None:
    th = getattr(args, "threads", None)
    if th is not None and int(th) < 1:
        raise argparse.ArgumentError(None, "-t/--threads must be >= 1")
    codes = _codes(args)
    if not codes or "ALL" in codes:
        return
    if "BRUTE" in codes and not check_if_brute(args):
        raise argparse.ArgumentError(None, "BRUTE requires -u/--user or -U/--users; -p/--password or -P/--passwords")
    if "USRENUM" in codes and not (
        getattr(args, "user", None) or getattr(args, "users", None) or getattr(args, "user_enum_wordlist", None)
    ):
        raise argparse.ArgumentError(None, "USRENUM requires -u/--user or -U/--users")
    if "ENUMPATH" in codes and not getattr(args, "paths_wordlist", None) and not getattr(args, "enum_files", None):
        raise argparse.ArgumentError(None, "ENUMPATH requires -w/--paths-wordlist or --files")
    if "ENUMPATH" in codes:
        depth = getattr(args, "enum_depth", 1)
        if depth is None:
            depth = 1
        if int(depth) < 1:
            raise argparse.ArgumentError(None, "--depth must be >= 1")
    need_creds = {"ACCESS", "ENUMPATH", "MODES", "PASVPORT", "CMDAUDITACTIVE", "DOS", "CHROOT", "EICAR"} & set(codes)
    # ACCESS/EICAR etc. may rely on -ts ANON in the same run (results.anonymous) — allow ANON+ACCESS
    if need_creds and not _has_creds(args) and "ANON" not in codes:
        raise argparse.ArgumentError(
            None, f"{', '.join(sorted(need_creds))} requires -A/--anonymous or credentials (-u/-p), or include ANON in -ts",
        )
    if getattr(args, "bounce_file", None) and "ACCESS" not in codes:
        raise argparse.ArgumentError(None, "--bounce-file requires -ts ACCESS")
    if getattr(args, "access_list", False) and "ACCESS" not in codes:
        raise argparse.ArgumentError(None, "--access-list requires -ts ACCESS")
