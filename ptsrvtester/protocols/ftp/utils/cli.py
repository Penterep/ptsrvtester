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
    access_file: str | None
    access_path: str
    recursive: bool
    access_delete: bool
    bounce: Target | None
    bounce_file: str | None
    wordlist: str | None
    file_extensions: list[str] | None
    enum_depth: int | None
    base_path: str
    pasv_port_audit_samples: int | None
    pasv_port_audit_max_span: int | None
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
    ftp_dos_zip_small: bool
    ftp_dos_zip_medium: bool
    ftp_dos_zip_large: bool

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
            ["-u", "--user", "<name> …", "Username(s), space or comma separated, for BRUTE / USRENUM / authenticated tests"],
            ["-U", "--users", "<wordlist>", "Username wordlist"],
            ["-p", "--password", "[password] …", "Password(s), space or comma separated. No value or \"\" tests an empty password"],
            ["-P", "--passwords", "<wordlist>", "Password wordlist"],
            ["", "--spray", "", "Try one password against all users"],
            ["-t", "--threads", "<n>", "Threads (BRUTE default: 10, FILEENUM default: 5, USRENUM default: 1)"],
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
                "ptsrvtester ftp -ts FILEENUM -w paths.txt --extension txt,php --recursive -u user -p pass -tg 127.0.0.1",
                "ptsrvtester ftp -ts EICAR -A -tg 127.0.0.1",
                "ptsrvtester ftp -ts CONNLIM,ZIPXXE -u user -p pass -tg 127.0.0.1",
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
        mods.add_argument("-f", "--file", type=str, dest="access_file", metavar="<name>", help="ACCESS: remote file name when listing is refused")
        mods.add_argument("--path", type=str, default="/", dest="access_path", metavar="<dir>", help="ACCESS/ZIPXXE/EICAR: directory to test or upload into (default: /)")
        mods.add_argument("--delete", action="store_true", dest="access_delete", help="ACCESS: also delete an existing file and the tested directory. EICAR: delete the uploaded files together after --delay. ZIPXXE: delete the uploaded files after --delay")
        mods.add_argument("-B", "--bounce", type=valid_target_bounce, help="ACCESS: FTP bounce to IP:PORT / HOST:PORT")
        mods.add_argument("--bounce-file", type=str, help="ACCESS: file with request for bounce")
        mods.add_argument("-w", "--wordlist", type=str, dest="wordlist", metavar="<file>", help="FILEENUM: names to try, one per line")
        mods.add_argument("-e", "--extension", nargs="+", dest="file_extensions", metavar="<ext>", help="FILEENUM: suffixes, comma or space separated. An empty suffix tries the name as a directory")
        mods.add_argument("-r", "--recursive", action="store_true", dest="recursive", help="ACCESS/FILEENUM: also continue inside directories that are found")
        mods.add_argument("--depth", type=int, default=None, dest="enum_depth", metavar="<n>", help="FILEENUM -r/--recursive depth (default: 5). ACCESS -r/--recursive depth (default: 1)")
        mods.add_argument("--base-path", type=str, default="", dest="base_path", help="FILEENUM: start directory")
        mods.add_argument("--pasv-port-audit-samples", type=int, default=None, dest="pasv_port_audit_samples", metavar="<n>", help=argparse.SUPPRESS)
        mods.add_argument("--pasv-port-audit-max-span", type=int, default=None, dest="pasv_port_audit_max_span", metavar="<n>", help=argparse.SUPPRESS)
        mods.add_argument("-c", "--count", type=int, default=None, dest="conn_limit_count", metavar="<n>", help=argparse.SUPPRESS)
        mods.add_argument("--duration", type=float, default=None, dest="conn_limit_duration", metavar="<sec>", help=argparse.SUPPRESS)
        mods.add_argument("--active-audit-low-ports", type=str, default="80,443,21", dest="active_audit_low_ports")
        mods.add_argument("--user-enum-wordlist", type=str, dest="user_enum_wordlist", metavar="<file>")
        mods.add_argument("--user-enum-password", type=str, default="PtsrvUEnumWrongPass!77~", dest="user_enum_password", metavar="<str>")
        mods.add_argument("--user-enum-keep-alive", action="store_true", dest="user_enum_keep_alive")
        mods.add_argument("--user-enum-timing", action="store_true", dest="user_enum_timing")
        mods.add_argument("--user-enum-max", type=int, default=0, dest="user_enum_max", metavar="<n>")
        mods.add_argument(
            "--delay", "--eicar-post-stor-delay", type=float, default=None,
            dest="eicar_post_stor_delay", metavar="<sec>",
        )
        mods.add_argument(
            "-T", "--timeout", type=float, default=30.0,
            dest="ftp_dos_timeout", metavar="<sec>",
        )
        mods.add_argument("--zipxxe-zip-bomb-small", action="store_true", dest="ftp_dos_zip_small")
        mods.add_argument("--zipxxe-zip-bomb-medium", action="store_true", dest="ftp_dos_zip_medium")
        mods.add_argument(
            "--zipxxe-zip-bomb-large", "--ftp-dos-large", action="store_true", dest="ftp_dos_zip_large",
        )
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
    for name, label in (
        ("conn_limit_count", "-c/--count"),
        ("pasv_port_audit_samples", "--pasv-port-audit-samples"),
    ):
        raw = getattr(args, name, None)
        if raw is not None and int(raw) < 1:
            raise argparse.ArgumentError(None, f"{label} must be >= 1")
    codes = _codes(args)
    if codes and getattr(args, "enum_depth", None) is not None and (
        "ALL" in codes or "FILEENUM" in codes or "ACCESS" in codes
    ):
        if int(args.enum_depth) < 1:
            raise argparse.ArgumentError(None, "--depth must be >= 1")
    if not codes or "ALL" in codes:
        return
    if "USRENUM" in codes and not (
        getattr(args, "user", None) or getattr(args, "users", None) or getattr(args, "user_enum_wordlist", None)
    ):
        raise argparse.ArgumentError(None, "USRENUM requires -u/--user or -U/--users")
    if "FILEENUM" in codes and not getattr(args, "wordlist", None):
        raise argparse.ArgumentError(None, "FILEENUM requires -w/--wordlist")
    if "FILEENUM" not in codes and getattr(args, "file_extensions", None):
        raise argparse.ArgumentError(None, "--extension requires -ts FILEENUM")
    if getattr(args, "recursive", False) and "ACCESS" not in codes and "FILEENUM" not in codes:
        raise argparse.ArgumentError(None, "-r/--recursive requires -ts ACCESS or -ts FILEENUM")
    need_creds = {"ACCESS", "FILEENUM", "CMDAUDITACTIVE", "ZIPXXE", "CHROOT", "EICAR"} & set(codes)
    # ACCESS/EICAR etc. may rely on -ts ANON in the same run (results.anonymous) — allow ANON+ACCESS
    if need_creds and not _has_creds(args) and "ANON" not in codes:
        raise argparse.ArgumentError(
            None, f"{', '.join(sorted(need_creds))} requires -A/--anonymous or credentials (-u/-p), or include ANON in -ts",
        )
    if getattr(args, "bounce_file", None) and "ACCESS" not in codes:
        raise argparse.ArgumentError(None, "--bounce-file requires -ts ACCESS")
    if getattr(args, "access_list", False) and "ACCESS" not in codes:
        raise argparse.ArgumentError(None, "--access-list requires -ts ACCESS")
    if "ACCESS" not in codes:
        if getattr(args, "access_delete", False) and "EICAR" not in codes and "ZIPXXE" not in codes:
            raise argparse.ArgumentError(None, "--delete requires -ts ACCESS, -ts EICAR or -ts ZIPXXE")
        path = getattr(args, "access_path", "/") or "/"
        if path not in ("/", "") and "ZIPXXE" not in codes and "EICAR" not in codes:
            raise argparse.ArgumentError(None, "--path requires -ts ACCESS, -ts ZIPXXE or -ts EICAR")
    if "ZIPXXE" not in codes and (
        getattr(args, "ftp_dos_zip_small", False)
        or getattr(args, "ftp_dos_zip_medium", False)
        or getattr(args, "ftp_dos_zip_large", False)
    ):
        raise argparse.ArgumentError(None, "zip bomb switches require -ts ZIPXXE")
