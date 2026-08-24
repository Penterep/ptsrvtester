#!/usr/bin/python3
"""
    Copyright (c) 2024 Penterep Security s.r.o.

    ptsrvtester - Application Server Penetration Testing Tool

    ptsrvtester is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    ptsrvtester is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with ptsrvtester.  If not, see <https://www.gnu.org/licenses/>.
"""

import argparse
import importlib
import os
import re
import sys

from ptlibs import ptprinthelper, ptjsonlib
from ptlibs.ptprinthelper import out_if, out_ifnot, ptprint
from .protocols._shared.utils.cli import add_shared_rate_limit_args

from ._version import __version__
from .protocols._base import BaseArgs

SCRIPTNAME = "ptsrvtester"

MODULES: dict[str, tuple[str, str]] = {
    "snmp":  ("ptsrvtester.protocols.snmp:SNMP",   "SNMP testing module"),
    "dns":   ("ptsrvtester.protocols.dns:DNS",     "DNS testing module"),
    "ldap":  ("ptsrvtester.protocols.ldap:LDAP",   "LDAP testing module"),
    "msrpc": ("ptsrvtester.protocols.msrpc:MSRPC", "MSRPC testing module"),
    "ftp":   ("ptsrvtester.protocols.ftp:FTP",     "FTP testing module"),
    "ssh":   ("ptsrvtester.protocols.ssh:SSH",     "SSH testing module"),
    "smtp":  ("ptsrvtester.protocols.smtp:SMTP",   "SMTP testing module"),
    "pop3":  ("ptsrvtester.protocols.pop3:POP3",   "POP3 testing module"),
    "imap":  ("ptsrvtester.protocols.imap:IMAP",   "IMAP testing module"),
    "dhcp":  ("ptsrvtester.protocols.dhcp:DHCP",   "DHCP testing module"),
    "rdp":   ("ptsrvtester.protocols.rdp:RDP",     "RDP testing module"),
    "smb":   ("ptsrvtester.protocols.smb:SMB",     "SMB testing module"),
}


def load_module(name: str):
    """Import and return the module class registered under ``name`` (lazy)."""
    dotted, _ = MODULES[name]
    mod_path, cls_name = dotted.split(":")
    return getattr(importlib.import_module(mod_path), cls_name)


class PtsrvtesterJsonLib(ptjsonlib.PtJsonLib):
    """PtJsonLib subclass with unified error output format for customer reports.
    On end_error: status=error, message='Error: ...', empty nodes/properties/vulnerabilities."""

    def end_error(self, message, condition, details=None):
        full_msg = f"Error: {message}"
        ptprint(out_ifnot(full_msg, "ERROR", condition))
        if details:
            from ptlibs.ptprinthelper import get_colored_text
            ptprint("    " + out_ifnot(f"{get_colored_text(details, 'ADDITIONS')}", "TEXT", condition))
        self.json_object["status"] = "error"
        self.json_object["message"] = full_msg
        self.json_object["results"]["nodes"] = []
        self.json_object["results"]["properties"] = {}
        self.json_object["results"]["vulnerabilities"] = []
        ptprint(out_if(self.get_result_json(), None, condition))
        sys.stdout.write("\033[?25h")
        sys.stdout.flush()
        os._exit(1)


_LAST_ERROR: dict[str, str | None] = {"message": None}


class CustomArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        _LAST_ERROR["message"] = message
        raise SystemExit(2)


class Ptsrvtester:
    def __init__(self, args: BaseArgs) -> None:
        self.args = args

    def run(self) -> None:
        """Runs selected module with its configured arguments"""
        ptjson = PtsrvtesterJsonLib()

        module = load_module(self.args.module)(self.args, ptjson)
        module.run()
        module.output()


def get_help():
    module_rows = [[name, "<options>", "", desc] for name, (_, desc) in MODULES.items()]
    return [
        {"description": ["Server Penetration Testing Tool"]},
        {"usage": ["ptsrvtester <module> <options>"]},
        {"usage_example": [
            "ptsrvtester snmp detection --ip 192.168.1.1",
            "ptsrvtester <module> -h     for help for module use"
        ]},
        {"options": [
            *module_rows,
            ["", " ", "", ""],
            ["-v", "--version", "", "Show script version and exit"],
            ["-h", "--help", "", "Show this help message and exit"],
            ["-j", "--json", "", "Output in JSON format"],
            ["-vv", "--verbose", "", "Enable verbose mode"],
        ]
        }]


def _extract_test_help(module_args, argv):
    """Return per-test help object for `-ts <TEST> -h`, or None to fall back to module help."""
    get_test_help = getattr(module_args, "get_test_help", None)
    if get_test_help is None:
        return None
    codes = None
    for i, tok in enumerate(argv):
        if tok in ("-ts", "--tests"):
            if i + 1 < len(argv):
                codes = argv[i + 1]
            break
        if tok.startswith("-ts="):
            codes = tok[len("-ts="):]
            break
        if tok.startswith("--tests="):
            codes = tok[len("--tests="):]
            break
    if not codes:
        return None
    parsed = [c.strip().upper() for c in codes.split(",") if c.strip()]
    if not parsed or parsed == ["ALL"]:
        return None
    return get_test_help(parsed)


def _print_main_help() -> None:
    ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)


def _print_module_help(name: str, argv: list[str]) -> None:
    module_args = load_module(name).module_args()
    test_help = _extract_test_help(module_args, argv)
    help_obj = test_help if test_help is not None else module_args.get_help()
    ptprinthelper.help_print(help_obj, f"{SCRIPTNAME} {name}", __version__)


def _error_unknown_module(name: str) -> None:
    ptprinthelper.print_banner(SCRIPTNAME, __version__, False)
    print(f"\n\033[31m[✗]\033[0m Error: Unknown module '{name}'")
    print(f"\nAvailable modules: {', '.join(MODULES.keys())}")
    print(f"\nUse 'ptsrvtester -h' for help.\n")


def _friendly_error(message: str | None) -> str:
    """Rewrite argparse's wording into the Penterep 'Invalid option(s)' style."""
    if not message:
        return "Invalid arguments"
    if "unrecognized arguments:" in message:
        match = re.search(r"unrecognized arguments:\s*(.+)", message)
        return f"Invalid option(s): {match.group(1).strip() if match else message}"
    return message


def _global_parent() -> argparse.ArgumentParser:
    """Shared -j/-vv so they work both before and after the module name."""
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument("-j", "--json", action="store_true", help="use Penterep JSON output format")
    parent.add_argument("-vv", "--verbose", action="store_true", dest="debug", help="Enable verbose mode")
    return parent


def parse_args() -> BaseArgs:
    """Processes command line arguments.

    Resolves the module from argv first, then imports only that module and parses
    its options into a typed namespace. Help / version / unknown-module are handled
    without importing any module.

    Returns:
        BaseArgs: parsed arguments of the selected module.
    """
    argv = sys.argv[1:]

    if not argv:
        _print_main_help()
        sys.exit(0)

    module = next((tok.lower() for tok in argv if not tok.startswith("-")), None)
    wants_help = any(tok in ("-h", "--help", "--h", "-help") for tok in argv)
    wants_version = any(tok in ("-v", "--version") for tok in argv)

    if wants_version:
        print(f"{SCRIPTNAME} {__version__}")
        sys.exit(0)

    if wants_help:
        if module in MODULES:
            _print_module_help(module, argv)
        else:
            _print_main_help()
        sys.exit(0)

    if module is None:
        _print_main_help()
        sys.exit(0)

    if module not in MODULES:
        _error_unknown_module(module)
        sys.exit(2)

    if len(argv) == 1:
        _print_module_help(module, argv)
        sys.exit(0)

    parser = CustomArgumentParser(add_help=True, parents=[_global_parent()])
    subparsers = parser.add_subparsers(required=True, dest="module", parser_class=CustomArgumentParser)
    module_args = load_module(module).module_args()
    module_args.add_subparser(module, subparsers)
    subparsers.choices[module].add_argument("-j", "--json", action="store_true", default=argparse.SUPPRESS, help="use Penterep JSON output format")
    subparsers.choices[module].add_argument("-vv", "--verbose", action="store_true", dest="debug", default=argparse.SUPPRESS, help="Enable verbose mode")
    add_shared_rate_limit_args(subparsers.choices[module])

    _LAST_ERROR["message"] = None
    try:
        args = parser.parse_args(argv, namespace=module_args)
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else 2
        if code != 0:
            ptprinthelper.print_banner(SCRIPTNAME, __version__, False)
            print(f"\n\033[31m[✗]\033[0m Error: {_friendly_error(_LAST_ERROR['message'])}")
            print()
        sys.exit(code)

    ptprinthelper.print_banner(SCRIPTNAME, __version__, args.json)
    return args


def main() -> None:
    args = parse_args()

    script = Ptsrvtester(args)
    try:
        script.run()
    except argparse.ArgumentError as e:
        print(f"\n\033[31m[✗]\033[0m Error: {e.message}")
        print()
        sys.exit(2)
    except OSError as e:
        print(f"\n\033[31m[✗]\033[0m {e}")
        print()
        sys.exit(1)


if __name__ == "__main__":
    main()
