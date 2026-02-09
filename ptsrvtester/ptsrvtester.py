#!/usr/bin/python3
"""
    Copyright (c) 2024 Penterep Security s.r.o.

    ptapptest-plus - Application Server Penetration Testing Tool

    ptapptest-plus is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    ptapptest-plus is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with ptapptest-plus.  If not, see <https://www.gnu.org/licenses/>.
"""

import argparse
import re
import sys

from ptlibs import ptprinthelper, ptjsonlib


from ._version import __version__
from .modules.snmp import SNMP
from .modules._base import BaseArgs
from .modules.dns import DNS
from .modules.ldap import LDAP
from .modules.msrpc import MSRPC
from .modules.ftp import FTP
from .modules.ssh import SSH
from .modules.smtp import SMTP
from .modules.pop3 import POP3
from .modules.imap import IMAP
from .modules.dhcp import DHCP
from .modules.xrdp import XRDP

SCRIPTNAME = "ptsrvtester"

MODULES = {
    "snmp": SNMP,
    "dns": DNS,
    "ldap": LDAP,
    "msrpc": MSRPC,
    "ftp": FTP,
    "ssh": SSH,
    "smtp": SMTP,
    "pop3": POP3,
    "imap": IMAP,
    "dhcp": DHCP,
    "xrdp": XRDP,
}


class Ptsrvtester:
    def __init__(self, args: BaseArgs) -> None:
        self.args = args

    def run(self) -> None:
        """Runs selected module with its configured arguments"""
        # Initialize JSON data
        ptjson = ptjsonlib.PtJsonLib()

        # Run the selected module
        module = MODULES[self.args.module](self.args, ptjson)
        module.run()
        module.output()


def get_help():
    return [
        {"description": ["Server Penetration Testing Tool"]},
        {"usage": ["ptsrvtester <module> <options>"]},
        {"usage_example": [
            "ptsrvtester snmp detection --ip 192.168.1.1",
            "ptsrvtester <module> -h     for help for module use"
        ]},
        {"options": [
            ["snmp", "<options>", "", "SNMP testing module"],
            ["dns", "<options>", "", "DNS testing module"],
            ["ldap", "<options>", "", "LDAP testing module"],
            ["msrpc", "<options>", "", "MSRPC testing module"],
            ["ftp", "<options>", "", "FTP testing module"],
            ["ssh", "<options>", "", "SSH testing module"],
            ["smtp", "<options>", "", "SMTP testing module"],
            ["pop3", "<options>", "", "POP3 testing module"],
            ["imap", "<options>", "", "IMAP testing module"],
            ["dhcp", "<options>", "", "DHCP testing module"],
            ["xrdp", "<options>", "", "XRDP testing module"],
            ["", " ", "", ""],
            ["-v", "--version", "", "Show script version and exit"],
            ["-h", "--help", "", "Show this help message and exit"],
            ["-j", "--json", "", "Output in JSON format"],
            ["", "--debug", "", "Enable debug messages"],
        ]
        }]


def parse_args() -> BaseArgs:
    """Processes command line arguments

    Returns:
        BaseArgs: parsed arguments of the selected module
    """
    
    # Check for help flag before argparse processing
    # Case 1: No arguments at all - show main help
    if len(sys.argv) == 1:
        ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(0)
    
    # Normalize module name to lowercase (case-insensitive module names)
    if len(sys.argv) >= 2 and not sys.argv[1].startswith("-"):
        sys.argv[1] = sys.argv[1].lower()
    
    # Case 2: Only module specified without arguments - show module help
    if len(sys.argv) == 2 and sys.argv[1] in MODULES:
        module_name = sys.argv[1]
        module_help = MODULES[module_name].module_args().get_help()
        ptprinthelper.help_print(module_help, f"{SCRIPTNAME} {module_name}", __version__)
        sys.exit(0)
    
    # Case 2b: Non-existent module (e.g. ptsrvtester FOO) - show banner, error, and our help
    if len(sys.argv) == 2 and sys.argv[1] not in MODULES and not sys.argv[1].startswith("-"):
        ptprinthelper.print_banner(SCRIPTNAME, __version__, False)
        print(f"\n\033[31m[✗]\033[0m Error: Unknown module '{sys.argv[1]}'")
        print(f"\nAvailable modules: {', '.join(MODULES.keys())}")
        print(f"\nUse 'ptsrvtester -h' for help.\n")
        sys.exit(2)
    
    # Case 3: Help flag present
    if "-h" in sys.argv or "--help" in sys.argv or "--h" in sys.argv or "-help" in sys.argv:
        # Check if module is specified
        if len(sys.argv) >= 2 and sys.argv[1] in MODULES:
            # Show module-specific help
            module_name = sys.argv[1]
            module_help = MODULES[module_name].module_args().get_help()
            ptprinthelper.help_print(module_help, f"{SCRIPTNAME} {module_name}", __version__)
            sys.exit(0)
        else:
            # Show main help
            ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
            sys.exit(0)

    # Shared error message storage
    shared_error = {'message': None}
    
    # Custom ArgumentParser that stores error message
    class CustomArgumentParser(argparse.ArgumentParser):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.error_message = None
            # Override parser_class for subparsers
            if 'parser_class' not in kwargs:
                kwargs['parser_class'] = CustomArgumentParser
            
        def error(self, message):
            # Store error message in both instance and shared storage
            self.error_message = message
            shared_error['message'] = message
            raise SystemExit(2)
        
        def parse_args(self, *args, **kwargs):
            try:
                return super().parse_args(*args, **kwargs)
            except argparse.ArgumentError as e:
                # Store the error message before it gets lost
                self.error_message = e.message
                # Re-raise to let argparse handle it normally
                raise
    
    parser = CustomArgumentParser(add_help=True)

    parser.add_argument(
        "-v", "--version", action="version", version=f"%(prog)s {__version__}", help="print version"
    )
    parser.add_argument("-j", "--json", action="store_true", help="use Penterep JSON output format")
    parser.add_argument("--debug", action="store_true", help="enable debug messages")

    # Subparser for every application module
    subparsers = parser.add_subparsers(required=True, dest="module", parser_class=CustomArgumentParser)
    for name, module in MODULES.items():
        module.module_args().add_subparser(name, subparsers)
    # Global options must be on each subparser too (subparser parses the remainder of argv)
    for subp in subparsers.choices.values():
        subp.add_argument("-j", "--json", action="store_true", help="use Penterep JSON output format")
        subp.add_argument("--debug", action="store_true", help="enable debug messages")

    # First parse to get the module name, second parse to get the module-specific arguments
    try:
        args = parser.parse_args(namespace=BaseArgs)
        args = parser.parse_args(namespace=MODULES[args.module].module_args())
    except (SystemExit, argparse.ArgumentError) as e:
        # Argparse error occurred
        error_code = e.code if isinstance(e, SystemExit) else 2
        
        if error_code != 0:  # 0 means success (e.g., --version was called)
            # Print banner first
            ptprinthelper.print_banner(SCRIPTNAME, __version__, False)
            
            # Get error message
            error_msg = None
            if isinstance(e, argparse.ArgumentError):
                error_msg = e.message
            elif isinstance(e, SystemExit):
                # Check shared error message (set by any CustomArgumentParser instance)
                if shared_error['message']:
                    error_msg = shared_error['message']
                # Fallback to parser error message
                elif hasattr(parser, 'error_message') and parser.error_message:
                    error_msg = parser.error_message
            
            # Make error message user-friendly for invalid options
            if error_msg and "unrecognized arguments:" in error_msg:
                match = re.search(r"unrecognized arguments:\s*(.+)", error_msg)
                invalid = match.group(1).strip() if match else error_msg
                error_msg = f"Invalid option(s): {invalid}"
            elif error_msg and "the following arguments are required:" in error_msg:
                # "required: target" is misleading when user typed invalid option (e.g. -dfsdfs)
                # Only flag as invalid if option looks suspicious: -xxx with >2 letters (not -i, -sd)
                invalid_arg = None
                if len(sys.argv) >= 3 and sys.argv[1] in MODULES:
                    for arg in sys.argv[2:]:
                        if arg.startswith("-") and not arg.startswith("--"):
                            if len(arg) > 4:
                                invalid_arg = arg
                                break
                if invalid_arg:
                    error_msg = f"Invalid option: {invalid_arg}"
            
            # Always show error message (no help on error)
            if error_msg:
                print(f"\n\033[31m[✗]\033[0m Error: {error_msg}")
            else:
                print(f"\n\033[31m[✗]\033[0m Error: Invalid arguments")
            print()
        sys.exit(error_code)

    ptprinthelper.print_banner(SCRIPTNAME, __version__, args.json)
    

    return args


def main() -> None:
    args = parse_args()

    script = Ptsrvtester(args)
    try:
        script.run()
    except argparse.ArgumentError as e:
        # Module raised ArgumentError - error only (banner already printed after parse_args)
        print(f"\n\033[31m[✗]\033[0m Error: {e.message}")
        print()
        sys.exit(2)


if __name__ == "__main__":
    main()
