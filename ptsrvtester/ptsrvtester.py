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
            ["<module>", "", "", "Select module to use"],
            ["", " ", " snmp", "SNMP testing module"],
            ["", " ", " dns", "DNS testing module"],
            ["", " ", " ldap", "LDAP testing module"],
            ["", " ", " msrpc", "MSRPC testing module"],
            ["", " ", " ftp", "FTP testing module"],
            ["", " ", " ssh", "SSH testing module"],
            ["", " ", " smtp", "SMTP testing module"],
            ["", " ", " pop3", "POP3 testing module"],
            ["", " ", " imap", "IMAP testing module"],
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
    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        # Only show main help if no module is specified
        if len(sys.argv) <= 2:
            ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
            sys.exit(0)

    parser = argparse.ArgumentParser(add_help=True)

    parser.add_argument(
        "-v", "--version", action="version", version=f"%(prog)s {__version__}", help="print version"
    )
    parser.add_argument("-j", "--json", action="store_true", help="use Penterep JSON output format")
    parser.add_argument("--debug", action="store_true", help="enable debug messages")

    # Subparser for every application module
    subparsers = parser.add_subparsers(required=True, dest="module")
    for name, module in MODULES.items():
        module.module_args().add_subparser(name, subparsers)

    # First parse to get the module name, second parse to get the module-specific arguments
    args = parser.parse_args(namespace=BaseArgs)
    args = parser.parse_args(namespace=MODULES[args.module].module_args())

    ptprinthelper.print_banner(SCRIPTNAME, __version__, args.json)
    

    return args


def main() -> None:
    global SCRIPTNAME
    SCRIPTNAME = "ptsrvtester"
    args = parse_args()

    script = Ptsrvtester(args)
    script.run()


if __name__ == "__main__":
    main()
