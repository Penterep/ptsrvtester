import argparse

from ptlibs.ptprinthelper import get_colored_text
from ptsrvtester.protocols.dhcp.utils.registry import (
    TargetDHCP,
    valid_interface,
    is_valid_mac_address,
    is_valid_xid,
    is_valid_ip
)
from ptsrvtester.protocols._base import BaseArgs

__all__ = ['DHCPArgs']


DHCP_TEST_GROUPS = [
    ("Enumeration", ["SERVER_INFO"]),
    ("Denial-of-Service", ["DENIAL", "STARVATION"])
]

# Per-test definitions:
#   desc      one-line description for the main -ts table
#   long      list of <=3 lines describing what the test does (per-test help)
#   flags     dict dest->value applied to the args namespace when selected
#   value     (dest, default) for tests whose flag carries a value (default set if None)
#   requires  human-readable prerequisite strings (per-test help)
DHCP_TESTS: dict[str, dict] = {
    "SERVER_INFO": {
        "desc": "DHCP server enumeration",
        "long": ["Discovers information about a DHCP server"],
        "mods": [
            ["-t", "--timeout", "", "Timeout for DHCP offer reply (default: 10s)"],
            ["-mac", "--mac-address", "", "Source MAC address to use"],
            ["-xid", "--transaction-id", "", "Transaction ID to use"]
        ],
        "requires": [
            ["-i", "--interface", "", "Network interface to use"]
        ],
        "usage": [
            "-i eth0",
            "-i eth0 -t 5",
            "-i eth0 -t5 -mac 01:23:45:67:89:aa -xid 5"
        ],
        "flags": {"server_info": True}
    },
    "DENIAL": {
        "desc": "DHCP flood attack",
        "long": ["Floods the target with DHCPDISCOVER packets to overwhelm him"],
        "mods": [
            ["-c", "--count", "", "Number of IP addresses to obtain (omit for unlimited)"],
            ["-mac", "--mac-address", "", "Source MAC address to use"],
            ["-xid", "--transaction-id", "", "Transaction ID to use"]
        ],
        "requires": [
            ["-i", "--interface", "", "Network interface to use"]
        ],
        "usage": [
            "-i eth0",
            "-i eth0 -c 4",
        ],
        "flags": {"denial": True}
    },
    "STARVATION": {
        "desc": "DHCP starvation attack",
        "long": ["Starves the available IP address pool of a DHCP server"],
        "mods": [
            ["-d", "--duration", "", "Duration in seconds (omit for unlimited)"],
            ["-mac", "--mac-address", "", "Source MAC address to use"],
            ["-xid", "--transaction-id", "", "Transaction ID to use"]
        ],
        "requires": [
            ["-i", "--interface", "", "Network interface to use"]
        ],
        "usage": [
            "-i eth0",
            "-i eth0 -d 5",
        ],
        "flags": {"starvation": True}
    }
}
#   common    True -> append common outbound message options to per-test help
#   mods      test-specific option rows [short, long, metavar, help] (per-test help)

def _dhcp_test_help(codes: list[str]):
    """Build a help object (for ptprinthelper.help_print) describing given test codes."""
    if not codes:
        return None
    valid = [c for c in codes if c in DHCP_TESTS]
    if not valid:
        available = ", ".join(sorted(DHCP_TESTS))
        return [
            {"unknown_test": [f"Unknown test: {', '.join(codes)}"]},
            {"available_tests": [f"ALL, {available}"]},
        ]
    out: list[dict] = []
    for code in valid:
        spec = DHCP_TESTS[code]
        header = f"{code} — {spec.get('desc', '')}"
        out.append({"test": [header, *spec.get("long", [])]})
        req = list(spec.get("requires", []))
        if req:
            out.append({"requires": req})
        rows: list[list[str]] = list(spec.get("mods", []))

        if rows:
            out.append({"test_options": rows})
        has_opts = bool(rows or req)
        usage = [f"ptsrvtester SNMP -ts {code} " + example + '\n ' for example in spec.get("usage", "")]
        usage[-1] = usage[-1].rstrip("\n ")
        out.append({"usage": [usage]})
    return out

def valid_target_dhcp(target: str) -> TargetDHCP:
    return valid_interface(target)

class DHCPArgs(BaseArgs):
    interface: str
    command: str
    timeout: int
    duration: int
    count: int
    start_ip: str
    end_ip: str
    netmask: str
    gateway: str
    server_ip: str
    lease_time: int
    renew_time: int
    rebind_time: int

    @staticmethod
    def get_test_help(codes):
        return _dhcp_test_help(codes)

    @staticmethod
    def get_help():
        options: list[list[str]] = [
            ["-ts", "--tests", "<test>", "One or more tests, comma-separated (e.g. SERVER_INFO, STARVATION); ALL runs everything:"],
        ]

        for group_title, codes in DHCP_TEST_GROUPS:
            options.append(["", "", "", ""])
            options.append(["", "", get_colored_text(group_title, "TITLE")])
            for code in codes:
                options.append(["", "", code, DHCP_TESTS[code]["desc"]])

        options += [
                ["", "", "", ""],
                ["-h", "--help", "", "Show this help message and exit"],
                ["-vv", "--verbose", "", "Enable verbose mode"],
                ["-i", "--interface", "", "Network interface to use"],
                ["-j", "--json", "", "Output in JSON format"],
        ]

        return [
            {"description": ["DHCP Testing Module"]},
            {"usage": ["ptsrvtester dhcp <command> <options>"]},
            {"usage_example": [
                "ptsrvtester dhcp -ts server_info -i eth0",
                "ptsrvtester dhcp -ts starvation --interface eth0 --count 10",
                "ptsrvtester dhcp -ts denial -i eth0 --duration 30"
            ]},
            {"options": options}
        ]

    def add_subparser(self, name: str, subparsers) -> None:
        """Adds a subparser of DHCP arguments"""

        examples = """example usage:
  ptsrvtester dhcp -ts server_info --interface eth0
  ptsrvtester dhcp -ts starvation --interface eth0 --count 10
  ptsrvtester dhcp -ts denial --interface eth0 --duration 30"""

        dhcp_subparsers = subparsers.add_parser(
            name,
            epilog=examples,
            add_help=True,
            formatter_class=argparse.RawTextHelpFormatter,
        )

        if not isinstance(dhcp_subparsers, argparse.ArgumentParser):
            raise TypeError

        dhcp_subparsers.add_argument("-i", "--interface",
                                     type=valid_target_dhcp,
                                     help="Network interface to use",
                                     required=True
                                     )

        dhcp_subparsers.add_argument("-w", "--write-to-file", help="File to save the output results.",
                                                                          default=None,
                                                                          type=str)

        dhcp_subparsers.add_argument(
            "-ts",
            "--tests",
            type=str,
            #nargs="+",
            default=None,
            metavar="<test>",
            dest="tests",
            help="Comma-separated test codes (e.g. version,v2brute) or ALL; 'smtp -ts <TEST> -h' for test options",
        )


        dhcp_subparsers.add_argument(
            "-xid",
            "--transaction-id",
            default=None,
            help="Transaction ID to use",
            type=is_valid_xid
        )

        dhcp_subparsers.add_argument(
            "-mac",
            "--mac-address",
            default=None,
            help="MAC address to use",
            type=is_valid_mac_address
        )

        dhcp_subparsers.add_argument(
            "-giaddr",
            "--gateway-ip-address",
            default=None,
            help="Gateway IP address to use",
            type=is_valid_ip
        )

        # DHCP info
        dhcp_info = dhcp_subparsers.add_argument_group("info", description="Display DHCP server information")
        #dhcp_info.add_argument("--interface", "-i", required=True, help="Network interface to use")
        dhcp_info.add_argument("--timeout", "-t", type=int, default=10, help="Timeout for DHCP offer reply (default: 10s)")

        # DHCP starvation
        dhcp_starve = dhcp_subparsers.add_argument_group("starve", description="Run DHCP starvation attack")
        #dhcp_starve.add_argument("--interface", "-i", required=True, help="Network interface to use")
        dhcp_starve.add_argument("--count", "-c", type=int, help="Number of IP addresses to obtain (omit for unlimited)")

        # DHCP denial
        dhcp_denial = dhcp_subparsers.add_argument_group("denial", description="Run DHCP DoS flood attack")
        #dhcp_denial.add_argument("--interface", "-i", required=True, help="Network interface to use")
        dhcp_denial.add_argument("--duration", "-d", type=int, help="Duration in seconds (omit for unlimited)")

# endregion
