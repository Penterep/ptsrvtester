"""DNS CLI: the ``DNSArgs`` argparse namespace and its help.

Tests are selected with ``-ts/--tests`` (codes matched against the modules'
``__MODULECODE__`` by :class:`BaseMain`). Mirrors ``ssh/utils/cli.py``.

Empty skeleton: only the universal options are defined (target, test selection,
output). When modules are added, register them in ``registry.py`` (so they show
in the help) and add any per-module input options to :meth:`add_subparser`.
"""
import argparse

from ptlibs.ptprinthelper import get_colored_text

from ..._base import BaseArgs
from .helpers import Target, valid_target
from .registry import DNS_TEST_GROUPS, DNS_TESTS, dns_test_help

__all__ = ["DNSArgs", "valid_target_dns"]


def valid_target_dns(target: str) -> Target:
    """argparse helper: IP or hostname with an optional port."""
    return valid_target(target, domain_allowed=True)


class DNSArgs(BaseArgs):
    tests: str | None
    target: Target | None
    output: str | None
    module_threads: int

    @staticmethod
    def get_help():
        options: list[list[str]] = [
            ["-tg", "--target", "<server>", "DNS server IP[:PORT] to query (default port 53; optional — else system resolver)"],
            ["-ts", "--tests", "<test>", "One or more tests, comma-separated; ALL runs everything:"],
        ]
        for group_title, codes in DNS_TEST_GROUPS:
            options.append(["", "", "", ""])
            options.append(["", "", get_colored_text(group_title, "TITLE")])
            for code in codes:
                options.append(["", "", code, DNS_TESTS[code]["desc"]])

        options += [
            ["", "", "", ""],
            [get_colored_text("Output", "TITLE")],
            ["-o", "--output", "<file>", "Append results to a file"],
            ["-j", "--json", "", "Output in JSON format"],
            ["-vv", "--verbose", "", "Enable verbose mode"],
            ["-v", "--version", "", "Show version and exit"],
            ["-h", "--help", "", "Show this help; 'dns -ts <TEST> -h' for test options"],
        ]

        return [
            {"description": ["DNS Testing Module"]},
            {"usage": ["ptsrvtester dns -ts <test>[,<test>...] <options>"]},
            {"usage_example": [
                "ptsrvtester dns -tg 8.8.8.8 -ts ALL",
                "ptsrvtester dns -tg 8.8.8.8 -ts VERSION,NSID,EDNS",
                "ptsrvtester dns -tg ns1.example.com -ts ROLE,TRANSPORT",
                "ptsrvtester dns -tg 8.8.8.8 -ts CVE",
                "ptsrvtester dns -ts VERSION -h",
            ]},
            {"options": options},
        ]

    @staticmethod
    def get_test_help(codes):
        """Per-test help object (used by ``dns -ts <TEST> -h``)."""
        return dns_test_help(codes)

    def add_subparser(self, name: str, subparsers) -> None:
        examples = """example usage:
  ptsrvtester dns -h
  ptsrvtester dns -tg 8.8.8.8 -ts ALL
  ptsrvtester dns -tg 8.8.8.8 -ts VERSION,NSID,EDNS
  ptsrvtester dns -tg ns1.example.com -ts ROLE,TRANSPORT
  ptsrvtester dns -ts VERSION -h"""

        parser = subparsers.add_parser(
            name,
            epilog=examples,
            add_help=True,
            formatter_class=argparse.RawTextHelpFormatter,
        )

        if not isinstance(parser, argparse.ArgumentParser):
            raise TypeError  # IDE typing

        parser.add_argument(
            "-tg",
            "--target",
            type=valid_target_dns,
            default=None,
            metavar="<server>",
            dest="target",
            help="DNS server IP[:PORT] to query (default port 53; optional)",
        )
        parser.add_argument(
            "-ts",
            "--tests",
            type=str,
            default=None,
            metavar="<test>",
            dest="tests",
            help="Comma-separated test codes or ALL; 'dns -ts <TEST> -h' for test options",
        )

        output = parser.add_argument_group("Output")
        output.add_argument(
            "-o", "--output", type=str, default=None, dest="output",
            metavar="<file>", help="Append results to a file",
        )

        parser.add_argument(
            "--module-threads", type=int, default=1, dest="module_threads",
            help=argparse.SUPPRESS,
        )
