"""DNS CLI: the ``DNSArgs`` argparse namespace and its help.

Tests are selected with ``-ts/--tests`` (codes matched against the modules'
``__MODULECODE__`` by :class:`BaseMain`). Mirrors ``ssh/utils/cli.py``.

Universal options (``-tg`` target, ``-ts`` tests, ``-o`` output) plus the input
options the enumeration modules consume (``-d`` domain, ``-r`` range, ``-sub``
wordlist, ``-rec`` record types, ``--dkim-selectors``). When a module is added,
register it in ``registry.py`` and add any new input options here.
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
    domain: str | None
    domain_file: str | None
    records: list[str] | None
    ip_range: str | None
    subdomains: str | None
    threads: int
    dkim_selectors: list[str] | None

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
            [get_colored_text("Enumeration inputs", "TITLE")],
            ["-d", "--domain", "<domain>", "Domain (RECORDS, WHOIS, BRUTESUB, EMAILSEC, CAA, WILDCARD)"],
            ["-dl", "--domain-file", "<file>", "File with domains"],
            ["-rec", "--records", "<type...>", "RECORDS: record types (default: A AAAA MX TXT CNAME NS SRV SOA)"],
            ["-r", "--range", "<range>", "PTRSWEEP: IP, CIDR (192.0.2.0/24) or start-end (192.0.2.1-50)"],
            ["-sub", "--subdomains", "<wordlist>", "BRUTESUB: subdomain label wordlist"],
            ["", "--brute-threads", "<n>", "BRUTESUB/PTRSWEEP threads (default: 10)"],
            ["", "--dkim-selectors", "<sel...>", "EMAILSEC: DKIM selectors to try (default: common list)"],
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
                "ptsrvtester dns -ts RECORDS,EMAILSEC,CAA -d example.com",
                "ptsrvtester dns -ts BRUTESUB -d example.com -sub subs.txt",
                "ptsrvtester dns -ts PTRSWEEP -r 192.0.2.0/24",
                "ptsrvtester dns -ts AXFR,IXFR -d zonetransfer.me",
                "ptsrvtester dns -ts RECURSION,AMPLIFICATION,CACHESNOOP -tg 8.8.8.8",
                "ptsrvtester dns -ts COOKIES -tg 8.8.8.8",
                "ptsrvtester dns -ts DNSSEC,DNSSECALG,RRSIG,CHAIN,NSEC -d cloudflare.com",
                "ptsrvtester dns -ts ZONEWALK,NSEC3CRACK -d nic.cz -sub subs.txt",
                "ptsrvtester dns -ts EMAILSEC -h",
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
  ptsrvtester dns -ts RECORDS,EMAILSEC,CAA -d example.com
  ptsrvtester dns -ts BRUTESUB -d example.com -sub subs.txt
  ptsrvtester dns -ts PTRSWEEP -r 192.0.2.0/24
  ptsrvtester dns -ts AXFR,IXFR -d zonetransfer.me
  ptsrvtester dns -ts EMAILSEC -h"""

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

        inputs = parser.add_argument_group("Enumeration inputs")
        inputs.add_argument("-d", "--domain", type=str, default=None, dest="domain",
                            metavar="<domain>", help="Domain (RECORDS/WHOIS/BRUTESUB/EMAILSEC/CAA/WILDCARD)")
        inputs.add_argument("-dl", "--domain-file", type=str, default=None, dest="domain_file",
                            metavar="<file>", help="File with domains")
        inputs.add_argument("-rec", "--records", nargs="+", default=None, dest="records",
                            metavar="<type>", help="RECORDS: record types (default: common set)")
        inputs.add_argument("-r", "--range", type=str, default=None, dest="ip_range",
                            metavar="<range>", help="PTRSWEEP: IP, CIDR or start-end")
        inputs.add_argument("-sub", "--subdomains", type=str, default=None, dest="subdomains",
                            metavar="<wordlist>", help="BRUTESUB: subdomain label wordlist")
        inputs.add_argument("--brute-threads", type=int, default=10, dest="threads",
                            metavar="<n>", help="BRUTESUB/PTRSWEEP threads (default: 10)")
        inputs.add_argument("--dkim-selectors", nargs="+", default=None, dest="dkim_selectors",
                            metavar="<sel>", help="EMAILSEC: DKIM selectors to try (default: common list)")

        output = parser.add_argument_group("Output")
        output.add_argument(
            "-o", "--output", type=str, default=None, dest="output",
            metavar="<file>", help="Append results to a file",
        )

        parser.add_argument(
            "--module-threads", type=int, default=1, dest="module_threads",
            help=argparse.SUPPRESS,
        )
