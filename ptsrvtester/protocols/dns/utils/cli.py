"""DNS CLI."""
from __future__ import annotations

import argparse

from ..._base import BaseArgs
from .helpers import valid_target

DNS_DEFAULT_SUITE = ("INFO",)


class DNSArgs(BaseArgs):
    target: object | None
    tests: str | None
    ip: str | None
    port: int
    domain: str | None
    subdomains: str | None
    ip_file: str | None
    domain_file: str | None
    output: str | None
    threads: int
    lookup_records: list | None
    module_threads: int

    @staticmethod
    def get_help():
        return [
            {"description": ["DNS Testing Module"]},
            {"usage": ["ptsrvtester dns -ts <test>[,...] <options>"]},
            {"usage_example": [
                "ptsrvtester dns -ts INFO -tg 8.8.8.8",
                "ptsrvtester dns -ts LOOKUP -d example.com",
                "ptsrvtester dns -ts WHOIS -d example.com",
                "ptsrvtester dns -ts ZONEXFR -d example.com",
                "ptsrvtester dns -ts BRUTESUB -d example.com -sub wordlist.txt",
            ]},
            {"options": [
                ["-ts", "--tests", "<test>", "INFO, REVERSE, ZONEXFR, LOOKUP, WHOIS, BRUTESUB, DNSSEC, ZONEWALK, ZONEWALKFULL"],
                ["-tg", "--target", "<host>", "DNS server IP[:PORT] (INFO/REVERSE; default port 53)"],
                ["-ip", "--ip", "<ip>", "Alias for target IP (legacy)"],
                ["-ips", "--ip_file", "<file>", "File with DNS server IPs"],
                ["-d", "--domain", "<dom>", "Domain name"],
                ["-dl", "--domain_file", "<file>", "File with domains"],
                ["-sub", "--subdomains", "<file>", "BRUTESUB: subdomain wordlist"],
                ["-rec", "--lookup-records", "<t>", "LOOKUP: record types"],
                ["", "--threads", "<n>", "BRUTESUB threads (default 10)"],
                ["-o", "--output", "<file>", "Save results"],
                ["-j", "--json", "", "JSON output"],
                ["-h", "--help", "", "Show this help"],
            ]},
        ]

    def add_subparser(self, name, subparsers):
        examples = """example usage:
  ptsrvtester dns -ts INFO -tg 8.8.8.8
  ptsrvtester dns -ts LOOKUP -d example.com
  ptsrvtester dns -ts ZONEXFR -d example.com
  ptsrvtester dns -ts BRUTESUB -d example.com -sub subs.txt"""
        p = subparsers.add_parser(
            name, add_help=True, epilog=examples, formatter_class=argparse.RawTextHelpFormatter
        )
        p.add_argument(
            "-tg", "--target", type=lambda t: valid_target(t, domain_allowed=True),
            default=None, dest="target",
        )
        p.add_argument("-ts", "--tests", default=None, dest="tests")
        p.add_argument("-ip", "--ip", dest="ip", default=None)
        p.add_argument("-p", "--port", type=int, default=53, dest="port")
        p.add_argument("-ips", "--ip_file", dest="ip_file", default=None)
        p.add_argument("-d", "--domain", dest="domain", default=None)
        p.add_argument("-dl", "--domain_file", dest="domain_file", default=None)
        p.add_argument("-sub", "--subdomains", dest="subdomains", default=None)
        p.add_argument("-rec", "--lookup-records", nargs="+", dest="lookup_records", default=None)
        p.add_argument("--threads", type=int, default=10, dest="threads")
        p.add_argument("-o", "--output", dest="output", default=None)
        p.add_argument("--module-threads", type=int, default=1, dest="module_threads", help=argparse.SUPPRESS)
