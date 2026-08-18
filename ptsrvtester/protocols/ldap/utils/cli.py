"""LDAP CLI."""
from __future__ import annotations

import argparse

from ..._base import BaseArgs
from .helpers import valid_target

LDAP_DEFAULT_SUITE = ("BANNER",)


class LDAPArgs(BaseArgs):
    target: object
    tests: str | None
    use_ssl: bool
    spray: bool
    output: str | None
    base_dn: str | None
    upn_domain: str | None
    username_file: str | None
    password_file: str | None
    user: str | None
    password: str | None
    ldap_filter: str
    attributes: list | None
    cn_uid: list
    target_dn: str | None
    attribute: str
    test_value: str | None
    threads: int
    module_threads: int
    ip: str
    port: int

    @staticmethod
    def get_help():
        return [
            {"description": ["LDAP Testing Module"]},
            {"usage": ["ptsrvtester ldap -ts <test>[,...] -tg <host> <options>"]},
            {"usage_example": [
                "ptsrvtester ldap -ts BANNER -tg 192.168.1.1",
                "ptsrvtester ldap -ts SEARCH -tg 192.168.1.1 -bd dc=example,dc=com",
                "ptsrvtester ldap -ts USERENUM -tg 192.168.1.1 -ul users.txt -bd dc=example,dc=com",
                "ptsrvtester ldap -ts BRUTE -tg 192.168.1.1 -ul users.txt -pl passwords.txt",
            ]},
            {"options": [
                ["-ts", "--tests", "<test>", "BANNER, SEARCH, USERENUM, BRUTE, WRITETEST (ALL=BANNER)"],
                ["-tg", "--target", "<host>", "IP[:PORT] or HOST[:PORT] (default port 389)"],
                ["", "--ssl", "", "Use SSL"],
                ["-u", "--user", "<dn>", "Bind username / DN"],
                ["-pw", "--password", "<pw>", "Bind password"],
                ["-bd", "--base-dn", "<dn>", "Base DN"],
                ["-f", "--filter", "<filt>", "SEARCH: LDAP filter"],
                ["-a", "--attributes", "<attrs>", "SEARCH: attributes"],
                ["-ul", "--username_file", "<file>", "USERENUM/BRUTE: username list"],
                ["-pl", "--password_file", "<file>", "BRUTE: password list"],
                ["-upn", "--upn-domain", "<dom>", "BRUTE: UPN domain"],
                ["", "--spray", "", "BRUTE: password spray"],
                ["", "--threads", "<n>", "BRUTE threads (default 10)"],
                ["-tdn", "--target-dn", "<dn>", "WRITETEST: target DN"],
                ["", "--attr", "<a>", "WRITETEST: attribute"],
                ["", "--val", "<v>", "WRITETEST: test value"],
                ["-o", "--output", "<file>", "Save results"],
                ["-j", "--json", "", "JSON output"],
                ["-h", "--help", "", "Show this help"],
            ]},
        ]

    def add_subparser(self, name, subparsers):
        examples = """example usage:
  ptsrvtester ldap -ts BANNER -tg 192.168.1.1
  ptsrvtester ldap -ts SEARCH -tg 192.168.1.1 -bd "dc=example,dc=com"
  ptsrvtester ldap -ts BRUTE -tg 192.168.1.1 -ul users.txt -pl passwords.txt"""
        p = subparsers.add_parser(
            name, add_help=True, epilog=examples, formatter_class=argparse.RawTextHelpFormatter
        )
        p.add_argument(
            "-tg", "--target", type=lambda t: valid_target(t, domain_allowed=True),
            required=True, dest="target",
        )
        p.add_argument("-ts", "--tests", default=None, dest="tests")
        p.add_argument("--ssl", action="store_true", dest="use_ssl")
        p.add_argument("-u", "--user", dest="user", default=None)
        p.add_argument("-pw", "--password", dest="password", default=None)
        p.add_argument("-bd", "--base-dn", dest="base_dn", default=None)
        p.add_argument("-f", "--filter", dest="ldap_filter", default="(objectClass=*)")
        p.add_argument("-a", "--attributes", nargs="+", dest="attributes", default=None)
        p.add_argument("-ul", "--username_file", dest="username_file", default=None)
        p.add_argument("-pl", "--password_file", dest="password_file", default=None)
        p.add_argument("-upn", "--upn-domain", dest="upn_domain", default=None)
        p.add_argument("--spray", action="store_true", dest="spray")
        p.add_argument("--threads", type=int, default=10, dest="threads")
        p.add_argument("-tdn", "--target-dn", dest="target_dn", default=None)
        p.add_argument("--attr", dest="attribute", default="sn")
        p.add_argument("--val", dest="test_value", default=None)
        p.add_argument("-o", "--output", dest="output", default=None)
        p.add_argument("-cnuid", nargs="+", dest="cn_uid", default=["uid", "cn"], help=argparse.SUPPRESS)
        p.add_argument("--module-threads", type=int, default=1, dest="module_threads", help=argparse.SUPPRESS)
