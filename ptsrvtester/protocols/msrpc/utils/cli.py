"""MSRPC CLI."""
from __future__ import annotations

import argparse

from ..._base import BaseArgs
from .helpers import valid_target

MSRPC_DEFAULT_SUITE = ("ENUMEPM",)


class MSRPCArgs(BaseArgs):
    target: object
    tests: str | None
    pipes: list | None
    username: str | None
    password: str | None
    username_file: str | None
    password_file: str | None
    pipe: str | None
    domain: str | None
    uuid: str | None
    output: str | None
    threads: int
    module_threads: int
    ip: str
    port: int | None
    verbose: bool

    @staticmethod
    def get_help():
        return [
            {"description": ["MSRPC Testing Module"]},
            {"usage": ["ptsrvtester msrpc -ts <test>[,...] -tg <host> <options>"]},
            {"usage_example": [
                "ptsrvtester msrpc -ts ENUMEPM -tg 192.168.1.1",
                "ptsrvtester msrpc -ts ENUMMGMT -tg 192.168.1.1",
                "ptsrvtester msrpc -ts ANONSMB -tg 192.168.1.1",
                "ptsrvtester msrpc -ts BRUTESMB -tg 192.168.1.1 -ul users.txt -pl passwords.txt",
            ]},
            {"options": [
                ["-ts", "--tests", "<test>", "ENUMEPM, ENUMMGMT, ENUMPIPES, ANONSMB, BRUTEPIPE, BRUTESMB, BRUTETCP, BRUTEHTTP"],
                ["-tg", "--target", "<host>", "IP[:PORT] (default 135; ANONSMB uses 445)"],
                ["", "--pipe", "<name>", "BRUTEPIPE: named pipe"],
                ["-d", "--domain", "<dom>", "Domain"],
                ["", "--uuid", "<uuid>", "BRUTETCP: interface UUID"],
                ["-u", "--username", "<user>", "Username"],
                ["-pw", "--password", "<pw>", "Password"],
                ["-ul", "--username_file", "<file>", "Username wordlist"],
                ["-pl", "--password_file", "<file>", "Password wordlist"],
                ["", "--threads", "<n>", "Brute threads (default 10)"],
                ["-o", "--output", "<file>", "Save results"],
                ["-j", "--json", "", "JSON output"],
                ["-h", "--help", "", "Show this help"],
            ]},
        ]

    def add_subparser(self, name, subparsers):
        examples = """example usage:
  ptsrvtester msrpc -ts ENUMEPM -tg 192.168.1.1
  ptsrvtester msrpc -ts ANONSMB -tg 192.168.1.1
  ptsrvtester msrpc -ts BRUTESMB -tg 192.168.1.1 -ul users.txt -pl passwords.txt"""
        p = subparsers.add_parser(
            name, add_help=True, epilog=examples, formatter_class=argparse.RawTextHelpFormatter
        )
        p.add_argument(
            "-tg", "--target", type=lambda t: valid_target(t, domain_allowed=True),
            required=True, dest="target",
        )
        p.add_argument("-ts", "--tests", default=None, dest="tests")
        p.add_argument("--pipe", dest="pipe", default=None)
        p.add_argument("-d", "--domain", dest="domain", default=None)
        p.add_argument("--uuid", dest="uuid", default=None)
        p.add_argument("-u", "--username", dest="username", default=None)
        p.add_argument("-pw", "--password", dest="password", default=None)
        p.add_argument("-ul", "--username_file", dest="username_file", default=None)
        p.add_argument("-pl", "--password_file", dest="password_file", default=None)
        p.add_argument("--threads", type=int, default=10, dest="threads")
        p.add_argument("-o", "--output", dest="output", default=None)
        p.add_argument("--module-threads", type=int, default=1, dest="module_threads", help=argparse.SUPPRESS)
