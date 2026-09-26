"""Command-line arguments for targeted IPv4 UPnP/SSDP discovery."""

from __future__ import annotations

import argparse
import ipaddress
import math
import re
from dataclasses import dataclass

from ..._base import BaseArgs


@dataclass
class Target:
    ip: str
    port: int = 0


_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_TESTS = frozenset({"DISCOVER", "DESCRIBE"})


def valid_target(value: str) -> Target:
    """Accept one IPv4 address or hostname with an optional UDP port."""
    raw = value.strip()
    if not raw or raw.count(":") > 1:
        raise argparse.ArgumentTypeError("target must be IPv4 or HOST[:PORT]")
    host, separator, port_text = raw.partition(":")
    try:
        ipaddress.IPv4Address(host)
    except ipaddress.AddressValueError:
        candidate = host.rstrip(".")
        if not (
            candidate
            and len(candidate) <= 253
            and all(_HOST_LABEL.fullmatch(label) for label in candidate.split("."))
        ):
            raise argparse.ArgumentTypeError("target must be a valid IPv4 address or hostname") from None
    port = 0
    if separator:
        try:
            port = int(port_text)
        except ValueError:
            raise argparse.ArgumentTypeError("target port must be an integer") from None
        if not 1 <= port <= 65535:
            raise argparse.ArgumentTypeError("target port must be between 1 and 65535")
    return Target(host, port)


def valid_tests(value: str) -> str:
    codes = [part.strip().upper() for part in value.split(",")]
    invalid = [code for code in codes if code not in _TESTS and code != "ALL"]
    if invalid or not codes:
        raise argparse.ArgumentTypeError(
            f"unknown UPnP test(s): {', '.join(invalid) if invalid else value}; "
            "choose from ALL, DISCOVER, DESCRIBE"
        )
    return ",".join(dict.fromkeys(codes))


def _bounded_int(option: str, minimum: int, maximum: int):
    def parse(value: str) -> int:
        try:
            number = int(value)
        except ValueError:
            raise argparse.ArgumentTypeError(f"{option} must be an integer") from None
        if not minimum <= number <= maximum:
            raise argparse.ArgumentTypeError(f"{option} must be between {minimum} and {maximum}")
        return number

    return parse


def _timeout(value: str) -> float:
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("--timeout-seconds must be a number") from None
    if not math.isfinite(number) or not 0.1 <= number <= 60:
        raise argparse.ArgumentTypeError("--timeout-seconds must be between 0.1 and 60")
    return number


def _search_target(value: str) -> str:
    if not value or len(value) > 255 or not value.isascii() or any(
        char.isspace() or ord(char) < 33 or ord(char) > 126 for char in value
    ):
        raise argparse.ArgumentTypeError(
            "--search-target must be 1-255 visible ASCII characters without whitespace"
        )
    return value


class UPnPArgs(BaseArgs):
    target: Target
    tests: str | None
    timeout_seconds: float
    search_target: str
    max_responses: int
    max_description_bytes: int
    output: str | None

    @staticmethod
    def get_help():
        return [
            {"description": ["UPnP/SSDP Testing Module"]},
            {"usage": ["ptsrvtester upnp -tg <host> [-ts DISCOVER,DESCRIBE] <options>"]},
            {"usage_example": [
                "ptsrvtester upnp -tg 192.168.1.1",
                "ptsrvtester upnp -ts DISCOVER -tg 192.168.1.1 --search-target upnp:rootdevice",
                "ptsrvtester upnp -ts DESCRIBE -tg router.example.test -j",
            ]},
            {"options": [
                ["-tg", "--target", "<host>", "IPv4 address or hostname[:UDP port]; default port 1900"],
                ["-ts", "--tests", "<test>", "DISCOVER, DESCRIBE, ALL; default is both"],
                ["", "--timeout-seconds", "<seconds>", "UDP/HTTP timeout (default 3; range 0.1-60; DNS uses system timeout)"],
                ["", "--search-target", "<ST>", "SSDP search target (default ssdp:all)"],
                ["", "--max-responses", "<n>", "Maximum SSDP responses (default 100)"],
                ["", "--max-description-bytes", "<n>", "Maximum bytes per description (default 1048576; 50 URLs/32 MiB per run)"],
                ["-o", "--output", "<file>", "Save results"],
                ["-j", "--json", "", "JSON output"],
                ["-vv", "--verbose", "", "Verbose output"],
                ["-h", "--help", "", "Show this help"],
            ]},
        ]

    def add_subparser(self, name: str, subparsers) -> None:
        parser = subparsers.add_parser(name, add_help=True)
        parser.add_argument(
            "-tg", "--target", type=valid_target, required=True, metavar="<host>", dest="target"
        )
        parser.add_argument("-ts", "--tests", type=valid_tests, default=None, metavar="<test>")
        parser.add_argument("--timeout-seconds", type=_timeout, default=3.0)
        parser.add_argument("--search-target", type=_search_target, default="ssdp:all")
        parser.add_argument(
            "--max-responses", type=_bounded_int("--max-responses", 1, 1000), default=100
        )
        parser.add_argument(
            "--max-description-bytes",
            type=_bounded_int("--max-description-bytes", 1, 16 * 1024 * 1024),
            default=1024 * 1024,
        )
        parser.add_argument("-o", "--output", default=None)


__all__ = ["Target", "UPnPArgs", "valid_target", "valid_tests"]
