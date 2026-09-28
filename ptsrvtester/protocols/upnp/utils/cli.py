"""Command-line arguments for targeted IPv4 UPnP/SSDP discovery."""

from __future__ import annotations

import argparse
import ipaddress
import math
import re
from dataclasses import dataclass

from ..._base import BaseArgs
from .ipv6 import IPv6Target, parse_ipv6_target


@dataclass
class Target:
    ip: str
    port: int = 0


_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_TESTS = frozenset({"DISCOVER", "DESCRIBE", "IGDINFO", "SCPD", "PORTMAPS", "NOTIFY", "EVENTS"})


def valid_target(value: str) -> Target | IPv6Target:
    """Accept one IPv4/IPv6 address or hostname with an optional UDP port."""
    raw = value.strip()
    if not raw:
        raise argparse.ArgumentTypeError("target must be IPv4, IPv6 or HOST[:PORT]")
    if raw.startswith("[") or raw.count(":") > 1:
        try:
            return parse_ipv6_target(raw)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(str(exc)) from exc
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
            "choose from ALL, DISCOVER, DESCRIBE, IGDINFO, SCPD, PORTMAPS, NOTIFY, EVENTS"
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


def _notify_seconds(value: str) -> float:
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("--notify-seconds must be a number") from None
    if not math.isfinite(number) or not 0.1 <= number <= 60:
        raise argparse.ArgumentTypeError("--notify-seconds must be between 0.1 and 60")
    return number


def _event_seconds(value: str) -> float:
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("--event-seconds must be a number") from None
    if not math.isfinite(number) or not 0.1 <= number <= 30:
        raise argparse.ArgumentTypeError("--event-seconds must be between 0.1 and 30")
    return number


def _search_target(value: str) -> str:
    if not value or len(value) > 255 or not value.isascii() or any(
        char.isspace() or ord(char) < 33 or ord(char) > 126 for char in value
    ):
        raise argparse.ArgumentTypeError(
            "--search-target must be 1-255 visible ASCII characters without whitespace"
        )
    return value


def _interface_ip(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise argparse.ArgumentTypeError("--interface-ip must be a local unicast IP address") from None
    if (
        address.is_multicast or address.is_unspecified or "%" in value
        or str(address) == "255.255.255.255"
        or isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped
    ):
        raise argparse.ArgumentTypeError("--interface-ip must be a local unicast IP address")
    return str(address)


class UPnPArgs(BaseArgs):
    target: Target | IPv6Target
    tests: str | None
    timeout_seconds: float
    search_target: str
    multicast: bool
    interface_ip: str | None
    interface_index: int | None
    family: int | None
    mx: int
    ttl: int
    max_responses: int
    max_description_bytes: int
    max_scpd: int
    max_mappings: int
    notify_seconds: float
    max_notifications: int
    event_seconds: float
    max_events: int
    output: str | None

    @staticmethod
    def get_help():
        return [
            {"description": ["UPnP/SSDP Testing Module"]},
            {"usage": ["ptsrvtester upnp -tg <host> [-ts DISCOVER,DESCRIBE,IGDINFO,SCPD,PORTMAPS,NOTIFY,EVENTS] <options>"]},
            {"usage_example": [
                "ptsrvtester upnp -tg 192.168.1.1",
                "ptsrvtester upnp -ts DISCOVER -tg 192.168.1.1 --search-target upnp:rootdevice",
                "ptsrvtester upnp -ts DISCOVER -tg 192.168.1.1 --multicast --interface-ip 192.168.1.10",
                "ptsrvtester upnp -ts DESCRIBE -tg router.example.test -j",
                "ptsrvtester upnp -ts SCPD -tg 192.168.1.1 --max-scpd 20",
                "ptsrvtester upnp -ts PORTMAPS -tg 192.168.1.1 --max-mappings 100",
                "ptsrvtester upnp -ts NOTIFY -tg 192.168.1.1 -i 192.168.1.10 --notify-seconds 10",
                "ptsrvtester upnp -ts EVENTS -tg 192.168.1.1 -i 192.168.1.10 --event-seconds 5",
                "ptsrvtester upnp -ts DISCOVER -tg '[fe80::1%Ethernet]:1900'",
                "ptsrvtester upnp -ts DISCOVER -tg '2001:db8::10' --multicast -i '2001:db8::20' --interface-index 7",
                "ptsrvtester upnp -ts NOTIFY -tg '2001:db8::10' -i '2001:db8::20' --interface-index 7",
                "ptsrvtester upnp -ts EVENTS -tg '2001:db8::10' -i '2001:db8::20'",
            ]},
            {"options": [
                ["-tg", "--target", "<host>", "IPv4, IPv6 literal or hostname[:UDP port]; default port 1900"],
                ["", "--family", "<4|6>", "Address family for hostnames; IPv6 literals select family 6"],
                ["-ts", "--tests", "<test>", "DISCOVER, DESCRIBE, IGDINFO, SCPD, PORTMAPS, NOTIFY, EVENTS, ALL; default excludes SCPD, PORTMAPS, NOTIFY and EVENTS"],
                ["", "--timeout-seconds", "<seconds>", "UDP/HTTP timeout (default 3; range 0.1-60; DNS uses system timeout)"],
                ["", "--search-target", "<ST>", "SSDP search target (default ssdp:all)"],
                ["", "--multicast", "", "Send SSDP M-SEARCH to IPv4 or IPv6 multicast; keep results scoped to -tg"],
                ["-i", "--interface-ip", "<IP>", "Local IP address for multicast, NOTIFY or EVENTS callback"],
                ["", "--interface-index", "<n>", "Local IPv6 interface index for multicast, NOTIFY or scoped hostname"],
                ["", "--mx", "<seconds>", "Multicast response delay, 1-5 seconds (default 2)"],
                ["", "--ttl", "<hops>", "Multicast IPv4 TTL / IPv6 hop limit, 1-255 (default 2)"],
                ["", "--max-responses", "<n>", "Maximum SSDP responses (default 100)"],
                ["", "--max-description-bytes", "<n>", "Maximum bytes per description (default 1048576; 50 URLs/32 MiB per run)"],
                ["", "--max-scpd", "<n>", "Maximum service descriptions to fetch (default 20; range 1-100)"],
                ["", "--max-mappings", "<n>", "Global PORTMAPS entry limit (default 100; range 1-1000)"],
                ["", "--notify-seconds", "<seconds>", "NOTIFY listen duration (default 10; range 0.1-60)"],
                ["", "--max-notifications", "<n>", "Maximum target NOTIFY messages (default 100; range 1-1000)"],
                ["", "--event-seconds", "<seconds>", "GENA listen duration per service (default 5; range 0.1-30)"],
                ["", "--max-events", "<n>", "Global GENA event limit (default 100; range 1-1000)"],
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
        parser.add_argument("--family", type=int, choices=(4, 6), default=None)
        parser.add_argument("-ts", "--tests", type=valid_tests, default=None, metavar="<test>")
        parser.add_argument("--timeout-seconds", type=_timeout, default=3.0)
        parser.add_argument("--search-target", type=_search_target, default="ssdp:all")
        parser.add_argument("--multicast", action="store_true", default=False)
        parser.add_argument("-i", "--interface-ip", type=_interface_ip, default=None)
        parser.add_argument(
            "--interface-index",
            type=_bounded_int("--interface-index", 1, 2**32 - 1), default=None,
        )
        parser.add_argument("--mx", type=_bounded_int("--mx", 1, 5), default=2)
        parser.add_argument("--ttl", type=_bounded_int("--ttl", 1, 255), default=2)
        parser.add_argument(
            "--max-responses", type=_bounded_int("--max-responses", 1, 1000), default=100
        )
        parser.add_argument(
            "--max-description-bytes",
            type=_bounded_int("--max-description-bytes", 1, 16 * 1024 * 1024),
            default=1024 * 1024,
        )
        parser.add_argument("--max-scpd", type=_bounded_int("--max-scpd", 1, 100), default=20)
        parser.add_argument(
            "--max-mappings", type=_bounded_int("--max-mappings", 1, 1000), default=100
        )
        parser.add_argument("--notify-seconds", type=_notify_seconds, default=10.0)
        parser.add_argument(
            "--max-notifications", type=_bounded_int("--max-notifications", 1, 1000),
            default=100,
        )
        parser.add_argument("--event-seconds", type=_event_seconds, default=5.0)
        parser.add_argument("--max-events", type=_bounded_int("--max-events", 1, 1000), default=100)
        parser.add_argument("-o", "--output", default=None)


__all__ = ["Target", "UPnPArgs", "valid_target", "valid_tests"]
