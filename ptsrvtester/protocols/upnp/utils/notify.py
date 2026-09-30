"""Bounded, target-scoped passive IPv4 SSDP NOTIFY observation.

Packet forms follow UPnP Device Architecture 2.0, sections 1.2.2-1.2.4.
This module never follows LOCATION or sends a network request.
"""

from __future__ import annotations

import ipaddress
import math
import re
import socket
import time
from urllib.parse import urlsplit

from .multicast import MULTICAST_ADDRESS, MULTICAST_PORT

MAX_NOTIFY_BYTES = 8192
MAX_NOTIFY_HEADERS = 64
MAX_NOTIFY_LOCATION_LENGTH = 2048
MAX_NOTIFY_DATAGRAMS = 20_000
MAX_NOTIFY_RECORDS = 1000
MAX_NOTIFY_SECONDS = 60.0

_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_MAX_AGE = re.compile(r"(?:^|,)\s*max-age\s*=\s*(\d+)\s*(?:,|$)", re.IGNORECASE)
_DECIMAL = re.compile(r"^[0-9]{1,10}$")
_NTS = frozenset({"ssdp:alive", "ssdp:byebye", "ssdp:update"})
_FIELDS = {
    "host": "host",
    "nt": "nt",
    "nts": "nts",
    "usn": "usn",
    "location": "location",
    "server": "server",
    "bootid.upnp.org": "bootId",
    "configid.upnp.org": "configId",
    "nextbootid.upnp.org": "nextBootId",
}


def _valid_location(value: str) -> bool:
    if len(value) > MAX_NOTIFY_LOCATION_LENGTH:
        return False
    try:
        parsed = urlsplit(value)
        return (
            parsed.scheme.lower() in ("http", "https")
            and bool(parsed.hostname)
            and parsed.username is None
            and parsed.password is None
            and not parsed.fragment
            and (parsed.port is None or 1 <= parsed.port <= 65535)
        )
    except ValueError:
        return False


def parse_ssdp_notify(packet: bytes, source: tuple) -> dict:
    """Parse one NOTIFY packet while retaining bounded malformed target evidence."""
    result = {
        "sourceIp": str(source[0]),
        "sourcePort": int(source[1]),
        "host": None,
        "nt": None,
        "nts": None,
        "usn": None,
        "location": None,
        "server": None,
        "cacheMaxAge": None,
        "bootId": None,
        "configId": None,
        "nextBootId": None,
        "valid": False,
        "validationErrors": [],
        "warnings": [],
    }
    errors = result["validationErrors"]
    warnings = result["warnings"]
    if len(packet) > MAX_NOTIFY_BYTES:
        errors.append("notification_too_large")
        return result
    if b"\x00" in packet:
        errors.append("nul_byte")
        return result

    header_bytes, separator, body = packet.partition(b"\r\n\r\n")
    if not separator:
        errors.append("missing_header_terminator")
    elif body:
        warnings.append("unexpected_body")
    lines = header_bytes.decode("iso-8859-1").split("\r\n")
    if not lines or lines[0] != "NOTIFY * HTTP/1.1":
        errors.append("invalid_request_line")
    headers: dict[str, str] = {}
    if len(lines) - 1 > MAX_NOTIFY_HEADERS:
        errors.append("too_many_headers")
    for line in lines[1:MAX_NOTIFY_HEADERS + 1]:
        if not line or ":" not in line or line[0] in " \t":
            errors.append("invalid_header")
            continue
        name, value = line.split(":", 1)
        if not _HEADER_NAME.fullmatch(name):
            errors.append("invalid_header_name")
            continue
        key = name.lower()
        value = value.strip(" \t")
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            errors.append("invalid_header_value")
            continue
        if key in headers:
            errors.append(f"duplicate_{key}")
            continue
        headers[key] = value

    for header, field in _FIELDS.items():
        result[field] = headers.get(header)
    for field in ("host", "nt", "nts", "usn"):
        if not result[field]:
            errors.append(f"missing_{field}")
    if result["host"] and result["host"] not in (
        MULTICAST_ADDRESS, f"{MULTICAST_ADDRESS}:{MULTICAST_PORT}"
    ):
        errors.append("invalid_host")
    nts = result["nts"]
    if nts and nts not in _NTS:
        errors.append("unsupported_nts")
    if nts in ("ssdp:alive", "ssdp:update") and not result["location"]:
        errors.append("missing_location")
    if result["location"] and not _valid_location(result["location"]):
        errors.append("invalid_location")
    if nts == "ssdp:alive" and "cache-control" not in headers:
        errors.append("missing_cache_control")
    if nts == "ssdp:update" and not result["nextBootId"]:
        errors.append("missing_next_boot_id")
    if nts in _NTS:
        for field, name in (("bootId", "boot_id"), ("configId", "config_id")):
            if not result[field]:
                (errors if nts == "ssdp:update" else warnings).append(f"missing_{name}")
    if nts == "ssdp:alive" and not result["server"]:
        warnings.append("missing_server")

    cache_control = headers.get("cache-control", "")
    match = _MAX_AGE.search(cache_control)
    if match and len(match.group(1)) <= 20:
        result["cacheMaxAge"] = int(match.group(1))
    elif cache_control:
        errors.append("invalid_cache_control")
    if nts == "ssdp:alive" and result["cacheMaxAge"] is None and "invalid_cache_control" not in errors:
        errors.append("invalid_cache_control")
    for field, name in (
        ("bootId", "boot_id"),
        ("configId", "config_id"),
        ("nextBootId", "next_boot_id"),
    ):
        value = result[field]
        if value is not None and (not _DECIMAL.fullmatch(value) or int(value) > 2**31 - 1):
            (errors if nts == "ssdp:update" else warnings).append(f"invalid_{name}")
    if nts == "ssdp:update" and result["bootId"] and result["nextBootId"]:
        try:
            if int(result["nextBootId"]) <= int(result["bootId"]):
                errors.append("next_boot_id_not_greater")
        except ValueError:
            pass
    result["valid"] = not errors
    return result


def _unicast_ipv4(value: str, name: str) -> str:
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        raise ValueError(f"{name} must be a unicast IPv4 address") from None
    if address.is_multicast or address.is_unspecified or str(address) == "255.255.255.255":
        raise ValueError(f"{name} must be a unicast IPv4 address")
    return str(address)


def listen_ssdp_notify(
    target_ip: str,
    interface_ip: str,
    duration_seconds: float,
    max_notifications: int = 100,
    max_datagrams: int = MAX_NOTIFY_DATAGRAMS,
) -> dict:
    """Receive SSDP multicast NOTIFY on one interface for one selected target.

    Socket setup errors propagate to the caller; no active SSDP or HTTP request is sent.
    """
    target_ip = _unicast_ipv4(target_ip, "target_ip")
    interface_ip = _unicast_ipv4(interface_ip, "interface_ip")
    if not isinstance(duration_seconds, (float, int)) or isinstance(duration_seconds, bool):
        raise TypeError("duration_seconds must be a number between 0.1 and 60")
    if not math.isfinite(duration_seconds) or not 0.1 <= duration_seconds <= MAX_NOTIFY_SECONDS:
        raise ValueError("duration_seconds must be between 0.1 and 60")
    if (
        not isinstance(max_notifications, int)
        or isinstance(max_notifications, bool)
        or not 1 <= max_notifications <= MAX_NOTIFY_RECORDS
    ):
        raise ValueError("max_notifications must be between 1 and 1000")
    if (
        not isinstance(max_datagrams, int)
        or isinstance(max_datagrams, bool)
        or not 1 <= max_datagrams <= MAX_NOTIFY_DATAGRAMS
    ):
        raise ValueError("max_datagrams must be between 1 and 20000")

    notifications: list[dict] = []
    received = 0
    membership = socket.inet_aton(MULTICAST_ADDRESS) + socket.inet_aton(interface_ip)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        # Multicast listeners legitimately share :1900. Windows delivers group
        # datagrams to each socket joined on the same interface and port.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", MULTICAST_PORT))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
        deadline = time.monotonic() + duration_seconds
        while len(notifications) < max_notifications and received < max_datagrams:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                packet, source = sock.recvfrom(MAX_NOTIFY_BYTES + 1)
            except TimeoutError:
                break
            received += 1
            if source[0] != target_ip:
                continue
            notifications.append(parse_ssdp_notify(packet, source))

    truncated = len(notifications) >= max_notifications or received >= max_datagrams
    if truncated or any(not item["valid"] for item in notifications):
        status = "partial"
    elif notifications:
        status = "complete"
    else:
        status = "no_notifications"
    return {
        "notifications": notifications,
        "status": status,
        "truncated": truncated,
        "receivedDatagrams": received,
    }


__all__ = [
    "MAX_NOTIFY_BYTES", "MAX_NOTIFY_DATAGRAMS", "MAX_NOTIFY_HEADERS",
    "MAX_NOTIFY_RECORDS", "MAX_NOTIFY_SECONDS", "listen_ssdp_notify", "parse_ssdp_notify",
]
