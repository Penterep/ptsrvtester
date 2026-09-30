"""Passive, target-scoped IPv6 SSDP NOTIFY observation.

UPnP Device Architecture 2.0 annex A uses FF02::C for link-local sources and
FF05::C for site-scope sources. This listener sends no packets and never opens
an advertised LOCATION.
"""

from __future__ import annotations

import ipaddress
import math
import re
import socket
import struct
import time

from .ipv6 import (
    LINK_LOCAL_SSDP_ADDRESS,
    MAX_INTERFACE_INDEX,
    SITE_LOCAL_SSDP_ADDRESS,
    SSDP_PORT,
    IPv6Target,
)
from .notify import (
    MAX_NOTIFY_BYTES,
    MAX_NOTIFY_DATAGRAMS,
    MAX_NOTIFY_RECORDS,
    MAX_NOTIFY_SECONDS,
    parse_ssdp_notify,
)

_HOST = re.compile(r"^\[([0-9a-fA-F:]+)\]:1900$")


def _valid_ipv6_address(value: str, name: str) -> ipaddress.IPv6Address:
    if not isinstance(value, str) or "%" in value:
        raise ValueError(f"{name} must be a native unicast IPv6 address without a zone")
    try:
        address = ipaddress.IPv6Address(value)
    except ipaddress.AddressValueError as exc:
        raise ValueError(f"{name} must be a native unicast IPv6 address") from exc
    if address.is_multicast or address.is_unspecified or address.ipv4_mapped or address.is_loopback:
        raise ValueError(f"{name} must be a native unicast IPv6 address")
    return address


def _valid_host(value: str | None, expected_group: str) -> bool:
    if value is None:
        return False
    match = _HOST.fullmatch(value)
    if not match:
        return False
    try:
        return ipaddress.IPv6Address(match.group(1)) == ipaddress.IPv6Address(expected_group)
    except ipaddress.AddressValueError:
        return False


def parse_ssdp_notify_ipv6(packet: bytes, source: tuple, expected_group: str) -> dict:
    """Reuse bounded NOTIFY parsing and validate its IPv6 multicast HOST."""
    result = parse_ssdp_notify(packet, source)
    errors = result["validationErrors"]
    if _valid_host(result["host"], expected_group):
        if "invalid_host" in errors:
            errors.remove("invalid_host")
    elif result["host"] and "invalid_host" not in errors:
        errors.append("invalid_host")
    source_address = ipaddress.IPv6Address(str(source[0]).split("%", 1)[0])
    result["sourceIp"] = source_address.compressed
    result["sourceScopeId"] = int(source[3])
    result["valid"] = not errors
    return result


def _source_matches(source: tuple, target_ip: ipaddress.IPv6Address, scope_id: int) -> bool:
    if len(source) < 4:
        return False
    try:
        address = ipaddress.IPv6Address(str(source[0]).split("%", 1)[0])
        source_scope = int(source[3])
    except (ValueError, TypeError):
        return False
    if address != target_ip:
        return False
    return not target_ip.is_link_local or source_scope == scope_id


def listen_ssdp_notify_ipv6(
    target: IPv6Target,
    local_ip: str,
    interface_index: int,
    seconds: float,
    max_notifications: int = 100,
    max_datagrams: int = MAX_NOTIFY_DATAGRAMS,
) -> dict:
    """Join one IPv6 SSDP group and observe only the selected target.

    Binding/join failures propagate as OSError. The caller can report them as
    a module error. Other senders are discarded before packet parsing.
    """
    if not isinstance(target, IPv6Target):
        raise TypeError("target must be an IPv6Target")
    target_ip = _valid_ipv6_address(target.ip, "target.ip")
    local_address = _valid_ipv6_address(local_ip, "local_ip")
    if (
        not isinstance(interface_index, int)
        or isinstance(interface_index, bool)
        or not 1 <= interface_index <= MAX_INTERFACE_INDEX
    ):
        raise ValueError("interface_index must be between 1 and 4294967295")
    if target_ip.is_link_local:
        if target.scope_id != interface_index or not local_address.is_link_local:
            raise ValueError("link-local target and local address must use the selected interface")
        group = LINK_LOCAL_SSDP_ADDRESS
    else:
        if target.scope_id != 0 or local_address.is_link_local:
            raise ValueError("site-scope target requires a non-link-local local address")
        group = SITE_LOCAL_SSDP_ADDRESS
    if (
        not isinstance(seconds, (int, float))
        or isinstance(seconds, bool)
        or not math.isfinite(seconds)
        or not 0.1 <= seconds <= MAX_NOTIFY_SECONDS
    ):
        raise ValueError("seconds must be between 0.1 and 60")
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

    membership = socket.inet_pton(socket.AF_INET6, group) + struct.pack("@I", interface_index)
    notifications: list[dict] = []
    received = 0
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("::", SSDP_PORT))
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, membership)
        deadline = time.monotonic() + seconds
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
            if not _source_matches(source, target_ip, target.scope_id):
                continue
            notifications.append(parse_ssdp_notify_ipv6(packet, source, group))

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


__all__ = ["listen_ssdp_notify_ipv6", "parse_ssdp_notify_ipv6"]
