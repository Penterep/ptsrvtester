"""Bounded, target-scoped IPv6 SSDP search transport.

The caller parses and reports responses. This module only sends one M-SEARCH,
receives bounded UDP datagrams, and keeps replies from the selected IPv6 host.
"""

from __future__ import annotations

import ipaddress
import math
import socket
import time

from .ipv6 import IPv6Target, multicast_endpoint, multicast_host_header

MAX_DATAGRAM_BYTES = 8192
MAX_MULTICAST_DATAGRAMS = 20_000
MAX_RESPONSES = 1000


def _valid_search_target(value: str) -> bool:
    return (
        bool(value)
        and len(value) <= 255
        and all(33 <= ord(char) <= 126 for char in value)
    )


def _build_msearch(search_target: str, host_header: str, mx: int | None) -> bytes:
    if not _valid_search_target(search_target):
        raise ValueError(
            "search target must be 1-255 visible ASCII characters without spaces"
        )
    lines = [
        "M-SEARCH * HTTP/1.1",
        f"HOST: {host_header}",
        'MAN: "ssdp:discover"',
    ]
    if mx is not None:
        lines.append(f"MX: {mx}")
    lines.extend((f"ST: {search_target}", "", ""))
    return "\r\n".join(lines).encode("ascii")


def _source_matches(
    source: tuple, target_ip: str, target_scope: int, link_local: bool
) -> bool:
    if len(source) < 4:
        return False
    try:
        source_address = ipaddress.IPv6Address(source[0])
        source_scope = int(source[3])
    except (ValueError, TypeError, IndexError):
        return False
    if source_address.compressed.split("%", 1)[0] != target_ip:
        return False
    return not link_local or source_scope == target_scope


def discover_ipv6_packets(
    target: IPv6Target,
    *,
    search_target: str,
    max_responses: int,
    timeout: float,
    multicast: bool,
    interface_index: int,
    mx: int,
    ttl: int,
    interface_ip: str | None = None,
) -> dict:
    """Return raw responses from one target and bounded receive accounting.

    For multicast, the selected remote target determines the UPnP IPv6 scope:
    link-local addresses use FF02::C and other native IPv6 addresses use FF05::C.
    Responses are unicast to this socket's ephemeral port, so group membership is
    unnecessary. ``received`` counts every datagram, including other hosts.
    """
    if not isinstance(target, IPv6Target):
        raise TypeError("target must be an IPv6Target")
    try:
        address = ipaddress.IPv6Address(target.ip)
    except ipaddress.AddressValueError as exc:
        raise ValueError("target must contain a valid IPv6 address") from exc
    if (
        address.scope_id is not None
        or address.is_multicast
        or address.is_unspecified
        or address.ipv4_mapped
    ):
        raise ValueError(
            "target must contain one native unicast IPv6 address without a zone"
        )
    target_ip = address.compressed
    link_local = address.is_link_local
    if link_local and not 1 <= target.scope_id <= 2**32 - 1:
        raise ValueError("link-local IPv6 target requires an interface scope ID")
    if (
        not isinstance(max_responses, int)
        or isinstance(max_responses, bool)
        or not 1 <= max_responses <= MAX_RESPONSES
    ):
        raise ValueError(f"max_responses must be between 1 and {MAX_RESPONSES}")
    if (
        not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ValueError("timeout must be a positive finite number")
    if not isinstance(mx, int) or isinstance(mx, bool) or not 1 <= mx <= 5:
        raise ValueError("MX must be an integer between 1 and 5")
    if not isinstance(ttl, int) or isinstance(ttl, bool) or not 1 <= ttl <= 255:
        raise ValueError("IPv6 multicast hop limit must be between 1 and 255")
    if (
        not isinstance(interface_index, int)
        or isinstance(interface_index, bool)
        or not 0 <= interface_index <= 2**32 - 1
    ):
        raise ValueError("IPv6 interface index is out of range")
    if link_local and interface_index not in (0, target.scope_id):
        raise ValueError("IPv6 interface index conflicts with link-local target scope")

    local_address: ipaddress.IPv6Address | None = None
    if interface_ip is not None:
        if not isinstance(interface_ip, str) or "%" in interface_ip:
            raise ValueError(
                "interface_ip must be a native IPv6 address without a zone"
            )
        try:
            local_address = ipaddress.IPv6Address(interface_ip)
        except ipaddress.AddressValueError as exc:
            raise ValueError("interface_ip must be a native IPv6 address") from exc
        if (
            local_address.is_multicast
            or local_address.is_unspecified
            or local_address.is_loopback
            or local_address.ipv4_mapped
        ):
            raise ValueError(
                "interface_ip must be a native unicast IPv6 interface address"
            )
        if local_address.is_link_local != link_local:
            raise ValueError(
                "interface_ip scope conflicts with the selected IPv6 target"
            )
    if multicast and local_address is None:
        raise ValueError("IPv6 multicast requires interface_ip")

    if multicast:
        if target.port not in (0, 1900):
            raise ValueError("multicast SSDP uses UDP port 1900")
        scope = "link" if link_local else "site"
        destination = multicast_endpoint(scope, interface_index)
        host_header = multicast_host_header(scope)
        packet = _build_msearch(search_target, host_header, mx)
        wait = max(float(timeout), float(mx))
        receive_limit = MAX_MULTICAST_DATAGRAMS
    else:
        destination = target.sockaddr()
        host_header = f"[{target_ip}]:{destination[1]}"
        packet = _build_msearch(search_target, host_header, None)
        wait = float(timeout)
        receive_limit = max_responses * 4

    packets: list[tuple[bytes, tuple]] = []
    received = 0
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
        if local_address is None:
            sock.bind(("::", 0))
        else:
            bind_scope = (
                (interface_index or target.scope_id)
                if local_address.is_link_local
                else 0
            )
            sock.bind((local_address.compressed, 0, 0, bind_scope))
        if multicast:
            sock.setsockopt(
                socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, interface_index
            )
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, ttl)
        sock.sendto(packet, destination)
        deadline = time.monotonic() + wait
        while len(packets) < max_responses and received < receive_limit:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                response, source = sock.recvfrom(MAX_DATAGRAM_BYTES + 1)
            except TimeoutError:
                break
            received += 1
            if _source_matches(source, target_ip, target.scope_id, link_local):
                packets.append((response, source))

    return {
        "packets": packets,
        "received": received,
        "truncated": len(packets) >= max_responses or received >= receive_limit,
    }


__all__ = ["MAX_DATAGRAM_BYTES", "MAX_MULTICAST_DATAGRAMS", "discover_ipv6_packets"]
