"""Scoped IPv6 address and URL helpers for target-limited UPnP discovery.

Zone identifiers are accepted only from the local operator and converted to
an interface index. They are never taken from SSDP or description documents.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

LINK_LOCAL_SSDP_ADDRESS = "ff02::c"
SITE_LOCAL_SSDP_ADDRESS = "ff05::c"
SSDP_PORT = 1900
MAX_LOCATION_LENGTH = 2048
MAX_ZONE_LENGTH = 128
MAX_INTERFACE_INDEX = 2**32 - 1


class OutOfScopeIPv6URL(ValueError):
    """An advertised URL cannot be safely reached through the selected target."""


@dataclass(frozen=True)
class IPv6Target:
    ip: str
    port: int = 0
    scope_id: int = 0
    zone: str | None = None

    def sockaddr(self, port: int | None = None) -> tuple[str, int, int, int]:
        """Return an AF_INET6 destination, preserving the local interface index."""
        selected_port = (self.port or SSDP_PORT) if port is None else port
        if not 1 <= selected_port <= 65535:
            raise ValueError("IPv6 destination port must be between 1 and 65535")
        return self.ip, selected_port, 0, self.scope_id


@dataclass(frozen=True)
class IPv6URL:
    scheme: str
    host: str
    port: int
    path: str
    authority: str
    connect: tuple[str, int, int, int]


def _local_interface_index(zone: str) -> int:
    if not zone or len(zone) > MAX_ZONE_LENGTH or any(
        not char.isprintable() or char in "%[]:" for char in zone
    ):
        raise ValueError("invalid IPv6 interface zone")
    if zone.isascii() and zone.isdecimal():
        index = int(zone)
        if not 1 <= index <= MAX_INTERFACE_INDEX:
            raise ValueError("IPv6 interface index is out of range")
        try:
            socket.if_indextoname(index)
        except OSError as exc:
            raise ValueError("IPv6 interface index does not exist locally") from exc
        return index
    try:
        index = socket.if_nametoindex(zone)
    except OSError as exc:
        raise ValueError("IPv6 interface name does not exist locally") from exc
    if not 1 <= index <= MAX_INTERFACE_INDEX:
        raise ValueError("invalid IPv6 interface index")
    return index


def parse_ipv6_target(value: str) -> IPv6Target:
    """Parse ``fe80::1%zone`` or ``[fe80::1%zone]:1900`` from the CLI.

    Brackets are required when a UDP port is given. A link-local unicast
    target requires a locally valid zone; other unicast targets reject one.
    """
    raw = value.strip()
    if not raw or any(ord(char) < 32 or ord(char) == 127 for char in raw):
        raise ValueError("IPv6 target is empty or contains control characters")
    if raw.startswith("["):
        closing = raw.find("]")
        if closing < 0 or "[" in raw[1:closing]:
            raise ValueError("IPv6 target has invalid brackets")
        host = raw[1:closing]
        suffix = raw[closing + 1:]
        if suffix and (not suffix.startswith(":") or not suffix[1:].isdecimal()):
            raise ValueError("IPv6 target port must follow a closing bracket")
        port = int(suffix[1:]) if suffix else 0
        explicit_port = bool(suffix)
    else:
        if "[" in raw or "]" in raw:
            raise ValueError("IPv6 target has invalid brackets")
        host = raw
        port = 0
        explicit_port = False
    if explicit_port and not 1 <= port <= 65535:
        raise ValueError("IPv6 target port must be between 1 and 65535")
    if host.count("%") > 1:
        raise ValueError("IPv6 target has multiple zone identifiers")
    address_text, separator, zone = host.partition("%")
    try:
        address = ipaddress.IPv6Address(address_text)
    except ipaddress.AddressValueError as exc:
        raise ValueError("target must be an IPv6 address") from exc
    if address.is_multicast or address.is_unspecified or address.ipv4_mapped:
        raise ValueError("IPv6 target must be one native unicast address")
    if address.is_link_local:
        if not separator:
            raise ValueError("link-local IPv6 target requires an interface zone")
        scope_id = _local_interface_index(zone)
    else:
        if separator:
            raise ValueError("IPv6 interface zone is only accepted for link-local targets")
        scope_id = 0
    return IPv6Target(str(address), port, scope_id, zone if separator else None)


def multicast_endpoint(scope: str, interface_index: int) -> tuple[str, int, int, int]:
    """Return one explicitly scoped IPv6 SSDP multicast destination."""
    if scope not in ("link", "site"):
        raise ValueError("IPv6 multicast scope must be 'link' or 'site'")
    if isinstance(interface_index, bool) or not isinstance(interface_index, int):
        raise TypeError("IPv6 multicast requires a numeric interface index")
    if not 1 <= interface_index <= MAX_INTERFACE_INDEX:
        raise ValueError("IPv6 multicast interface index is out of range")
    address = LINK_LOCAL_SSDP_ADDRESS if scope == "link" else SITE_LOCAL_SSDP_ADDRESS
    return address, SSDP_PORT, 0, interface_index


def multicast_host_header(scope: str) -> str:
    """Return the SSDP HOST field for an IPv6 multicast M-SEARCH."""
    if scope not in ("link", "site"):
        raise ValueError("IPv6 multicast scope must be 'link' or 'site'")
    address = LINK_LOCAL_SSDP_ADDRESS if scope == "link" else SITE_LOCAL_SSDP_ADDRESS
    return f"[{address}]:{SSDP_PORT}"


def _validate_authority(authority: str) -> None:
    if authority.startswith("["):
        closing = authority.find("]")
        if closing < 0 or "[" in authority[1:closing]:
            raise OutOfScopeIPv6URL("IPv6 LOCATION has invalid brackets")
        suffix = authority[closing + 1:]
        if suffix and (not suffix.startswith(":") or not suffix[1:].isdecimal()):
            raise OutOfScopeIPv6URL("IPv6 LOCATION has an invalid port suffix")
    elif "[" in authority or "]" in authority or authority.count(":") > 1:
        raise OutOfScopeIPv6URL("IPv6 LOCATION has an invalid authority")
    elif ":" in authority and not authority.rsplit(":", 1)[1].isdecimal():
        raise OutOfScopeIPv6URL("IPv6 LOCATION has an invalid port suffix")


def validate_ipv6_url(url: str, target: IPv6Target) -> IPv6URL:
    """Validate an advertised HTTP(S) URL and pin its destination to target.

    The returned ``connect`` tuple is for AF_INET6 socket calls. DNS may be
    consulted to check a hostname, but the returned socket destination is
    always the already selected target address and local scope ID.
    """
    if not url or len(url) > MAX_LOCATION_LENGTH or any(
        ord(char) < 33 or ord(char) == 127 for char in url
    ):
        raise OutOfScopeIPv6URL("IPv6 LOCATION has invalid characters or length")
    if "#" in url:
        raise OutOfScopeIPv6URL("IPv6 LOCATION must not contain a fragment")
    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        host = parsed.hostname
        if scheme not in ("http", "https") or not host or not parsed.netloc:
            raise OutOfScopeIPv6URL("IPv6 LOCATION must be an absolute HTTP(S) URL")
        if parsed.username is not None or parsed.password is not None:
            raise OutOfScopeIPv6URL("IPv6 LOCATION must not contain credentials")
        _validate_authority(parsed.netloc)
        if "%" in parsed.netloc:
            raise OutOfScopeIPv6URL("advertised IPv6 URL must not contain a local zone")
        if any(not char.isascii() or char.isspace() or char in "\\" for char in host):
            raise OutOfScopeIPv6URL("IPv6 LOCATION has an invalid hostname")
        port = parsed.port
        if port is None:
            port = 443 if scheme == "https" else 80
        if not 1 <= port <= 65535:
            raise OutOfScopeIPv6URL("IPv6 LOCATION has an invalid port")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            if parsed.netloc.startswith("["):
                raise OutOfScopeIPv6URL("IPv6 LOCATION has an invalid IP literal") from None
            try:
                answers = socket.getaddrinfo(
                    host, port, family=socket.AF_INET6, type=socket.SOCK_STREAM
                )
            except socket.gaierror as exc:
                raise OutOfScopeIPv6URL("IPv6 LOCATION hostname cannot be resolved") from exc
            matching = False
            for family, _type, _proto, _canonname, sockaddr in answers:
                if family != socket.AF_INET6:
                    continue
                try:
                    resolved = ipaddress.IPv6Address(sockaddr[0])
                except ipaddress.AddressValueError:
                    continue
                answer_scope = sockaddr[3] if len(sockaddr) > 3 else 0
                if str(resolved) == target.ip and answer_scope in (0, target.scope_id):
                    matching = True
                    break
            if not matching:
                raise OutOfScopeIPv6URL("IPv6 LOCATION hostname is outside the selected target")
        else:
            if not isinstance(address, ipaddress.IPv6Address) or str(address) != target.ip:
                raise OutOfScopeIPv6URL("IPv6 LOCATION IP is outside the selected target")
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        return IPv6URL(
            scheme, host, port, path, parsed.netloc, target.sockaddr(port),
        )
    except ValueError as exc:
        if isinstance(exc, OutOfScopeIPv6URL):
            raise
        raise OutOfScopeIPv6URL(f"invalid IPv6 LOCATION: {exc}") from exc


__all__ = [
    "LINK_LOCAL_SSDP_ADDRESS",
    "SITE_LOCAL_SSDP_ADDRESS",
    "SSDP_PORT",
    "IPv6Target",
    "IPv6URL",
    "OutOfScopeIPv6URL",
    "multicast_endpoint",
    "multicast_host_header",
    "parse_ipv6_target",
    "validate_ipv6_url",
]
