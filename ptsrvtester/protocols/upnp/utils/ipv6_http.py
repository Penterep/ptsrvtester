"""HTTP(S) connections pinned to one explicitly scoped IPv6 target.

The advertised host remains the HTTP Host and TLS verification name. TCP
always connects to the preselected IPv6 address and local interface scope.
"""

from __future__ import annotations

import errno
import http.client
import ipaddress
import socket
import sys

from .ipv6 import MAX_INTERFACE_INDEX, IPv6Target


class _PinnedIPv6SocketMixin:
    def __init__(
        self,
        host: str,
        target: IPv6Target,
        port: int,
        timeout: float,
        source_address: tuple[str, int, int, int] | None = None,
    ) -> None:
        if not isinstance(target, IPv6Target):
            raise TypeError("target must be an IPv6Target")
        try:
            address = ipaddress.IPv6Address(target.ip)
        except ipaddress.AddressValueError as exc:
            raise ValueError("target must contain an IPv6 address") from exc
        if address.scope_id or address.is_multicast or address.is_unspecified or address.ipv4_mapped:
            raise ValueError("target must contain an unscoped native IPv6 unicast address")
        if not isinstance(target.scope_id, int) or isinstance(target.scope_id, bool):
            raise TypeError("target interface index must be an integer")
        if not 0 <= target.scope_id <= MAX_INTERFACE_INDEX:
            raise ValueError("target interface index is out of range")
        if address.is_link_local and not target.scope_id:
            raise ValueError("link-local target requires an interface index")
        if not address.is_link_local and target.scope_id:
            raise ValueError("interface index is only valid for a link-local target")
        if not isinstance(host, str) or not host or "%" in host or any(
            ord(char) < 33 or ord(char) == 127 for char in host
        ):
            raise ValueError("advertised HTTP host is invalid")
        if not isinstance(port, int) or isinstance(port, bool):
            raise TypeError("HTTP port must be an integer")
        target.sockaddr(port)
        self._pinned_target = target
        self._pinned_source_address = self._validate_source_address(source_address, target)
        super().__init__(host, port, timeout=timeout)

    @staticmethod
    def _validate_source_address(
        source_address: tuple[str, int, int, int] | None,
        target: IPv6Target,
    ) -> tuple[str, int, int, int] | None:
        if source_address is None:
            return None
        if not isinstance(source_address, tuple) or len(source_address) != 4:
            raise ValueError("IPv6 source address must be a four-element socket tuple")
        host, port, flowinfo, scope_id = source_address
        try:
            address = ipaddress.IPv6Address(host)
        except (ipaddress.AddressValueError, TypeError) as exc:
            raise ValueError("IPv6 source address must be a native IPv6 literal") from exc
        if address.scope_id or address.is_multicast or address.is_unspecified or address.ipv4_mapped:
            raise ValueError("IPv6 source address must be an unscoped unicast literal")
        if port != 0 or flowinfo != 0:
            raise ValueError("IPv6 source port and flowinfo must be zero")
        if not isinstance(scope_id, int) or isinstance(scope_id, bool):
            raise TypeError("IPv6 source scope ID must be an integer")
        if scope_id != target.scope_id:
            raise ValueError("IPv6 source scope ID differs from selected target")
        if address.is_link_local != ipaddress.IPv6Address(target.ip).is_link_local:
            raise ValueError("IPv6 source and target scope types differ")
        return str(address), 0, 0, scope_id

    def set_tunnel(self, host, port=None, headers=None) -> None:
        """A proxy tunnel would bypass the selected target's HTTP endpoint."""
        raise ValueError("proxy tunnels are not allowed for pinned IPv6 connections")

    def _open_pinned_socket(self) -> socket.socket:
        if self._tunnel_host:
            raise ValueError("proxy tunnels are not allowed for pinned IPv6 connections")
        sys.audit("http.client.connect", self, self.host, self.port)
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        try:
            sock.settimeout(self.timeout)
            if self._pinned_source_address is not None:
                sock.bind(self._pinned_source_address)
            sock.connect(self._pinned_target.sockaddr(self.port))
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError as exc:
                if exc.errno != errno.ENOPROTOOPT:
                    raise
            return sock
        except BaseException:
            sock.close()
            raise


class PinnedIPv6HTTPConnection(_PinnedIPv6SocketMixin, http.client.HTTPConnection):
    """Plain HTTP transport to the one selected IPv6 socket address."""

    def connect(self) -> None:
        self.sock = self._open_pinned_socket()


class PinnedIPv6HTTPSConnection(_PinnedIPv6SocketMixin, http.client.HTTPSConnection):
    """HTTPS transport with normal certificate checks for the advertised host."""

    def connect(self) -> None:
        sock = self._open_pinned_socket()
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


__all__ = ["PinnedIPv6HTTPConnection", "PinnedIPv6HTTPSConnection"]
