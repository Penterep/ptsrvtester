"""Observe RPC Proxy channel setup separately from the backend RPC exchange."""
from __future__ import annotations

import re
from contextlib import contextmanager
from time import monotonic

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.rpch import RPCProxyClientException


def is_http_auth_rejection(exc: Exception) -> bool:
    return bool(re.search(r"HTTP/\d(?:\.\d)?\s+401\b", str(exc), re.IGNORECASE))


class _ProxyReadBudget:
    def __init__(self, byte_limit, read_limit, timeout):
        self.remaining_bytes = byte_limit
        self.remaining_reads = read_limit
        self.deadline = monotonic() + timeout


class _ProxySocket:
    """Keep Impacket's HTTP parser, but make its receive loops fail on EOF."""

    def __init__(self, sock, transport):
        self._socket = sock
        self._transport = transport

    def __getattr__(self, name):
        return getattr(self._socket, name)

    def recv(self, count, *args, **kwargs):
        budget = self._transport._read_budget
        if budget is None:
            raise RPCProxyClientException("RPC Proxy receive has no operation budget")
        if budget.remaining_reads <= 0 or budget.remaining_bytes <= 0:
            raise RPCProxyClientException("RPC Proxy receive limit reached")
        remaining_time = budget.deadline - monotonic()
        if remaining_time <= 0:
            raise TimeoutError("RPC Proxy receive timed out")
        budget.remaining_reads -= 1
        # Chunk sizes originate at the server. Do not pass an arbitrarily large
        # length through to socket.recv, which allocates its receive buffer.
        count = min(count, budget.remaining_bytes + 1)
        original_timeout = self._socket.gettimeout()
        timeout = remaining_time if original_timeout is None else min(original_timeout, remaining_time)
        self._socket.settimeout(timeout)
        try:
            data = self._socket.recv(count, *args, **kwargs)
        finally:
            try:
                self._socket.settimeout(original_timeout)
            except OSError:
                pass
        if count and not data:
            raise RPCProxyClientException("RPC Proxy connection closed before the response completed")
        budget.remaining_bytes -= len(data)
        if budget.remaining_bytes < 0:
            raise RPCProxyClientException("RPC Proxy receive limit reached")
        return data


class ObservedRPCProxyTransport(transport.HTTPTransport):
    MAX_HEADER_BYTES = 65536
    MAX_OPERATION_BYTES = 1024 * 1024
    MAX_OPERATION_READS = 4096

    def __init__(self, binding: str):
        super().__init__(None, 593)
        self.set_stringbinding(transport.DCERPCStringBinding(binding))
        self.channel_status = {"in": "not_tested", "out": "not_tested"}
        self.tunnel_status = "not_tested"
        self._read_budget = None

    def _guard_channels(self):
        # Impacket 0.12/0.13 reads these HTTPConnection sockets directly while
        # parsing headers. Guard them once, before those inherited loops run.
        channels = getattr(self, "_RPCProxyClient__channels", {})
        for channel in channels.values():
            if channel.sock is not None and not isinstance(channel.sock, _ProxySocket):
                channel.sock = _ProxySocket(channel.sock, self)

    @contextmanager
    def _bounded_reads(self, byte_limit):
        self._guard_channels()
        if self._read_budget is not None:
            yield
            return
        self._read_budget = _ProxyReadBudget(
            byte_limit, self.MAX_OPERATION_READS, self.get_connect_timeout(),
        )
        try:
            yield
        finally:
            self._read_budget = None

    def _read_100_continue(self, method):
        with self._bounded_reads(self.MAX_HEADER_BYTES):
            return super()._read_100_continue(method)

    def rpc_out_recv1(self, amt=None):
        with self._bounded_reads(self.MAX_OPERATION_BYTES):
            data = super().rpc_out_recv1(amt)
            # A terminating HTTP chunk also returns empty data without another
            # socket read. Upstream packet assembly must not retry that forever.
            if amt != 0 and not data:
                raise RPCProxyClientException("RPC Proxy response stream ended before an RPC packet completed")
            return data

    def rpc_out_read_pkt(self, handle_rts=False):
        with self._bounded_reads(self.MAX_OPERATION_BYTES):
            return super().rpc_out_read_pkt(handle_rts=handle_rts)

    def _open_channel(self, name, operation):
        try:
            operation()
        except Exception as exc:
            self.channel_status[name] = "denied" if is_http_auth_rejection(exc) else "error"
            raise
        # A 100 Continue response is not proof of valid credentials or a usable
        # backend. Only a completed, signed RPC call is promoted to a finding.
        self.channel_status[name] = "opened"

    def create_rpc_in_channel(self):
        self._open_channel("in", super().create_rpc_in_channel)

    def create_rpc_out_channel(self):
        self._open_channel("out", super().create_rpc_out_channel)

    def create_tunnel(self):
        try:
            with self._bounded_reads(self.MAX_OPERATION_BYTES):
                super().create_tunnel()
        except Exception:
            self.tunnel_status = "error"
            raise
        self.tunnel_status = "established"

    def disconnect(self):
        # Upstream disconnect stops after a missing/failed first channel.
        # Always attempt both, including partially established connections.
        for close in (self.close_rpc_in_channel, self.close_rpc_out_channel):
            try:
                close()
            except Exception:
                pass
        self.init_state()
