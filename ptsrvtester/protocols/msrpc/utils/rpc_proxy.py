"""Observe RPC Proxy channel setup separately from the backend RPC exchange."""
from __future__ import annotations

import re

from impacket.dcerpc.v5 import transport


def is_http_auth_rejection(exc: Exception) -> bool:
    return bool(re.search(r"HTTP/\d(?:\.\d)?\s+401\b", str(exc), re.IGNORECASE))


class ObservedRPCProxyTransport(transport.HTTPTransport):
    def __init__(self, binding: str):
        super().__init__(None, 593)
        self.set_stringbinding(transport.DCERPCStringBinding(binding))
        self.channel_status = {"in": "not_tested", "out": "not_tested"}
        self.tunnel_status = "not_tested"

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
