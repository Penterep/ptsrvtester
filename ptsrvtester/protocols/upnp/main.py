"""UPnP/SSDP integration with the generic protocol framework."""

from __future__ import annotations

import argparse
import importlib
import ipaddress
import socket

from .._base import BaseArgs, BaseMain
from .utils.cli import UPnPArgs


class UPnP(BaseMain):
    NAME = "upnp"
    ARGS_CLASS = UPnPArgs

    @staticmethod
    def module_args() -> BaseArgs:
        return UPnPArgs()

    def __init__(self, args: BaseArgs, ptjsonlib) -> None:
        super().__init__(args, ptjsonlib)
        # Keep the name supplied by the operator for output while pinning all
        # network operations to the one IPv4 address resolved for this run.
        self.args._upnp_resolved_ip = self.target[0]
        self.args._upnp_target_host = self.target_host
        from .utils.engine import UpnpEngine

        self.engine = UpnpEngine(args, ptjsonlib)

    def _prepare_target(self) -> None:
        target = self.args.target
        if target.port == 0:
            target.port = 1900
        self.target_host = target.ip
        try:
            addresses = socket.getaddrinfo(
                target.ip, target.port, family=socket.AF_INET, type=socket.SOCK_DGRAM
            )
        except socket.gaierror as exc:
            raise argparse.ArgumentError(
                None, f"Cannot resolve target '{target.ip}' to an IPv4 address"
            ) from exc
        if not addresses:
            raise argparse.ArgumentError(
                None, f"Cannot resolve target '{target.ip}' to an IPv4 address"
            )
        resolved_ip = addresses[0][4][0]
        address = ipaddress.IPv4Address(resolved_ip)
        if address.is_multicast or address.is_unspecified or resolved_ip == "255.255.255.255":
            raise argparse.ArgumentError(None, "UPnP target must be one unicast IPv4 host")
        self.target = (resolved_ip, target.port)

    def _import_module_file(self, name: str, path: str):
        return importlib.import_module(f"ptsrvtester.protocols.upnp.modules.{name}")

    def _discover_shared_modules(self):
        # The shared RATELIMIT module opens TCP connections, unlike SSDP.
        return {}

    def _select_codes(self, discovered) -> list[str]:
        raw = getattr(self.args, "tests", None)
        requested = raw.split(",") if raw else ["ALL"]
        if "ALL" in requested or "DESCRIBE" in requested:
            # DESCRIBE needs discovery evidence; always run the two in order.
            selected = ["DISCOVER", "DESCRIBE"]
        else:
            selected = ["DISCOVER"]
        missing = [code for code in selected if code not in discovered]
        if missing:
            raise argparse.ArgumentError(
                None, f"UPnP test adapter(s) unavailable: {', '.join(missing)}"
            )
        return selected

    def _thread_count(self) -> int:
        return 1

    def build_context(self) -> dict:
        return {
            "engine": self.engine,
            "host": self.target_host,
            "ip": self.target[0],
            "port": self.target[1],
        }

    def output(self) -> None:
        self.engine.output()


__all__ = ["UPnP"]
