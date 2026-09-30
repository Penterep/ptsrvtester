"""UPnP/SSDP integration with the generic protocol framework."""

from __future__ import annotations

import argparse
import importlib
import ipaddress
import socket

from .._base import BaseArgs, BaseMain
from .utils.cli import UPnPArgs
from .utils.ipv6 import IPv6Target


class UPnP(BaseMain):
    NAME = "upnp"
    ARGS_CLASS = UPnPArgs

    @staticmethod
    def module_args() -> BaseArgs:
        return UPnPArgs()

    def __init__(self, args: BaseArgs, ptjsonlib) -> None:
        super().__init__(args, ptjsonlib)
        # Keep the operator's name for output while pinning network operations
        # to the one address selected for this run.
        self.args._upnp_resolved_ip = self.target[0]
        self.args._upnp_target_host = self.target_host
        from .utils.engine import UpnpEngine

        self.engine = UpnpEngine(args, ptjsonlib)

    def _prepare_target(self) -> None:
        target = self.args.target
        multicast = bool(self.args.multicast)
        interface_ip = self.args.interface_ip
        family = 6 if isinstance(target, IPv6Target) else (self.args.family or 4)
        if self.args.family and self.args.family != family:
            raise argparse.ArgumentError(None, "--family conflicts with target address")
        if family == 6:
            self._prepare_ipv6_target(target, multicast, interface_ip)
            return
        if self.args.interface_index is not None:
            raise argparse.ArgumentError(None, "--interface-index requires IPv6 multicast")
        if interface_ip and ipaddress.ip_address(interface_ip).version != 4:
            raise argparse.ArgumentError(None, "IPv4 operations require an IPv4 --interface-ip")
        notify = "NOTIFY" in (self.args.tests or "").split(",")
        events = "EVENTS" in (self.args.tests or "").split(",")
        if multicast and not interface_ip:
            raise argparse.ArgumentError(None, "--multicast requires --interface-ip")
        if notify and not interface_ip:
            raise argparse.ArgumentError(None, "NOTIFY requires --interface-ip")
        if events and not interface_ip:
            raise argparse.ArgumentError(None, "EVENTS requires --interface-ip")
        if interface_ip and not (multicast or notify or events):
            raise argparse.ArgumentError(None, "--interface-ip requires --multicast, NOTIFY or EVENTS")
        if (multicast or notify) and target.port not in (0, 1900):
            raise argparse.ArgumentError(None, "multicast SSDP and NOTIFY use UDP port 1900")
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
        self.args._upnp_family = 4
        self.args._upnp_ipv6_target = None

    def _prepare_ipv6_target(self, target, multicast: bool, interface_ip: str | None) -> None:
        requested = (self.args.tests or "").split(",")
        notify = "NOTIFY" in requested
        events = "EVENTS" in requested
        if interface_ip and ipaddress.ip_address(interface_ip).version != 6:
            raise argparse.ArgumentError(None, "IPv6 operations require an IPv6 --interface-ip")
        if interface_ip and (multicast or notify) and ipaddress.IPv6Address(interface_ip).is_loopback:
            raise argparse.ArgumentError(
                None, "IPv6 multicast and NOTIFY require a non-loopback --interface-ip"
            )
        if multicast and not interface_ip:
            raise argparse.ArgumentError(None, "IPv6 multicast requires --interface-ip")
        if notify and not interface_ip:
            raise argparse.ArgumentError(None, "IPv6 NOTIFY requires --interface-ip")
        if events and not interface_ip:
            raise argparse.ArgumentError(None, "IPv6 EVENTS requires --interface-ip")
        if interface_ip and not (multicast or notify or events):
            raise argparse.ArgumentError(
                None, "--interface-ip requires --multicast, NOTIFY or EVENTS"
            )
        port = target.port or 1900
        if (multicast or notify) and port != 1900:
            raise argparse.ArgumentError(None, "multicast SSDP and NOTIFY use UDP port 1900")

        if isinstance(target, IPv6Target):
            selected = IPv6Target(target.ip, port, target.scope_id, target.zone)
        else:
            try:
                answers = socket.getaddrinfo(
                    target.ip, port, family=socket.AF_INET6, type=socket.SOCK_DGRAM
                )
            except socket.gaierror as exc:
                raise argparse.ArgumentError(
                    None, f"Cannot resolve target '{target.ip}' to an IPv6 address"
                ) from exc
            if not answers:
                raise argparse.ArgumentError(
                    None, f"Cannot resolve target '{target.ip}' to an IPv6 address"
                )
            address = ipaddress.IPv6Address(answers[0][4][0].split("%", 1)[0])
            if address.is_multicast or address.is_unspecified or address.ipv4_mapped:
                raise argparse.ArgumentError(
                    None, "UPnP target must be one native unicast IPv6 host"
                )
            scope_id = answers[0][4][3]
            if not address.is_link_local and scope_id:
                raise argparse.ArgumentError(
                    None, "IPv6 hostname resolved with an unexpected interface scope"
                )
            if address.is_link_local and not scope_id:
                scope_id = self.args.interface_index or 0
            if address.is_link_local and not scope_id:
                raise argparse.ArgumentError(None, "link-local IPv6 target requires a scope index")
            selected = IPv6Target(str(address), port, scope_id)

        if interface_ip and (
            ipaddress.IPv6Address(interface_ip).is_link_local
            != ipaddress.IPv6Address(selected.ip).is_link_local
        ):
            raise argparse.ArgumentError(
                None, "IPv6 multicast source and target must use the same address scope"
            )

        interface_index = self.args.interface_index or selected.scope_id
        if selected.scope_id and interface_index != selected.scope_id:
            raise argparse.ArgumentError(None, "IPv6 interface index conflicts with target scope")
        if multicast or notify:
            if not interface_index:
                raise argparse.ArgumentError(
                    None, "IPv6 multicast and NOTIFY require --interface-index"
                )
            try:
                socket.if_indextoname(interface_index)
            except OSError as exc:
                raise argparse.ArgumentError(
                    None, "IPv6 interface index does not exist locally"
                ) from exc
        elif self.args.interface_index is not None and not selected.scope_id:
            raise argparse.ArgumentError(
                None, "--interface-index requires IPv6 multicast or NOTIFY"
            )
        if selected.scope_id and not (multicast or notify):
            try:
                socket.if_indextoname(selected.scope_id)
            except OSError as exc:
                raise argparse.ArgumentError(
                    None, "IPv6 interface index does not exist locally"
                ) from exc

        self.args._upnp_family = 6
        self.args._upnp_ipv6_target = selected
        self.args._upnp_interface_index = interface_index
        self.target_host = target.ip
        self.target = (selected.ip, port)

    def _import_module_file(self, name: str, path: str):
        return importlib.import_module(f"ptsrvtester.protocols.upnp.modules.{name}")

    def _discover_shared_modules(self):
        # The shared RATELIMIT module opens TCP connections, unlike SSDP.
        return {}

    def _select_codes(self, discovered) -> list[str]:
        raw = getattr(self.args, "tests", None)
        requested = raw.split(",") if raw else ["ALL"]
        run_default = "ALL" in requested
        needs_description = run_default or any(
            code in requested for code in ("DESCRIBE", "IGDINFO", "SCPD", "PORTMAPS", "EVENTS")
        )
        selected = []
        if run_default or "DISCOVER" in requested or needs_description:
            selected.append("DISCOVER")
        if needs_description:
            selected.append("DESCRIBE")
        if run_default or "IGDINFO" in requested:
            selected.append("IGDINFO")
        if "SCPD" in requested:
            selected.append("SCPD")
        # Enumerating mappings may be expensive, so ALL does not imply PORTMAPS.
        if "PORTMAPS" in requested:
            selected.append("PORTMAPS")
        if "NOTIFY" in requested:
            selected.append("NOTIFY")
        if "EVENTS" in requested:
            selected.append("EVENTS")
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
