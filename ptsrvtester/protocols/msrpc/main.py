"""MSRPC integration with the generic protocol-module framework."""
from __future__ import annotations

import argparse
import importlib
import socket

from .._base import BaseArgs, BaseMain
from .utils.cli import MSRPCArgs, validate_msrpc_selection
from .utils.engine import MsrpcEngine
from .utils.registry import expand_msrpc_selection, selection_families


class MSRPC(BaseMain):
    """Run selected MSRPC checks through one serial, shared engine."""

    NAME = "msrpc"
    ARGS_CLASS = MSRPCArgs

    @staticmethod
    def module_args() -> BaseArgs:
        return MSRPCArgs()

    def __init__(self, args: BaseArgs, ptjsonlib) -> None:
        if not isinstance(args, MSRPCArgs):
            raise argparse.ArgumentError(None, "wrong arguments namespace for msrpc")
        self.selected_tests = validate_msrpc_selection(args)
        super().__init__(args, ptjsonlib)
        self.engine = MsrpcEngine(args, ptjsonlib)

    def _import_module_file(self, name: str, path: str):
        return importlib.import_module(f"ptsrvtester.protocols.msrpc.modules.{name}")

    def _prepare_target(self) -> None:
        target = self.args.target
        requested_port = int(getattr(target, "port", 0) or 0)
        families = selection_families(self.selected_tests)

        ports = {"rpc": 135, "smb": 445, "http": 443}
        if requested_port:
            # validate_msrpc_selection already rejected a mixed-family override.
            ports[next(iter(families))] = requested_port

        host = target.ip
        try:
            socket.inet_aton(host)
            ip = host
        except OSError:
            try:
                ip = socket.gethostbyname(host)
            except socket.gaierror as exc:
                raise argparse.ArgumentError(
                    None, f"Cannot resolve domain name '{host}' to IP address"
                ) from exc

        primary_family = next(iter(families)) if len(families) == 1 else "rpc"
        primary_port = ports[primary_family]
        target.port = primary_port
        self.target_host = host
        self.target = (ip, primary_port)
        self.transport_ports = ports

        # Compatibility fields used by the ported engine.
        self.args.ip = ip
        self.args.host = host
        self.args.port = primary_port
        self.args.rpc_port = ports["rpc"]
        self.args.smb_port = ports["smb"]
        self.args.http_port = ports["http"]

    def _select_codes(self, discovered) -> list[str]:
        requested = expand_msrpc_selection(self.args.tests)
        missing = [code for code in requested if code not in discovered]
        if missing:
            message = (
                "Selected MSRPC adapter(s) could not be loaded: "
                + ", ".join(missing)
            )
            self.engine.record_module_error("DISCOVERY", message)
            if not self.use_json:
                self.ptjsonlib.end_error(message, False)
            return []
        chosen = list(requested)
        chosen.sort(key=lambda code: (discovered[code].order, code))
        return chosen

    def _thread_count(self) -> int:
        # bind_ctx() and the result accumulator are intentionally shared.
        return 1

    def build_context(self) -> dict:
        return {
            "engine": self.engine,
            "host": self.target_host,
            "ip": self.target[0],
            "port": self.target[1],
            "ports": dict(self.transport_ports),
        }

    def output(self) -> None:
        self.engine.output()


__all__ = ["MSRPC"]
