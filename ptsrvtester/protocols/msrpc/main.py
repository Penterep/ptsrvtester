"""MSRPC integration with the generic protocol-module framework."""
from __future__ import annotations

import argparse
import importlib
import socket
import sys

from ptlibs.threads import printlock

from .._base import BaseArgs, BaseMain
from .utils.cli import MSRPCArgs, validate_msrpc_selection
from .utils.engine import MsrpcEngine
from .utils.registry import MSRPC_TESTS, expand_msrpc_selection, selection_families


class _LivePrintLock(printlock.PrintLock):
    """Keep ptlibs rendering while releasing each serial output chunk immediately."""

    def add_string_to_output(self, *args, **kwargs):
        super().add_string_to_output(*args, **kwargs)
        chunk = self.get_output_string()
        if chunk:
            sys.stdout.write(chunk)
            sys.stdout.flush()
            self.output_string = ""


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
        self._transport_checks: dict[str, OSError | None] = {}

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

    def _transport_error(self, family: str) -> OSError | None:
        """Check each selected TCP endpoint once, independently of authentication."""
        failure = self.engine.transport_failure(family)
        if failure is not None:
            return failure
        if family not in self._transport_checks:
            try:
                connection = socket.create_connection(
                    (self.target[0], self.transport_ports[family]),
                    timeout=self.engine.connect_timeout,
                )
                connection.close()
            except OSError as exc:
                self._transport_checks[family] = exc
            else:
                self._transport_checks[family] = None
        return self._transport_checks[family]

    def _run_module(self, code, discovered, extras) -> None:
        """Stream serial output so unavailable endpoints and progress appear promptly."""
        entry = discovered[code]
        ctx = self._make_context(_LivePrintLock(), extras)
        ctx.out(entry.label, "INFO", colortext=True)
        family = str(MSRPC_TESTS[code]["family"])
        error = self._transport_error(family)
        if error is not None:
            message = (
                f"{family.upper()} endpoint {self.target_host}:{self.transport_ports[family]} "
                f"is unavailable; {code} skipped: {self.engine._sanitized_samr_error(error)}"
            )
            self.engine.record_module_error(code, message)
            ctx.out(message, "TITLE", indent=4)
        else:
            try:
                entry.module.run(ctx)
            except Exception as exc:
                self.engine.record_module_error(code, exc)
                category = "ERROR" if isinstance(exc, argparse.ArgumentError) else "TITLE"
                ctx.out(f"Error in module {code}: {exc}", category, indent=4)
        # BaseMain.run will see no deferred text; JSON remains wholly silent.
        with self._lock:
            self._outputs[code] = ""

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
