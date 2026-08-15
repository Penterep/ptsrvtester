"""MSRPC protocol main."""
from __future__ import annotations

import argparse
import importlib
import socket

from .._base import BaseArgs, BaseMain
from .utils.cli import MSRPCArgs, MSRPC_DEFAULT_SUITE
from .utils.engine import MSRPCResult, MsrpcEngine


class MSRPC(BaseMain):
    NAME = "msrpc"
    ARGS_CLASS = MSRPCArgs

    @staticmethod
    def module_args() -> BaseArgs:
        return MSRPCArgs()

    def __init__(self, args: BaseArgs, ptjsonlib) -> None:
        if not isinstance(args, MSRPCArgs):
            raise argparse.ArgumentError(None, "wrong arguments namespace for msrpc")
        if not getattr(args, "module_threads", None):
            args.module_threads = 1
        self.engine = MsrpcEngine(args, ptjsonlib)
        self.engine.results = MSRPCResult()
        super().__init__(args, ptjsonlib)

    def _import_module_file(self, name: str, path: str):
        return importlib.import_module(f"ptsrvtester.protocols.msrpc.modules.{name}")

    def _prepare_target(self) -> None:
        target = self.args.target
        raw = getattr(self.args, "tests", None) or ""
        codes = {c.strip().upper() for c in raw.split(",") if c.strip()}
        if getattr(target, "port", 0) == 0:
            if codes & {"ANONSMB", "BRUTESMB", "ENUMPIPES"} and not (
                codes & {"ENUMEPM", "ENUMMGMT", "BRUTETCP"}
            ):
                target.port = 445
            else:
                target.port = 135
        host = target.ip
        try:
            socket.inet_aton(host)
            ip = host
        except OSError:
            try:
                ip = socket.gethostbyname(host)
            except socket.gaierror as e:
                raise argparse.ArgumentError(None, f"Cannot resolve domain name '{host}'") from e
        self.target_host = host
        self.target = (ip, target.port)
        self.args.ip = ip
        self.args.port = target.port

    def _select_codes(self, discovered):
        raw = getattr(self.args, "tests", None)
        codes = [c.strip().upper() for c in raw.split(",")] if raw else []
        codes = [c for c in codes if c]
        if not codes or "ALL" in codes:
            chosen = [c for c in MSRPC_DEFAULT_SUITE if c in discovered]
            chosen.sort(key=lambda c: (discovered[c].order, c))
            return chosen
        return super()._select_codes(discovered)

    def build_context(self) -> dict:
        return {
            "engine": self.engine,
            "host": self.target_host,
            "ip": self.target[0],
            "port": self.target[1],
        }

    def output(self) -> None:
        if self.engine.results is None:
            self.engine.results = MSRPCResult()
        self.engine.output()
