"""DNS protocol main."""
from __future__ import annotations

import argparse
import importlib
import socket

from .._base import BaseArgs, BaseMain
from .utils.cli import DNSArgs, DNS_DEFAULT_SUITE
from .utils.engine import DNSResult, DnsEngine
from .utils.helpers import Target


class DNS(BaseMain):
    NAME = "dns"
    ARGS_CLASS = DNSArgs

    @staticmethod
    def module_args() -> BaseArgs:
        return DNSArgs()

    def __init__(self, args: BaseArgs, ptjsonlib) -> None:
        if not isinstance(args, DNSArgs):
            raise argparse.ArgumentError(None, "wrong arguments namespace for dns")
        if not getattr(args, "module_threads", None):
            args.module_threads = 1
        self.engine = DnsEngine(args, ptjsonlib)
        self.engine.results = DNSResult()
        super().__init__(args, ptjsonlib)

    def _import_module_file(self, name: str, path: str):
        return importlib.import_module(f"ptsrvtester.protocols.dns.modules.{name}")

    def _prepare_target(self) -> None:
        if getattr(self.args, "target", None) is None:
            if getattr(self.args, "ip", None):
                self.args.target = Target(self.args.ip, getattr(self.args, "port", 53) or 53)
            else:
                self.args.target = Target("0.0.0.0", getattr(self.args, "port", 53) or 53)

        target = self.args.target
        if getattr(target, "port", 0) == 0:
            target.port = getattr(self.args, "port", 53) or 53

        host = target.ip
        if host == "0.0.0.0":
            ip = host
        else:
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
        if not getattr(self.args, "ip", None) and host != "0.0.0.0":
            self.args.ip = host
        self.args.port = target.port

    def _select_codes(self, discovered):
        raw = getattr(self.args, "tests", None)
        codes = [c.strip().upper() for c in raw.split(",")] if raw else []
        codes = [c for c in codes if c]
        if not codes or "ALL" in codes:
            chosen = [c for c in DNS_DEFAULT_SUITE if c in discovered]
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
            self.engine.results = DNSResult()
        self.engine.output()
