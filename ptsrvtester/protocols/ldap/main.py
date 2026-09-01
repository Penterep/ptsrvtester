"""LDAP protocol main."""
from __future__ import annotations

import argparse
import importlib
import socket

from .._base import BaseArgs, BaseMain
from .utils.cli import LDAPArgs, LDAP_DEFAULT_SUITE
from .utils.engine import LDAPResult, LdapEngine


class LDAP(BaseMain):
    NAME = "ldap"
    ARGS_CLASS = LDAPArgs

    @staticmethod
    def module_args() -> BaseArgs:
        return LDAPArgs()

    def __init__(self, args: BaseArgs, ptjsonlib) -> None:
        if not isinstance(args, LDAPArgs):
            raise argparse.ArgumentError(None, "wrong arguments namespace for ldap")
        if not getattr(args, "module_threads", None):
            args.module_threads = 1
        self.engine = LdapEngine(args, ptjsonlib)
        self.engine.results = LDAPResult()
        super().__init__(args, ptjsonlib)

    def _import_module_file(self, name: str, path: str):
        return importlib.import_module(f"ptsrvtester.protocols.ldap.modules.{name}")

    def _prepare_target(self) -> None:
        target = self.args.target
        if getattr(target, "port", 0) == 0:
            target.port = 636 if getattr(self.args, "use_ssl", False) else 389
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
            chosen = [c for c in LDAP_DEFAULT_SUITE if c in discovered]
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
            self.engine.results = LDAPResult()
        self.engine.output()
