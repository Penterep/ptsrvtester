"""IMAP protocol main — thin BaseMain specialization."""
from __future__ import annotations

import argparse
import importlib
import socket
import sys

from ptlibs.ptprinthelper import out_if
from ptlibs.threads import printlock

from .._base import BaseArgs, BaseMain
from .._shared.utils.connection import banner_tcp_adapter
from .utils.cli import IMAPArgs, validate_imap_selection
from .utils.engine import ImapEngine
from .utils.registry import IMAP_DEFAULT_SUITE
from .utils.report import ImapReport


class IMAP(BaseMain):
    NAME = "imap"
    ARGS_CLASS = IMAPArgs

    @staticmethod
    def module_args() -> BaseArgs:
        return IMAPArgs()

    def __init__(self, args: BaseArgs, ptjsonlib) -> None:
        if not isinstance(args, IMAPArgs):
            raise argparse.ArgumentError(
                None, f'module "{getattr(args, "module", "?")}" received wrong arguments namespace'
            )
        validate_imap_selection(args)
        if not getattr(args, "module_threads", None):
            args.module_threads = 1
        self.report = ImapReport()
        self.engine = ImapEngine(args, report=self.report)
        super().__init__(args, ptjsonlib)

    def _import_module_file(self, name: str, path: str):
        return importlib.import_module(f"ptsrvtester.protocols.imap.modules.{name}")

    def _run_module(self, code: str, discovered, extras: dict) -> None:
        """Heading now; ``-vv`` live; verdicts when the test finishes."""
        entry = discovered[code]
        lock = printlock.PrintLock()
        ctx = self._make_context(lock, extras)
        if not self.use_json:
            def live_debug(string="", *, indent=4):
                if not ctx.verbose:
                    return
                line = out_if(string, "ADDITIONS", True, colortext=True, indent=indent)
                if line:
                    sys.stdout.write(line if line.endswith("\n") else line + "\n")
                    sys.stdout.flush()
            ctx.debug = live_debug
        if entry.label.strip() and not self.use_json:
            sys.stdout.write(out_if(entry.label, "INFO", True, colortext=True) + "\n")
            sys.stdout.flush()
        try:
            entry.module.run(ctx)
        except Exception as e:
            ctx.out(f"Error in module {code}: {e}", "ERROR")
        chunk = lock.get_output_string()
        if chunk and not self.use_json:
            sys.stdout.write(chunk)
            sys.stdout.flush()
        with self._lock:
            self._outputs[code] = "" if not self.use_json else chunk

    def _prepare_target(self) -> None:
        target = self.args.target
        if getattr(target, "port", 0) == 0:
            target.port = 993 if getattr(self.args, "tls", False) else 143

        host = target.ip
        try:
            socket.inet_aton(host)
            ip = host
        except OSError:
            try:
                ip = socket.gethostbyname(host)
            except socket.gaierror as e:
                raise argparse.ArgumentError(
                    None, f"Cannot resolve domain name '{host}' to IP address"
                ) from e
        self.target_host = host
        self.target = (ip, target.port)

    def _select_codes(self, discovered):
        raw = getattr(self.args, "tests", None)
        codes = [c.strip().upper() for c in raw.split(",")] if raw else []
        codes = [c for c in codes if c]
        if not codes or "ALL" in codes:
            chosen = [c for c in IMAP_DEFAULT_SUITE if c in discovered]
            chosen.sort(key=lambda c: (discovered[c].order, c))
            return chosen
        return super()._select_codes(discovered)

    def build_context(self) -> dict:
        return {
            "host": self.target_host,
            "ip": self.target[0],
            "port": self.target[1],
            "tls": bool(getattr(self.args, "tls", False)),
            "starttls": bool(getattr(self.args, "starttls", False)),
            "engine": self.engine,
            "report": self.report,
            "rate_limit_adapter": banner_tcp_adapter(self.target[0], self.target[1], self.args),
        }

    def output(self) -> None:
        if self.report.connect_error and self.use_json:
            self.ptjsonlib.end_error(self.report.connect_error, self.use_json)
            return
        # Prefer engine JSON assembly (ported from monolith output()).
        self.engine.use_json = self.use_json
        self.engine.build_json(self.ptjsonlib)
