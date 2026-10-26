"""SMTP protocol main — thin BaseMain specialization."""
from __future__ import annotations

import argparse
import importlib
import socket

from .._base import BaseArgs, BaseMain
from .._shared.utils.connection import banner_tcp_adapter, end_if_target_unreachable
from .utils.cli import SMTPArgs
from .utils.helpers import get_mode
from .utils.registry import _apply_smtp_tests, _smtp_parse_test_codes, smtp_auto_suite
from .utils.engine import SmtpEngine
from .utils.report import SmtpReport


class SMTP(BaseMain):
    NAME = "smtp"
    ARGS_CLASS = SMTPArgs

    @staticmethod
    def module_args() -> BaseArgs:
        return SMTPArgs()

    def __init__(self, args: BaseArgs, ptjsonlib) -> None:
        if not isinstance(args, SMTPArgs):
            raise argparse.ArgumentError(
                None, f'module "{getattr(args, "module", "?")}" received wrong arguments namespace'
            )
        _apply_smtp_tests(args)
        SmtpEngine._validate_smtp_args(args)
        self.report = SmtpReport()
        self.engine = SmtpEngine(args, ptjsonlib=ptjsonlib, report=self.report)
        codes = _smtp_parse_test_codes(getattr(args, "tests", None))
        self.engine.run_all_mode = (not codes or "ALL" in codes)
        super().__init__(args, ptjsonlib)

    def _import_module_file(self, name: str, path: str):
        return importlib.import_module(f"ptsrvtester.protocols.smtp.modules.{name}")

    def _relay_code_for_all(self) -> str:
        """ALL runs one relay test: Submission -> RELANON, otherwise OPENREL (MTA and hybrid)."""
        role = getattr(getattr(self.engine.results, "role", None), "role", None)
        if role == "submission":
            return "RELANON"
        return "OPENREL"

    def _run_module(self, code: str, discovered, extras: dict) -> None:
        """One test, serial. ``ctx.debug`` logs every note and prints it on ``-vv``."""
        if (
            self.engine.run_all_mode
            and code in ("OPENREL", "RELANON")
            and code != self._relay_code_for_all()
        ):
            return
        entry = discovered[code]
        ctx = self._make_context(extras)
        ctx.module_code = code
        if entry.label.strip():
            ctx.out(entry.label, "INFO", colortext=True)
        try:
            entry.module.run(ctx)
        except Exception as e:
            ctx.out(f"Error in module {code}: {e}", "ERROR")

    def _prepare_target(self) -> None:
        target = self.args.target
        if getattr(target, "port", 0) == 0:
            if getattr(self.args, "tls", False):
                target.port = 465
            elif getattr(self.args, "starttls", False):
                target.port = 587
            else:
                target.port = 25
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
            chosen = [c for c in smtp_auto_suite(self.args) if c in discovered]
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

    def run(self) -> None:
        mode = "TLS" if (self.args.tls or self.args.target.port == 465) else get_mode(self.args)
        end_if_target_unreachable(self, mode=mode, smtp_port_hint=True)
        super().run()

    def output(self) -> None:
        if self.report.connect_error and self.use_json and not getattr(self.engine.results, "info_error", None):
            self.engine.results.info_error = self.report.connect_error
        self.engine.use_json = self.use_json
        self.engine.ptjsonlib = self.ptjsonlib
        self.engine.output()
