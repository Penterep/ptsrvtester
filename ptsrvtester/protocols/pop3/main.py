"""POP3 protocol main — thin BaseMain specialization."""
from __future__ import annotations

import argparse
import importlib
import socket
import sys

from ptlibs.ptprinthelper import out_if
from ptlibs.threads import printlock

from .._base import BaseArgs, BaseMain
from .._shared.utils.connection import banner_tcp_adapter
from .utils.cli import POP3Args, validate_brute_selection
from .utils.connection import ServerInfoCache, connect_pop3
from .utils.registry import POP3_DEFAULT_SUITE
from .utils.report import Pop3Report


class POP3(BaseMain):
    NAME = "pop3"
    ARGS_CLASS = POP3Args

    @staticmethod
    def module_args() -> BaseArgs:
        return POP3Args()

    def __init__(self, args: BaseArgs, ptjsonlib) -> None:
        if not isinstance(args, POP3Args):
            raise argparse.ArgumentError(
                None, f'module "{getattr(args, "module", "?")}" received wrong arguments namespace'
            )
        validate_brute_selection(args)
        # Ensure serial module runs unless operator overrides.
        if not getattr(args, "module_threads", None):
            args.module_threads = 1
        self.report = Pop3Report()
        super().__init__(args, ptjsonlib)

    def _import_module_file(self, name: str, path: str):
        """Import as a real package member so ``from ..utils`` works in modules.

        BaseMain's file-location loader sets no ``__package__``, which breaks
        relative imports. POP3 modules live under ``protocols.pop3.modules``.
        """
        return importlib.import_module(f"ptsrvtester.protocols.pop3.modules.{name}")

    def _run_module(self, code: str, discovered, extras: dict) -> None:
        """Heading now; ``-vv`` live; verdicts when the test finishes.

        CAPA uses an empty label (it prints its own ``[+] CAPA command …`` titles).
        """
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
            target.port = 995 if getattr(self.args, "tls", False) else 110

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
        """Empty/-ts ALL → default suite (not BRUTE/NTLM); explicit codes as requested."""
        raw = getattr(self.args, "tests", None)
        codes = [c.strip().upper() for c in raw.split(",")] if raw else []
        codes = [c for c in codes if c]
        if not codes or "ALL" in codes:
            chosen = [c for c in POP3_DEFAULT_SUITE if c in discovered]
            chosen.sort(key=lambda c: (discovered[c].order, c))
            return chosen
        return super()._select_codes(discovered)

    def build_context(self) -> dict:
        cache = ServerInfoCache(self.args)
        return {
            "host": self.target_host,
            "ip": self.target[0],
            "port": self.target[1],
            "tls": bool(getattr(self.args, "tls", False)),
            "starttls": bool(getattr(self.args, "starttls", False)),
            "connect": lambda debug=None: connect_pop3(self.args, debug=debug),
            "server_info": cache,
            "report": self.report,
            "rate_limit_adapter": banner_tcp_adapter(self.target[0], self.target[1], self.args),
        }

    def output(self) -> None:
        """Emit one software node + collected vulnerabilities (JSON mode)."""
        if self.report.connect_error and self.use_json:
            self.ptjsonlib.end_error(self.report.connect_error, self.use_json)
            return

        node = self.ptjsonlib.create_node_object("software", None, None, self.report.properties)
        self.ptjsonlib.add_node(node)
        node_key = node["key"]
        for vuln in self.report.vulns:
            self.ptjsonlib.add_vulnerability(node_key=node_key, **vuln)

        self.ptjsonlib.set_status("finished", "")
        if self.use_json:
            print(self.ptjsonlib.get_result_json())
