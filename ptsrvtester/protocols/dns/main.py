"""DNS protocol main — protocol-specific configuration only.

All the generic machinery (module discovery, ``-ts`` selection, parallel
execution, ordered output, the ``ctx`` object) lives in :class:`BaseMain` in
``protocols/_base.py``. This file declares only what is specific to DNS plus a
small :meth:`output` override so every module contributes to a single shared
``software`` node in JSON output (all DNS findings bind to one node). Mirrors
``ssh/main.py``.
"""
import argparse
import socket
import sys
import threading

from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.threads import printlock

from .._base import BaseMain, BaseArgs
from .utils.cli import DNSArgs

DNS_DEFAULT_PORT = 53


class DNS(BaseMain):
    NAME = "dns"
    ARGS_CLASS = DNSArgs

    @staticmethod
    def module_args() -> BaseArgs:
        return DNSArgs()

    def __init__(self, args: BaseArgs, ptjsonlib: PtJsonLib) -> None:
        super().__init__(args, ptjsonlib)
        self._properties: dict = {
            "software_type": None,
            "name": "dns",
            "version": None,
            "vendor": None,
            "description": None,
        }
        self._deferred_vulns: list[dict] = []
        self._results_lock = threading.Lock()

    def _prepare_target(self) -> None:
        """Resolve the DNS server target (``-tg``) to ``(ip, port)`` for the modules.

        ``-tg`` is optional: with no target, tests fall back to the system
        resolver / authoritative-NS discovery, so ``self.target`` becomes
        ``(None, 53)`` and ``self.target_host`` is ``None``.
        """
        target = getattr(self.args, "target", None)
        if target is None:
            self.target_host = None
            self.target = (None, DNS_DEFAULT_PORT)
            return

        if getattr(target, "port", 0) == 0:
            target.port = DNS_DEFAULT_PORT

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

    def build_context(self) -> dict:
        """Handles every DNS module receives on ``ctx`` (besides the core fields).

        ``properties`` / ``deferred_vulns`` are the shared JSON accumulators and
        ``results_lock`` guards them; modules read connection info as
        ``ctx.host`` / ``ctx.ip`` / ``ctx.port`` (any may be ``None`` when no
        ``-tg`` server was given).
        """
        return {
            "host": self.target_host,
            "ip": self.target[0],
            "port": self.target[1],
            "properties": self._properties,
            "deferred_vulns": self._deferred_vulns,
            "results_lock": self._results_lock,
        }

    def _run_module(self, code: str, discovered: dict, extras: dict) -> None:
        """Run one module and flush its result to the screen IMMEDIATELY.

        BaseMain buffers every module's output and prints it all at the very end;
        DNS instead streams each test's result as soon as that module finishes, so
        the user sees results live and does not wait for the other tests. With the
        DNS default of one module thread this stays correctly ordered. The chunk is
        cleared afterwards so BaseMain.run()'s end-of-run flush does not reprint it.
        Output is written under ``self._lock`` so a module's lines are never
        interleaved with another's.
        """
        entry = discovered[code]
        lock = printlock.PrintLock()
        ctx = self._make_context(lock, extras)
        ctx.out(entry.label, "INFO", colortext=True)
        try:
            entry.module.run(ctx)
        except Exception as e:
            ctx.out(f"Error in module {code}: {e}", "ERROR")
        chunk = lock.get_output_string()
        with self._lock:
            if chunk:
                sys.stdout.write(chunk)
                sys.stdout.flush()
            self._outputs[code] = ""  # already streamed — avoid BaseMain reprinting it

    def output(self) -> None:
        """Build the single shared ``software`` node and bind every module's vulns."""
        dns_node = self.ptjsonlib.create_node_object("software", None, None, self._properties)
        self.ptjsonlib.add_node(dns_node)
        node_key = dns_node["key"]
        for v in self._deferred_vulns:
            self.ptjsonlib.add_vulnerability(node_key=node_key, **v)

        self.ptjsonlib.set_status("finished", "")
        if self.use_json:
            print(self.ptjsonlib.get_result_json())
