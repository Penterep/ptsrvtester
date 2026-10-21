"""DNS protocol main — protocol-specific configuration only.

All the generic machinery (module discovery, ``-ts`` selection, parallel
execution, ordered output, the ``ctx`` object) lives in :class:`BaseMain` in
``protocols/_base.py``. This file declares only what is specific to DNS plus a
small :meth:`output` override: the JSON carries nothing but the run ``log`` and
``vulnerabilities``, where every distinct finding code a module reported becomes
its own ``{"vulnCode": ...}`` entry. No ``software`` node and no ``properties``
are emitted. Mirrors ``ssh/main.py``.
"""
import argparse
import socket
import threading

from ptlibs.ptjsonlib import PtJsonLib

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

    def output(self) -> None:
        """Emit one vulnerability object per finding code, like ``ssh/main.py``.

        Each code a module appended to ``ctx.deferred_vulns`` becomes its own
        ``{"vulnCode": ...}`` entry in ``results.vulnerabilities`` via ptlibs
        ``add_vulnerability`` (which de-duplicates by code, so the same code seen
        for several domains collapses to one entry). No ``software`` node and no
        ``properties`` are written; besides the log, nothing else goes into the JSON.
        """
        for v in self._deferred_vulns:
            self.ptjsonlib.add_vulnerability(vuln_code=v["vuln_code"])

        self.ptjsonlib.set_status("finished", "")
        if self.use_json:
            print(self.ptjsonlib.get_result_json())
