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
import json
import socket
import threading

from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.ptprinthelper import ptprint

from .._base import BaseMain, BaseArgs, ModuleContext
from .utils.cli import DNSArgs

DNS_DEFAULT_PORT = 53


class DnsModuleContext(ModuleContext):
    """DNS ``ctx`` that mirrors the ``-vv`` screen into ``results.log``.

    Leaves ``_base.py`` untouched: it subclasses :class:`ModuleContext` and is
    wired in via :meth:`DNS._make_context`. Every ``out()`` / ``debug()`` line is
    appended to ``results.log`` through ptlibs ``add_to_log`` (so entries are
    CRLF-separated), as it reads on screen but WITHOUT the leading indentation
    and WITH the status icon on ``out()`` verdict lines. The framework module
    heading (``INFO`` at indent 0) is not logged. Non-ASCII stays literal because
    :meth:`DNS.output` dumps with ``ensure_ascii=False``.
    """

    def out(self, string="", category="TEXT", *, colortext=False, indent=0, condition=None):
        super().out(string, category, colortext=colortext, indent=indent, condition=condition)
        if not (category == "INFO" and indent == 0):   # skip the framework module heading
            self._mirror(string, category)

    def debug(self, string="", *, indent=4):
        if string != "":
            self._mirror(string, "ADDITIONS")
        if self.verbose and not self.json:
            ptprint(string, "ADDITIONS", True, colortext=True, indent=indent)

    def _mirror(self, string, category) -> None:
        """Append one line to results.log: the on-screen bullet icon + text (no
        indentation), separated from previous entries by ptlibs with CRLF.

        Also advances ``_log_end`` so this module's log segment (``_log_start`` ..
        ``_log_end``) can later feed a per-finding ``poc`` (see :meth:`DNS.output`).
        """
        from ptlibs import ptdefs
        char = ptdefs.chars.get((category or "").upper(), "")
        prefix = f"[{char}] " if char else ""
        self.ptjsonlib.add_to_log(f"{prefix}{string}")
        self._log_end = len(self.ptjsonlib.json_object["results"].get("log", ""))


class _VulnSink:
    """Per-module proxy over the shared deferred-vulns list.

    Modules keep calling ``ctx.deferred_vulns.append(...)`` / ``.extend(...)``; this
    tags each finding with the context that recorded it, so :meth:`DNS.output` can
    set ``poc`` to ONLY that module's log segment (not the whole run's log).
    """

    def __init__(self, shared: list, ctx) -> None:
        self._shared = shared
        self._ctx = ctx

    def append(self, vuln: dict) -> None:
        entry = dict(vuln)
        entry["_ctx"] = self._ctx
        self._shared.append(entry)

    def extend(self, vulns) -> None:
        for v in vulns:
            self.append(v)


class DNS(BaseMain):
    NAME = "dns"
    ARGS_CLASS = DNSArgs

    @staticmethod
    def module_args() -> BaseArgs:
        return DNSArgs()

    def __init__(self, args: BaseArgs, ptjsonlib: PtJsonLib) -> None:
        super().__init__(args, ptjsonlib)
        self._deferred_vulns: list[dict] = []
        self._results_lock = threading.Lock()

    def _make_context(self, extras: dict) -> ModuleContext:
        """Build a :class:`DnsModuleContext` (mirrors the -vv screen into the log).

        Same wiring as ``BaseMain._make_context`` but with the DNS-specific
        context class — so the log-mirroring lives here, not in ``_base.py``.
        """
        ctx = DnsModuleContext(
            args=self.args,
            ptjsonlib=self.ptjsonlib,
            target=self.target,
        )
        for key, value in extras.items():
            setattr(ctx, key, value)
        # Mark where this module's log segment begins and wrap the shared vulns
        # list so each finding remembers its module (for a per-module poc).
        start = len(self.ptjsonlib.json_object["results"].get("log", ""))
        ctx._log_start = start
        ctx._log_end = start
        ctx.deferred_vulns = _VulnSink(self._deferred_vulns, ctx)
        return ctx

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

        ``deferred_vulns`` is the shared findings accumulator and ``results_lock``
        guards it; modules read connection info as ``ctx.host`` / ``ctx.ip`` /
        ``ctx.port`` (any may be ``None`` when no ``-tg`` server was given). No
        ``properties`` handle is exposed — the JSON ``properties`` object stays empty.
        """
        return {
            "host": self.target_host,
            "ip": self.target[0],
            "port": self.target[1],
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

        ``poc`` is the proof for THAT finding only: the log segment of the module
        that recorded it (``ctx._log_start`` .. ``ctx._log_end``), not the whole
        run's log. The JSON is dumped here with ``ensure_ascii=False`` (instead of
        ptlibs' ``get_result_json``, whose json default would escape any non-ASCII
        text to ``\\uXXXX``) so the log stays literal. Kept here in the DNS main so
        neither ``ptsrvtester.py`` nor ``_base.py`` is touched.
        """
        log_text = self.ptjsonlib.json_object["results"].get("log", "")
        for v in self._deferred_vulns:
            ctx = v.get("_ctx")
            if ctx is not None:
                poc = log_text[getattr(ctx, "_log_start", 0):getattr(ctx, "_log_end", len(log_text))]
                poc = poc.strip("\r\n")
            else:
                poc = log_text
            self.ptjsonlib.add_vulnerability(vuln_code=v["vuln_code"], poc=poc)

        self.ptjsonlib.set_status("finished", "")
        if self.use_json:
            print(json.dumps(self.ptjsonlib.json_object, indent=4, ensure_ascii=False))
