"""SSH protocol main — protocol-specific configuration only.

All the generic machinery (module discovery, ``-ts`` selection, ordered output,
the ``ctx`` object) lives in :class:`BaseMain` in ``protocols/_base.py``. This
file declares only what is specific to SSH, plus the same JSON/-vv redesign the
DNS protocol uses (kept entirely in this layer — ``_base.py`` and
``ptsrvtester.py`` are never touched):

* :class:`SshModuleContext` mirrors each ``out()`` / ``debug()`` line into
  ``results.log`` (with its status icon, CRLF-separated) so the JSON log reads
  exactly like the ``-vv`` screen;
* every finding carries a ``poc`` = ONLY that module's log segment;
* vulnerability codes are ``{"vulnCode": "PTV-SVC-SSH-<MODULECODE>"}`` and the
  JSON is dumped with ``ensure_ascii=False`` so non-ASCII stays literal.

No ``software`` node and no ``properties`` are emitted; besides the log, only the
vulnerabilities go into the JSON. Mirrors ``dns/main.py``.
"""
import argparse
import json
import socket

from ptlibs.ptprinthelper import ptprint

from .._base import BaseMain, BaseArgs, ModuleContext
from .utils.cli import SSHArgs
from .utils.results import VulnCollector
from .utils.sshaudit import SSHAuditShared


class SshModuleContext(ModuleContext):
    """SSH ``ctx`` that mirrors the ``-vv`` screen into ``results.log``.

    Leaves ``_base.py`` untouched: it subclasses :class:`ModuleContext` and is
    wired in via :meth:`SSH._make_context`. Every ``out()`` / ``debug()`` line is
    appended to ``results.log`` through ptlibs ``add_to_log`` (so entries are
    CRLF-separated), as it reads on screen but WITHOUT the leading indentation
    and WITH the status icon on ``out()`` verdict lines. The framework module
    heading (``INFO`` at indent 0) is not logged. Non-ASCII stays literal because
    :meth:`SSH.output` dumps with ``ensure_ascii=False``.
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
        ``_log_end``) can later feed a per-finding ``poc`` (see :meth:`SSH.output`).
        """
        from ptlibs import ptdefs
        char = ptdefs.chars.get((category or "").upper(), "")
        prefix = f"[{char}] " if char else ""
        self.ptjsonlib.add_to_log(f"{prefix}{string}")
        self._log_end = len(self.ptjsonlib.json_object["results"].get("log", ""))


class _VulnSink:
    """Per-module proxy over the shared :class:`VulnCollector`.

    Modules keep calling ``ctx.vulns.hit(ctx.module_code)``; this tags the finding
    with the context that recorded it, so :meth:`SSH.output` can set ``poc`` to
    ONLY that module's log segment (not the whole run's log).
    """

    def __init__(self, shared: VulnCollector, ctx) -> None:
        self._shared = shared
        self._ctx = ctx

    def hit(self, module_code) -> None:
        self._shared.hit(module_code, ctx=self._ctx)


class SSH(BaseMain):
    NAME = "ssh"
    ARGS_CLASS = SSHArgs

    @staticmethod
    def module_args() -> BaseArgs:
        return SSHArgs()

    def __init__(self, args: BaseArgs, ptjsonlib) -> None:
        super().__init__(args, ptjsonlib)
        self._vulns = VulnCollector()
        self._reach_cache: dict = {}   # (ip, port) -> bool, shared service-reachability verdict

    def _select_codes(self, discovered):
        """SSH-only tweak: in the default / ``ALL`` sweep, skip modules that opt out
        via ``__RUN_IN_ALL__ = False`` (tests needing extra options, e.g. BADHOSTKEY,
        BADAUTHKEY, BRUTE). Naming one of them explicitly in ``-ts`` still runs it.
        This overrides only SSH's selection; other protocols are unaffected.
        """
        chosen = super()._select_codes(discovered)
        raw = getattr(self.args, "tests", None)
        codes = {c.strip().upper() for c in raw.split(",")} if raw else set()
        run_all = (not codes) or ("ALL" in codes)
        if run_all:
            chosen = [c for c in chosen if getattr(discovered[c].module, "__RUN_IN_ALL__", True)]
        return chosen

    def _prepare_target(self) -> None:
        """Fill the default port (22) and resolve the host to an IP for the modules."""
        target = self.args.target
        if getattr(target, "port", 0) == 0:
            target.port = 22

        host = target.ip
        try:
            socket.inet_aton(host)
            ip = host
        except OSError:
            try:
                ip = socket.gethostbyname(host)
            except socket.gaierror:
                raise argparse.ArgumentError(
                    None, f"Cannot resolve domain name '{host}' to IP address"
                )
        self.target_host = host
        self.target = (ip, target.port)

    def _make_context(self, extras: dict) -> ModuleContext:
        """Build a :class:`SshModuleContext` (mirrors the -vv screen into the log).

        Same wiring as ``BaseMain._make_context`` but with the SSH-specific context
        class — so the log-mirroring lives here, not in ``_base.py``.
        """
        ctx = SshModuleContext(
            args=self.args,
            ptjsonlib=self.ptjsonlib,
            target=self.target,
        )
        for key, value in extras.items():
            setattr(ctx, key, value)
        # Mark where this module's log segment begins and wrap the shared vuln
        # collector so each finding remembers its module (for a per-module poc).
        start = len(self.ptjsonlib.json_object["results"].get("log", ""))
        ctx._log_start = start
        ctx._log_end = start
        ctx.vulns = _VulnSink(self._vulns, ctx)
        return ctx

    def build_context(self) -> dict:
        """Handles every SSH module receives on ``ctx`` (besides the core fields).

        Modules read connection info as ``ctx.host`` / ``ctx.ip`` / ``ctx.port``
        and record a finding with ``ctx.vulns.hit(ctx.module_code)`` (``vulns`` is a
        per-ctx sink over one shared :class:`VulnCollector`). ``reach_cache`` is the
        run-shared service-reachability verdict (BANNER seeds it; the service tests
        read it). ``ssh_audit`` is the run-once ssh-audit holder every crypto
        section test (KEX/KEYALG/ENC/MAC/FINGERPRINT) shares, so the external
        ssh-audit scan happens at most once per invocation.
        """
        from .._shared.utils.connection import SSHBannerAdapter

        rate_timeout = getattr(self.args, "rate_timeout", 5.0) or 5.0
        return {
            "host": self.target_host,
            "ip": self.target[0],
            "port": self.target[1],
            "vulns": self._vulns,
            "reach_cache": self._reach_cache,
            "ssh_audit": SSHAuditShared(self.target[0], self.target[1]),
            # Sharper RATELIMIT signal: a connection counts only once sshd sends
            # its SSH-2.0 banner, and holding it (no KEX) exercises LoginGraceTime.
            "rate_limit_adapter": SSHBannerAdapter(
                self.target[0], self.target[1], rate_timeout
            ),
        }

    def output(self) -> None:
        """Emit one vulnerability object per SSH test code that found something.

        Each ``PTV-SVC-SSH-<MODULECODE>`` code the run collected becomes its own
        ``{"vulnCode": ..., "poc": ...}`` entry in ``results.vulnerabilities`` via
        ptlibs ``add_vulnerability`` (which de-duplicates by code). ``poc`` is the
        proof for THAT finding only: the log segment of the module that recorded it
        (``ctx._log_start`` .. ``ctx._log_end``), not the whole run's log. The JSON
        is dumped here with ``ensure_ascii=False`` (instead of ptlibs'
        ``get_result_json``, whose json default would escape non-ASCII to
        ``\\uXXXX``) so the log stays literal. Kept here in the SSH main so neither
        ``ptsrvtester.py`` nor ``_base.py`` is touched.
        """
        log_text = self.ptjsonlib.json_object["results"].get("log", "")
        for code, ctx in self._vulns.hits:
            if ctx is not None:
                poc = log_text[getattr(ctx, "_log_start", 0):getattr(ctx, "_log_end", len(log_text))]
                poc = poc.strip("\r\n")
            else:
                poc = log_text
            self.ptjsonlib.add_vulnerability(vuln_code=code, poc=poc)

        self.ptjsonlib.set_status("finished", "")
        if self.use_json:
            print(json.dumps(self.ptjsonlib.json_object, indent=4, ensure_ascii=False))
