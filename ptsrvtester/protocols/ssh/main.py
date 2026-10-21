"""SSH protocol main — protocol-specific configuration only.

All the generic machinery (module discovery, ``-ts`` selection, ordered output,
the ``ctx`` object) lives in :class:`BaseMain` in ``protocols/_base.py``. This
file declares only what is specific to SSH. The JSON output carries nothing but
the run ``log`` and ``vulnerabilities``: a module that finds something calls
``ctx.vulns.hit(ctx.module_code)``, and :meth:`output` emits ONE vulnerability
object per hit test code — each a ``{"vulnCode": "PTV-SSH-<MODULECODE>"}`` entry
(second position = protocol) in ``results.vulnerabilities``. No nodes or
properties are emitted.
"""
import argparse
import socket

from .._base import BaseMain, BaseArgs
from .utils.cli import SSHArgs
from .utils.results import VulnCollector
from .utils.sshaudit import SSHAuditShared


class SSH(BaseMain):
    NAME = "ssh"
    ARGS_CLASS = SSHArgs

    @staticmethod
    def module_args() -> BaseArgs:
        return SSHArgs()

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

    def build_context(self) -> dict:
        """Handles every SSH module receives on ``ctx`` (besides the core fields).

        Modules read connection info as ``ctx.host`` / ``ctx.ip`` / ``ctx.port``
        and record a finding with ``ctx.vulns.hit(ctx.module_code)``; ``vulns`` is
        one shared :class:`VulnCollector` for the whole run. ``ssh_audit`` is the
        run-once ssh-audit holder every crypto section test
        (KEX/KEYALG/ENC/MAC/FINGERPRINT) shares, so the external ssh-audit scan
        happens at most once per invocation.
        """
        from .._shared.utils.connection import SSHBannerAdapter

        self._vulns = VulnCollector()
        rate_timeout = getattr(self.args, "rate_timeout", 5.0) or 5.0
        return {
            "host": self.target_host,
            "ip": self.target[0],
            "port": self.target[1],
            "vulns": self._vulns,
            "ssh_audit": SSHAuditShared(self.target[0], self.target[1]),
            # Sharper RATELIMIT signal: a connection counts only once sshd sends
            # its SSH-2.0 banner, and holding it (no KEX) exercises LoginGraceTime.
            "rate_limit_adapter": SSHBannerAdapter(
                self.target[0], self.target[1], rate_timeout
            ),
        }

    def output(self) -> None:
        """Emit one vulnerability object per SSH test code that found something.

        Each ``PTV-SSH-<MODULECODE>`` code the run collected becomes its own entry
        in ``results.vulnerabilities`` (``{"vulnCode": ...}``), added through ptlibs
        ``add_vulnerability`` (which de-duplicates by code). Besides the log,
        nothing else is written to the JSON.
        """
        vulns = getattr(self, "_vulns", None)
        for code in (vulns.codes if vulns is not None else []):
            self.ptjsonlib.add_vulnerability(vuln_code=code)
        self.ptjsonlib.set_status("finished", "")
        if self.use_json:
            print(self.ptjsonlib.get_result_json())