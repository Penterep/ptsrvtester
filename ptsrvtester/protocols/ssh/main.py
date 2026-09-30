"""SSH protocol main — protocol-specific configuration only.

All the generic machinery (module discovery, ``-ts`` selection, parallel
execution, ordered output, the ``ctx`` object) lives in :class:`BaseMain` in
``protocols/_base.py``. This file declares only what is specific to SSH plus a
small :meth:`output` override so every module contributes to a single shared
``software`` node in JSON output (banner, host key, auth methods, ssh-audit,
bad-key and bruteforce findings all bind to one node, like the old flat module).
"""
import argparse
import socket
import threading

from ptlibs.ptjsonlib import PtJsonLib

from .._base import BaseMain, BaseArgs
from .utils.cli import SSHArgs
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

    def __init__(self, args: BaseArgs, ptjsonlib: PtJsonLib) -> None:
        super().__init__(args, ptjsonlib)
        self._properties: dict = {
            "software_type": None,
            "name": "ssh",
            "version": None,
            "vendor": None,
            "description": None,
        }
        self._deferred_vulns: list[dict] = []
        self._results_lock = threading.Lock()

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

        ``properties`` / ``deferred_vulns`` are the shared JSON accumulators and
        ``results_lock`` guards them; modules read connection info as ``ctx.host`` /
        ``ctx.ip`` / ``ctx.port``. ``ssh_audit`` is the run-once ssh-audit holder
        every crypto section test (KEX/KEYALG/ENC/MAC/FINGERPRINT) shares, so the
        external ssh-audit scan happens at most once per invocation.
        """
        from .._shared.utils.connection import SSHBannerAdapter

        rate_timeout = getattr(self.args, "rate_timeout", 5.0) or 5.0
        return {
            "host": self.target_host,
            "ip": self.target[0],
            "port": self.target[1],
            "properties": self._properties,
            "deferred_vulns": self._deferred_vulns,
            "results_lock": self._results_lock,
            "ssh_audit": SSHAuditShared(self.target[0], self.target[1]),
            # Sharper RATELIMIT signal: a connection counts only once sshd sends
            # its SSH-2.0 banner, and holding it (no KEX) exercises LoginGraceTime.
            "rate_limit_adapter": SSHBannerAdapter(
                self.target[0], self.target[1], rate_timeout
            ),
        }

    def output(self) -> None:
        """Build the single shared ``software`` node and bind every module's vulns."""
        ssh_node = self.ptjsonlib.create_node_object("software", None, None, self._properties)
        self.ptjsonlib.add_node(ssh_node)
        node_key = ssh_node["key"]
        for v in self._deferred_vulns:
            self.ptjsonlib.add_vulnerability(node_key=node_key, **v)

        self.ptjsonlib.set_status("finished", "")
        if self.use_json:
            print(self.ptjsonlib.get_result_json())