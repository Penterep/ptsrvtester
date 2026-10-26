"""POP3 protocol main — thin BaseMain specialization."""
from __future__ import annotations

import argparse
import importlib
import socket

from .._base import BaseArgs, BaseMain
from .._shared.utils.connection import banner_tcp_adapter, end_if_target_unreachable
from .utils.cli import POP3Args, validate_brute_selection
from .utils.helpers import (
    apply_default_brute_creds,
    brute_sorted_creds,
    brute_weak_request,
    brute_weak_response,
    get_mode,
)
from .utils.results import VULNS
from .utils.connection import ServerInfoCache, _pop3_default_account, connect_pop3
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
        raw = getattr(args, "tests", None) or ""
        codes = {c.strip().upper() for c in str(raw).split(",") if c.strip()}
        if "BRUTE" in codes and "ALL" not in codes:
            apply_default_brute_creds(args)
        self.report = Pop3Report()
        super().__init__(args, ptjsonlib)

    def _import_module_file(self, name: str, path: str):
        """Import as a real package member so ``from ..utils`` works in modules.

        BaseMain's file-location loader sets no ``__package__``, which breaks
        relative imports. POP3 modules live under ``protocols.pop3.modules``.
        """
        return importlib.import_module(f"ptsrvtester.protocols.pop3.modules.{name}")

    def _run_module(self, code: str, discovered, extras: dict) -> None:
        """One test, serial. ``ctx.debug`` logs every note and prints it on ``-vv``.

        CAPA uses an empty label (it prints its own ``[+] CAPA command …`` titles).
        """
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

    def _brute_only(self) -> bool:
        raw = getattr(self.args, "tests", None) or ""
        codes = {c.strip().upper() for c in str(raw).split(",") if c.strip()}
        return codes == {"BRUTE"}

    def _brute_vuln_entries(self) -> list[dict]:
        vulns: list[dict] = []
        if self.report.properties.get("pop3PasswordGuessing") == "not_limited":
            vulns.append({"vuln_code": VULNS.AuthBlock.value})
        creds = brute_sorted_creds(self.report.brute_creds)
        if creds:
            request = brute_weak_request(self.args)
            response = brute_weak_response(creds)
            codes = [VULNS.WeakCredentials.value, VULNS.WeakCreds.value]
            if any(_pop3_default_account(c.user, c.passw)[0] for c in creds):
                codes.append(VULNS.DefAcc.value)
            if any(_pop3_default_account(c.user, c.passw)[1] for c in creds):
                codes.append(VULNS.DefAccPw.value)
            for code in codes:
                vulns.append({
                    "vuln_code": code,
                    "vuln_request": request,
                    "vuln_response": response,
                })
        return vulns

    def _add_brute_account_nodes(self) -> None:
        for cred in brute_sorted_creds(self.report.brute_creds):
            node = self.ptjsonlib.create_node_object(
                "userAccount",
                parent_type="userAccounts",
                parent=None,
                properties={"login": cred.user, "password": cred.passw},
            )
            self.ptjsonlib.add_node(node)

    def _add_vulns(self, vulns: list[dict], *, node_key: str | None = None) -> None:
        for entry in vulns:
            stamped = dict(entry)
            if not stamped.get("poc"):
                poc = self.report.poc_for(stamped.get("vuln_code"))
                if poc:
                    stamped["poc"] = poc
            if node_key:
                self.ptjsonlib.add_vulnerability(node_key=node_key, **stamped)
            else:
                self.ptjsonlib.add_vulnerability(**stamped)

    def _emit_brute_json(self) -> None:
        self._add_brute_account_nodes()
        self._add_vulns(self._brute_vuln_entries())
        self.ptjsonlib.set_status("finished", "")
        if self.use_json:
            print(self.ptjsonlib.get_result_json())

    def run(self) -> None:
        mode = "TLS" if (self.args.tls or self.args.target.port == 995) else get_mode(self.args)
        end_if_target_unreachable(self, mode=mode)
        super().run()

    def output(self) -> None:
        """Emit one software node + collected vulnerabilities (JSON mode)."""
        if self.report.connect_error and self.use_json:
            self.ptjsonlib.end_error(self.report.connect_error, self.use_json)
            return
        if self._brute_only():
            self._emit_brute_json()
            return

        node = self.ptjsonlib.create_node_object("software", None, None, self.report.properties)
        self.ptjsonlib.add_node(node)
        node_key = node["key"]
        self._add_vulns(self.report.vulns, node_key=node_key)
        self._add_brute_account_nodes()
        self._add_vulns(self._brute_vuln_entries())

        self.ptjsonlib.set_status("finished", "")
        if self.use_json:
            print(self.ptjsonlib.get_result_json())
