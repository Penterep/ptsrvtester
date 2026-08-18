"""RDP integration with the generic protocol-module framework.

The wire protocol implementation remains in :mod:`.utils.engine`.  This class
owns one engine for the whole scan and exposes it to the small modules in
``modules/``.  Keeping that engine shared is security-sensitive: negotiation
and Basic Settings probes stay cached and an authenticated RDP session is
created at most once.
"""

from __future__ import annotations

import argparse
import importlib
import socket
from collections.abc import Iterable

from .._base import BaseArgs, BaseMain
from .utils.cli import (
    RDP_EXPLICIT_ONLY_TESTS,
    RDP_TEST_ALIASES,
    RDP_TEST_ORDER,
    RDPArgs,
)


class RDP(BaseMain):
    """Run the selected RDP checks through one shared RDP engine."""

    NAME = "rdp"
    ARGS_CLASS = RDPArgs

    @staticmethod
    def module_args() -> BaseArgs:
        return RDPArgs()

    def __init__(self, args: BaseArgs, ptjsonlib) -> None:
        # BaseMain validates the namespace and calls _prepare_target() first.
        super().__init__(args, ptjsonlib)

        # Import lazily so importing CLI/help metadata does not eagerly load the
        # sizeable RDP protocol implementation and its optional dependencies.
        from .utils.engine import RDP as RDPEngine

        # Reuse BaseMain's one-time DNS result for connection-pressure tests so
        # baseline, load and recovery cannot drift across round-robin targets.
        self.args._rdp_resolved_ip = self.target[0]

        # Exactly one coordinator/engine is shared by every discovered module.
        self.rdp_engine = RDPEngine(args, ptjsonlib)

    def _prepare_target(self) -> None:
        """Apply the RDP port and retain both the hostname and resolved IP.

        ``args.target.ip`` deliberately remains unchanged.  The engine needs
        the operator's original hostname for TLS SNI/certificate verification
        and JSON compatibility, while BaseMain's context receives the resolved
        address in ``self.target``.
        """
        target = self.args.target
        if getattr(target, "port", 0) == 0:
            target.port = 3389

        if getattr(self.args, "timeout", 0) <= 0:
            raise argparse.ArgumentError(None, "--timeout must be a positive integer")

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
                ) from None

        self.target_host = host
        self.target = (ip, target.port)

    @staticmethod
    def _test_tokens(raw: str | Iterable[str] | None) -> list[str]:
        """Accept both legacy space-separated and BaseMain comma syntax."""
        if raw is None:
            return []
        values = [raw] if isinstance(raw, str) else list(raw)
        tokens: list[str] = []
        for value in values:
            tokens.extend(
                item.strip().upper()
                for item in str(value).split(",")
                if item.strip()
            )
        return tokens

    def _select_codes(self, discovered) -> list[str]:
        """Select RDP modules without changing the legacy safety policy.

        With no ``-ts`` value only the safe pre-authentication checks run.
        ``AUTH`` is added only when both credential options were supplied.
        Explicit selections retain their input order, accept either lists or a
        comma-separated string, canonicalize ``INFO`` to ``NTLMINFO`` and
        remove duplicates.
        """
        tokens = self._test_tokens(getattr(self.args, "tests", None))

        if not tokens:
            chosen = [
                code
                for code in RDP_TEST_ORDER
                if code != "AUTH"
                and code not in RDP_EXPLICIT_ONLY_TESTS
                and code in discovered
            ]
            if (
                getattr(self.args, "login", None) is not None
                and getattr(self.args, "password", None) is not None
                and "AUTH" in discovered
            ):
                chosen.append("AUTH")
            return self._remember_selection(chosen)

        # ALL retains the legacy single AUTH check but never implies the active
        # RATELIMIT test. Naming RATELIMIT alongside ALL remains explicit.
        if "ALL" in tokens:
            chosen = [
                code
                for code in RDP_TEST_ORDER
                if code in discovered and code not in RDP_EXPLICIT_ONLY_TESTS
            ]
            known = set(chosen)
            chosen.extend(
                code
                for code, entry in sorted(
                    discovered.items(),
                    key=lambda item: (item[1].order, item[0]),
                )
                if code not in known and code not in RDP_EXPLICIT_ONLY_TESTS
            )
            if "RATELIMIT" in tokens and "RATELIMIT" in discovered:
                chosen.append("RATELIMIT")
            return self._remember_selection(chosen)

        chosen: list[str] = []
        seen: set[str] = set()
        unknown: list[str] = []
        for token in tokens:
            code = RDP_TEST_ALIASES.get(token, token)
            if code not in discovered:
                if token not in unknown:
                    unknown.append(token)
                continue
            if code not in seen:
                chosen.append(code)
                seen.add(code)

        if unknown:
            available = list(RDP_TEST_ORDER) + list(RDP_TEST_ALIASES)
            self.ptjsonlib.end_error(
                f"Unknown module(s): {', '.join(unknown)}. "
                f"Available: ALL, {', '.join(available)}",
                self.use_json,
            )
            return self._remember_selection([])
        if "RATELIMIT" in chosen:
            chosen = [code for code in chosen if code != "RATELIMIT"] + [
                "RATELIMIT"
            ]
        return self._remember_selection(chosen)

    def _remember_selection(self, chosen: list[str]) -> list[str]:
        """Expose the full selection to credentialed fallback logic."""
        self.args._rdp_selected_tests = frozenset(chosen)
        return chosen

    def _import_module_file(self, name: str, path: str):
        """Load adapters as package members, matching the current main branch."""
        return importlib.import_module(f"ptsrvtester.protocols.rdp.modules.{name}")

    def _thread_count(self) -> int:
        """RDP modules share caches and a possible authenticated session."""
        return 1

    def build_context(self) -> dict:
        """Expose immutable target details and the one shared engine."""
        return {
            "rdp_engine": self.rdp_engine,
            "host": self.target_host,
            "original_host": self.target_host,
            "ip": self.target[0],
            "port": self.target[1],
        }

    def output(self) -> None:
        """Finalize the single RDP node and JSON result exactly once."""
        self.rdp_engine.output(emit_text=False)


__all__ = ["RDP"]
