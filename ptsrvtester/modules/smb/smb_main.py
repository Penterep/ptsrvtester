import argparse
import importlib.util
import os
import socket
import sys
import threading

from ptlibs.threads import ptthreads, printlock
from ptlibs.ptprinthelper import out_if
from ptsrvtester.modules._base import BaseModule, BaseArgs
from ptsrvtester.modules.utils.helpers import (
    valid_target,
    Target
)

from .utils.cli import SMBArgs

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))


class TestContext:
    """Everything a test's ``run(ctx)`` receives.

    The core fields are protocol-agnostic; ``build_context()`` adds
    protocol-specific handles onto the same object as plain attributes.
    """

    def __init__(self, *, args, ptjsonlib, target, print_lock):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.target = target                       # (ip, port)
        self.print_lock = print_lock
        self.json = bool(getattr(args, "json", False))
        self.verbose = bool(getattr(args, "debug", False))

    def out(self, string="", category="TEXT", *, colortext=False, indent=0, condition=None):
        """Buffer one formatted line (printed by the main after the test finishes).

        Suppressed in JSON mode unless ``condition`` is given explicitly.
        """
        cond = (not self.json) if condition is None else condition
        self.print_lock.add_string_to_output(
            out_if(string, category, cond, colortext=colortext, indent=indent)
        )

    def debug(self, string="", *, indent=4):
        """Buffer a verbose-only line (``-vv``); suppressed in JSON mode."""
        if self.verbose and not self.json:
            self.print_lock.add_string_to_output(
                out_if(string, "ADDITIONS", True, colortext=True, indent=indent)
            )


class _DiscoveredTest:
    """A test module found in ./tests/ plus its resolved metadata."""

    def __init__(self, code: str, label: str, order: int, module):
        self.code = code
        self.label = label
        self.order = order
        self.module = module


class SMB(BaseModule):
    # =====================================================================
    # GENERIC MAIN — protocol-agnostic; copy verbatim into <proto>_main.py.
    # =====================================================================

    #: Sub-directory (next to this file) that holds the test modules.
    TESTS_DIRNAME = "tests"

    def __init__(self, args: BaseArgs, ptjsonlib) -> None:
        if not isinstance(args, self.ARGS_CLASS):
            raise argparse.ArgumentError(
                None, f'module "{getattr(args, "module", "?")}" received wrong arguments namespace'
            )
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.use_json = bool(getattr(args, "json", False))
        self.ptthreads = ptthreads.PtThreads()
        self._lock = threading.Lock()
        self._outputs: dict[str, str] = {}
        # PROTOCOL-SPECIFIC: resolve target host/port before any test runs.
        self._prepare_target()

    # ---- discovery ------------------------------------------------------

    def _discover_tests(self) -> dict[str, _DiscoveredTest]:
        """Import every ``tests/*.py`` (not ``_``-prefixed) exposing ``run``.

        Files that fail to import or lack a callable ``run`` are skipped (they
        are not tests yet); a note is buffered only in verbose mode.
        """
        tests_dir = os.path.join(_THIS_DIR, self.TESTS_DIRNAME)
        discovered: dict[str, _DiscoveredTest] = {}
        skipped: list[str] = []
        for fname in sorted(os.listdir(tests_dir)):
            if not fname.endswith(".py") or fname.startswith("_"):
                continue
            name = fname[:-3]
            path = os.path.join(tests_dir, fname)
            try:
                module = self._import_test_file(name, path)
            except Exception as e:
                skipped.append(f"{name} ({e})")
                continue
            run_fn = getattr(module, "run", None)
            if not callable(run_fn):
                skipped.append(f"{name} (no run())")
                continue
            code = str(getattr(module, "__TESTCODE__", name.upper())).upper()
            label = str(getattr(module, "__TESTLABEL__", f"{code} test"))
            order = int(getattr(module, "__ORDER__", 100))
            discovered[code] = _DiscoveredTest(code, label, order, module)

        if skipped and getattr(self.args, "debug", False) and not self.use_json:
            sys.stdout.write("[skipped non-test files: " + ", ".join(skipped) + "]\n")
        return discovered

    @staticmethod
    def _import_test_file(name: str, path: str):
        mod_name = f"_ptsrv_smb_test_{name}"
        spec = importlib.util.spec_from_file_location(mod_name, path)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load spec for {path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[mod_name] = module
        spec.loader.exec_module(module)
        return module

    def _select_codes(self, discovered: dict[str, _DiscoveredTest]) -> list[str]:
        """Resolve ``-ts`` into an ordered list of test codes.

        Empty / ``ALL`` -> every discovered test. Ordered by ``__ORDER__`` then code.
        """
        raw = getattr(self.args, "tests", None)
        codes = [c.strip().upper() for c in raw.split(",")] if raw else []
        codes = [c for c in codes if c]
        if not codes or "ALL" in codes:
            chosen = list(discovered.keys())
        else:
            unknown = [c for c in codes if c not in discovered]
            if unknown:
                available = ", ".join(sorted(discovered)) or "(none)"
                self.ptjsonlib.end_error(
                    f"Unknown test(s): {', '.join(unknown)}. Available: ALL, {available}",
                    self.use_json,
                )
                return []
            chosen = [c for c in codes if c in discovered]
        chosen.sort(key=lambda c: (discovered[c].order, c))
        return chosen

    # ---- execution ------------------------------------------------------

    def run(self) -> None:
        discovered = self._discover_tests()
        if not discovered:
            self.ptjsonlib.end_error(
                f"No runnable tests found in {self.TESTS_DIRNAME}/", self.use_json
            )
            return

        selected = self._select_codes(discovered)
        if not selected:
            return

        extras = self.build_context()
        self._outputs = {}
        # PtThreads.threads() consumes (mutates) the list it is given, so hand it
        # a copy and keep `selected` intact for the ordered flush below.
        self.ptthreads.threads(
            list(selected),
            lambda test_code: self._run_test(test_code, discovered, extras),
            self._thread_count(),
        )

        # Flush per-test buffers back in the selected (deterministic) order.
        for code in selected:
            chunk = self._outputs.get(code, "")
            if chunk:
                sys.stdout.write(chunk)
                sys.stdout.flush()

    def _run_test(self, code: str, discovered: dict[str, _DiscoveredTest], extras: dict) -> None:
        test = discovered[code]
        lock = printlock.PrintLock()
        ctx = self._make_context(lock, extras)
        # The main owns the standardized section header so each test does not.
        ctx.out(test.label, "INFO", colortext=True)
        try:
            test.module.run(ctx)
        except Exception as e:  # one failing test must not abort the rest
            ctx.out(f"Error in test {code}: {e}", "ERROR")
        with self._lock:
            self._outputs[code] = lock.get_output_string()

    def _make_context(self, print_lock, extras: dict) -> TestContext:
        ctx = TestContext(
            args=self.args,
            ptjsonlib=self.ptjsonlib,
            target=self.target,
            print_lock=print_lock,
        )
        for key, value in extras.items():
            setattr(ctx, key, value)
        return ctx

    def _thread_count(self) -> int:
        return max(1, int(getattr(self.args, "test_threads", 1) or 1))

    def output(self) -> None:
        self.ptjsonlib.set_status("finished")
        if self.use_json:
            print(self.ptjsonlib.get_result_json())

    # =====================================================================
    # PROTOCOL-SPECIFIC — the only block that changes per protocol.
    # =====================================================================

    NAME = "smb"
    ARGS_CLASS = SMBArgs

    @staticmethod
    def module_args() -> BaseArgs:
        return SMBArgs()

    def _prepare_target(self) -> None:
        """Fill the default port and resolve the host to an IP for the tests."""
        target = self.args.target
        if getattr(target, "port", 0) == 0:
            target.port = 445

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
        """Protocol handles injected onto every test's ``ctx`` (besides the core fields).

        This is the main place a protocol owner customises. Extend it with
        whatever the protocol's tests need (a connection factory, EHLO FQDN,
        credentials, …); tests read them as ``ctx.<name>``.
        """
        return {
            "host": self.target_host,
            "ip": self.target[0],
            "port": self.target[1],
            # "fqdn": getattr(self.args, "fqdn", None) or "example.com",
            # "tls": bool(getattr(self.args, "tls", False)),
            # "starttls": bool(getattr(self.args, "starttls", False)),
        }