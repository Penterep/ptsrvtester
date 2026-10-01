"""TEMPLATE for a protocol main — copy this to protocols/Rsync/Rsync_main.py.

The generic machinery (module discovery, ``-ts`` selection, parallel execution,
ordered output, the ``ctx`` object) lives in :class:`BaseMain` (protocols/_base.py)
and is inherited unchanged. A protocol main declares only the five items below.

Steps to stand up a new protocol ``Rsync``:
  1. Create ``protocols/Rsync/`` with an ``__init__.py`` exporting the class.
  2. Put the CLI/args class in ``protocols/Rsync/Rsync_utils/cli.py`` (``RsyncArgs``).
  3. Copy this file to ``protocols/Rsync/Rsync_main.py`` and fill in the class below.
  4. Add tests as ``protocols/Rsync/tests/*.py`` (see protocols/smtp/tests/_TEMPLATE.py).
  5. Register the protocol in ``ptsrvtester.py`` MODULES: one line
     ``"Rsync": ("ptsrvtester.protocols.Rsync:Rsync", "Rsync testing module")``.
"""
import argparse, socket

from .._base import BaseMain, BaseArgs
from .utils.cli import RsyncArgs
from ptsrvtester.protocols.rsync.utils.registry import check_rsync_path
from ptsrvtester.protocols.rsync.modules.grab_modules import rsync_grab_modules 
from dataclasses import dataclass
import sys
from ptlibs.threads import printlock
from ptlibs.ptprinthelper import out_if

@dataclass
class TmpCtx:
    ip: str
    port: int
    timeout: int

class Rsync(BaseMain):  # rename to your protocol class, e.g. class SMB(BaseMain)
    #: Short protocol identity (also namespaces this protocol's tests).
    NAME = "rsync"
    #: The argparse namespace class for this protocol's options.
    ARGS_CLASS = RsyncArgs  # -> RsyncArgs

    @staticmethod
    def module_args() -> BaseArgs:
        # return RsyncArsg()
        return RsyncArgs()

    def _prepare_target(self) -> None:
        """Resolve self.target = (ip, port) before any module runs.

        Fill in protocol defaults (e.g. default port) and host resolution.
        If you don't override this, BaseMain's default takes (ip, port) straight
        from args.target.
        """
        target = self.args.target
        if getattr(target, "port", 0) == 0:
            target.port = 873  # <- set your protocol's default port here
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

    
    def _run_module(self, code: str, discovered, extras: dict) -> None:
        """Heading now; ``-vv`` live; verdicts when the test finishes."""
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
    
    def build_context(self) -> dict:
        """Protocol handles injected onto every module's ``ctx`` (besides core fields).

        Modules read them as ``ctx.<name>``. Return {} if none are needed.
        """
        tests = getattr(self.args, "tests", None)
        test_codes = {code.strip().upper() for code in tests.split(",")} if tests else set()
        needs_modules = not test_codes or "ALL" in test_codes or bool(
            test_codes & {"GRAB_MODULES", "MODULE_AUTH", "WRITE"}
        )
        modules = getattr(self.args, "modules", None)
        if modules is None:
            modules = []
            if needs_modules:
                tmp_ctx = TmpCtx(
                                        self.target[0],
                                        self.target[1],
                                        getattr(self.args, "timeout", None)
                                    )
                modules = rsync_grab_modules(
                    tmp_ctx,
                    printer=False
                ) or rsync_grab_modules(tmp_ctx, printer=False, include_motd=True) or []
        
        return {
            "host": self.target_host,
            "ip": self.target[0],
            "port": self.target[1],
            "timeout": getattr(self.args, "timeout", None),
            "modules": modules,
            "rsync_path": check_rsync_path()
        }
