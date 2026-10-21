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
    user: str | None = None
    password: str | None = None

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

    def build_context(self) -> dict:
        """Protocol handles injected onto every module's ``ctx`` (besides core fields).

        Modules read them as ``ctx.<name>``. Return {} if none are needed.
        """
        tests = getattr(self.args, "tests", None)
        test_codes = {code.strip().upper() for code in tests.split(",")} if tests else set()
        needs_modules = (
            not test_codes
            or "ALL" in test_codes
            or bool(test_codes & {"GRAB_MODULES", "MODULE_AUTH", "WRITE", "OWNERSHIP", "SYMLINK"})
            or ("FILL_SPACE" in test_codes and getattr(self.args, "dos", False))
        )
        modules = getattr(self.args, "modules", None)
        if modules is None:
            modules = []
            if needs_modules:
                tmp_ctx = TmpCtx(
                                        self.target[0],
                                        self.target[1],
                                        getattr(self.args, "timeout", None),
                                        getattr(self.args, "user", None),
                                        getattr(self.args, "password", None),
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
            "rsync_path": check_rsync_path(),
            "recursion": getattr(self.args, "recursion", False),
            "user": getattr(self.args, "user", None),
            "password": getattr(self.args, "password", None),
            "dos": getattr(self.args, "dos", False),
            "dos_limit": getattr(self.args, "dos_limit", 10),
            "supported_digests": [],
        }
