"""TEMPLATE for a protocol main — copy this to protocols/<proto>/<proto>_main.py.

The generic machinery (module discovery, ``-ts`` selection, parallel execution,
ordered output, the ``ctx`` object) lives in :class:`BaseMain` (protocols/_base.py)
and is inherited unchanged. A protocol main declares only the five items below.

Steps to stand up a new protocol ``<proto>``:
  1. Create ``protocols/<proto>/`` with an ``__init__.py`` exporting the class.
  2. Put the CLI/args class in ``protocols/<proto>/<proto>_utils/cli.py`` (``<Proto>Args``).
  3. Copy this file to ``protocols/<proto><proto>/<proto>_main.py`` and fill in the class below.
  4. Add modules as ``protocols/<proto>/modules/*.py`` (see protocols/smtp/modules/_TEMPLATE.py).
  5. Register the protocol in ``ptsrvtester.py`` MODULES: one line
     ``"<proto>": ("ptsrvtester.protocols.<proto>:<Proto>", "<Proto> testing module")``.
"""
import argparse
import socket

from .._base import BaseMain, BaseArgs
from .ntp_utils.cli import NTPArgs


class NTP(BaseMain):  # rename to your protocol class, e.g. class SMB(BaseMain)
    #: Short protocol identity (also namespaces this protocol's modules).
    NAME = "NTP"
    #: The argparse namespace class for this protocol's options.
    ARGS_CLASS = NTPArgs  # -> <Proto>Args

    @staticmethod
    def module_args() -> BaseArgs:
        return NTPArgs()
        raise NotImplementedError

    def _prepare_target(self) -> None:
        """Resolve self.target = (ip, port) before any module runs.

        Fill in protocol defaults (e.g. default port) and host resolution.
        If you don't override this, BaseMain's default takes (ip, port) straight
        from args.target.
        """
        target = self.args.target
        if getattr(target, "port", 0) == 0:
            target.port = 123
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
        return {
            "host": self.target_host,
            "ip": self.target[0],
            "port": self.target[1],
            "error": False
        }
