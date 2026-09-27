"""TEMPLATE for a protocol main — copy this to protocols/<proto>/<proto>_main.py.

The generic machinery (module discovery, ``-ts`` selection, parallel execution,
ordered output, the ``ctx`` object) lives in :class:`BaseMain` (protocols/_base.py)
and is inherited unchanged. A protocol main declares only the five items below.

Steps to stand up a new protocol ``<proto>``:
  1. Create ``protocols/<proto>/`` with an ``__init__.py`` exporting the class.
  2. Put the CLI/args class in ``protocols/<proto>/<proto>_utils/cli.py`` (``<Proto>Args``).
  3. Copy this file to ``protocols/<proto>/<proto>_main.py`` and fill in the class below.
  4. Add modules as ``protocols/<proto>/modules/*.py`` (see protocols/smtp/modules/_TEMPLATE.py).
  5. Register the protocol in ``ptsrvtester.py`` MODULES: one line
     ``"<proto>": ("ptsrvtester.protocols.<proto>:<Proto>", "<Proto> testing module")``.
"""

import argparse
import importlib
import socket

from .._base import BaseMain, BaseArgs
from .smb_utils.cli import SMBArgs

from impacket.smbconnection import (
    SMB_DIALECT,
    SMB2_DIALECT_002,
    SMB2_DIALECT_21,
    SMB2_DIALECT_30,
    SMB2_DIALECT_311,
)


class SMB(BaseMain):
    NAME = "SMB"
    ARGS_CLASS = SMBArgs

    @staticmethod
    def module_args() -> BaseArgs:
        return SMBArgs()
        raise NotImplementedError

    def _import_module_file(self, name: str, path: str):
        """Import as a real package member so ``from ..smb_utils`` works in modules.

        BaseMain's file-location loader sets no ``__package__``, which breaks
        relative imports; POP3 and RDP override this the same way.
        """
        return importlib.import_module(f"ptsrvtester.protocols.smb.modules.{name}")

    def _prepare_target(self) -> None:
        """Resolve self.target = (ip, port) before any module runs.

        Fill in protocol defaults (e.g. default port) and host resolution.
        If you don't override this, BaseMain's default takes (ip, port) straight
        from args.target.
        """
        target = self.args.target
        if getattr(target, "port", 0) == 0:
            target.port = 445  # default SMB port

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
            # "ip": self.target[0],
            # "port": self.target[1],
            "mapping": {  # bool represents if dialect has been tried
                SMB_DIALECT:        False,
                SMB2_DIALECT_002:   False,
                SMB2_DIALECT_21:    False,
                SMB2_DIALECT_30:    False,
                SMB2_DIALECT_311:   False,
            },
            "server_name": "",
            "os_version": "",
            "dns_domain_name": "",
            "dns_host_name": "",
            "ntlmv2_support": None,
            "login_required": None,
            "signing_required": None,
            "successful_dialects": [],
            "v30_encryption": "",
            "v311_encryption": "",
            "error": None
        }