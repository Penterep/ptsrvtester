"""TEMPLATE for a protocol main — copy this to protocols/SNMP/SNMP_main.py.

The generic machinery (module discovery, ``-ts`` selection, parallel execution,
ordered output, the ``ctx`` object) lives in :class:`BaseMain` (protocols/_base.py)
and is inherited unchanged. A protocol main declares only the five items below.

Steps to stand up a new protocol ``SNMP``:
  1. Create ``protocols/SNMP/`` with an ``__init__.py`` exporting the class.
  2. Put the CLI/args class in ``protocols/SNMP/SNMP_utils/cli.py`` (``SNMPArgs``).
  3. Copy this file to ``protocols/SNMP/SNMP_main.py`` and fill in the class below.
  4. Add tests as ``protocols/SNMP/tests/*.py`` (see protocols/smtp/tests/_TEMPLATE.py).
  5. Register the protocol in ``ptsrvtester.py`` MODULES: one line
     ``"SNMP": ("ptsrvtester.protocols.SNMP:SNMP", "SNMP testing module")``.
"""
import argparse
import socket

from .._base import BaseMain, BaseArgs
from .utils.cli import SNMPArgs


class SNMP(BaseMain):  # rename to your protocol class, e.g. class SMB(BaseMain)
    #: Short protocol identity (also namespaces this protocol's tests).
    NAME = "snmp"
    #: The argparse namespace class for this protocol's options.
    ARGS_CLASS = SNMPArgs  # -> SNMPArgs

    @staticmethod
    def module_args() -> BaseArgs:
        # return SNMPArgs()
        return SNMPArgs()

    def _prepare_target(self) -> None:
        """Resolve self.target = (ip, port) before any module runs.

        Fill in protocol defaults (e.g. default port) and host resolution.
        If you don't override this, BaseMain's default takes (ip, port) straight
        from args.target.
        """
        target = self.args.target
        if getattr(target, "port", 0) == 0:
            target.port = 161  # <- set your protocol's default port here
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
            "single_community": getattr(self.args, "single_community", None),
            "community_file": getattr(self.args, "community_file", None),
            "write_to_file": getattr(self.args, "output", None),
            "oid": getattr(self.args, "oid", None),
            "oid_format": getattr(self.args, "oid_format", None),
            "auth_protocols": getattr(self.args, "auth_protocols", None),
            "priv_protocols": getattr(self.args, "priv_protocols", None),
            "single_username": getattr(self.args, "single_username", None),
            "single_password": getattr(self.args, "single_password", None),
            "password_file": getattr(self.args, "password_file", None),
            "username_file": getattr(self.args, "username_file", None),
            "valid_credentials_file": getattr(self.args, "valid_credentials_file", None),
            "value": getattr(self.args, "valid_credentials_file", None),
            "spray": getattr(self.args, "spray", None)
        }
