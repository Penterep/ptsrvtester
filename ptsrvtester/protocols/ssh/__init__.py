"""SSH server testing module.

Provides the ``SSH`` test runner and its ``SSHArgs`` CLI definition. Tests are
organized one-per-file under ``modules/`` and selected via ``-ts`` (BANNER,
HOSTKEY, AUTHM, AUDIT, BADHOSTKEY, BADAUTHKEY, BRUTE).
"""
from .main import SSH
from ptsrvtester.protocols.ssh.utils.cli import SSHArgs

__all__ = ["SSH", "SSHArgs"]