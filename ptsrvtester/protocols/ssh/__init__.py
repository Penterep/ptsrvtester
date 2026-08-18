"""SSH server testing module.

Provides the ``SSH`` test runner and its ``SSHArgs`` CLI definition. Tests are
organized one-per-file under ``modules/`` and selected via ``-ts`` (BANNER,
HOSTKEY, AUTHM, KEX, KEYALG, ENC, MAC, FINGERPRINT, BADHOSTKEY, BADAUTHKEY,
BRUTE, DHEAT). The crypto section tests (KEX/KEYALG/ENC/MAC/FINGERPRINT) share a
single ssh-audit scan; DHEAT is an aggressive, opt-in DoS test with its own run.
"""
from .main import SSH
from ptsrvtester.protocols.ssh.utils.cli import SSHArgs

__all__ = ["SSH", "SSHArgs"]