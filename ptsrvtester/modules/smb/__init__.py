"""SMB server testing module.

Provides the ``SMB`` test runner and its ``SMBArgs`` CLI definition.
Tests are organized into groups (recon, protocol, auth, relay, delivery,
content, stress, …) selectable via the ``-ts`` switch.
"""
from .main import SMB
from .smb_utils.cli import SMBArgs

__all__ = ["SMB", "SMBArgs"]
