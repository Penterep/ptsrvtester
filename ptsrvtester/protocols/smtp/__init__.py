"""SMTP server testing module.

Provides the ``SMTP`` test runner and its ``SMTPArgs`` CLI definition.
Tests are organized into groups (recon, protocol, auth, relay, delivery,
content, stress, …) selectable via the ``-ts`` switch.
"""
from .main import SMTP
from .utils.cli import SMTPArgs

__all__ = ["SMTP", "SMTPArgs"]
