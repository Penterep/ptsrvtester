"""SMTP server testing module.

Provides the ``SMTP`` test runner and its ``SMTPArgs`` CLI definition.
Tests are organized into groups (recon, protocol, auth, relay, delivery,
content, stress, …) selectable via the ``-ts`` switch.
"""
from .core import SMTP
from .cli import SMTPArgs

__all__ = ["SMTP", "SMTPArgs"]
