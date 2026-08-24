"""IMAP testing module (plugin architecture)."""
from .main import IMAP
from .utils.cli import IMAPArgs

__all__ = ["IMAP", "IMAPArgs"]
