"""UPnP/SSDP device discovery and description module."""

from .main import UPnP
from .utils.cli import UPnPArgs

__all__ = ["UPnP", "UPnPArgs"]
