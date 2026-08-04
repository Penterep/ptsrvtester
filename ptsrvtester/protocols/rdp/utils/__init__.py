"""Shared CLI and protocol-engine support for the RDP package."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .cli import RDPArgs

__all__ = ["RDPArgs"]


def __getattr__(name: str) -> Any:
    if name == "RDPArgs":
        from .cli import RDPArgs

        globals()[name] = RDPArgs
        return RDPArgs
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
