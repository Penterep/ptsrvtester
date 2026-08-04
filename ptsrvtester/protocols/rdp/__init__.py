"""RDP server testing package.

``RDP`` and ``RDPArgs`` are loaded lazily.  This keeps the protocol engine
importable while a branch is being rebased onto the generic ``BaseMain``
framework; importing a utility module must not require the protected framework
files to have landed already.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .main import RDP
    from .utils.cli import RDPArgs

__all__ = ["RDP", "RDPArgs"]


def __getattr__(name: str) -> Any:
    if name == "RDP":
        from .main import RDP

        globals()[name] = RDP
        return RDP
    if name == "RDPArgs":
        from .utils.cli import RDPArgs

        globals()[name] = RDPArgs
        return RDPArgs
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
