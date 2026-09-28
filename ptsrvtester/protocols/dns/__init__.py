"""DNS server testing module.

Provides the ``DNS`` test runner and its ``DNSArgs`` CLI definition. Tests are
organized one-per-file under ``modules/`` and selected via ``-ts`` (each
module's ``__MODULECODE__``); RATELIMIT is provided by the shared modules.

This is a clean SSH-style skeleton with no DNS modules defined yet: the
architecture is wired up (discovery, ``-ts`` selection, ordered parallel
execution, one shared ``software`` node), ready for new modules to be dropped
into ``modules/`` and registered in ``utils/registry.py``.
"""
from .main import DNS
from .utils.cli import DNSArgs

__all__ = ["DNS", "DNSArgs"]
