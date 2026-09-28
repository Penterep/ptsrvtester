"""Result types & vulnerability codes shared by the DNS modules.

Collected here so every ``dns/modules/*.py`` imports them from one place via
the absolute path (the modules are loaded dynamically by :class:`BaseMain` and
have no package parent, so relative imports would fail). Mirrors
``ssh/utils/results.py``.

Modules accumulate findings onto the shared ``ctx.properties`` dict and append
finding dicts to ``ctx.deferred_vulns`` (both guarded by ``ctx.results_lock``);
:meth:`DNS.output` then binds them all to a single ``software`` node.
"""
from enum import Enum


class VULNS(Enum):
    """Penterep vulnerability codes emitted by the DNS tests."""

    # Recon / fingerprint
    VersionDisclosure = "PTV-DNS-VERSIONDISCLOSURE"   # software/build leaked via CHAOS TXT
    NsidDisclosure = "PTV-DNS-NSID"                   # server instance revealed via NSID
    OpenRecursion = "PTV-DNS-OPENRECURSION"           # recursion offered to arbitrary clients
    KnownCve = "PTV-DNS-KNOWNCVE"                     # advertised version matches a known CVE
