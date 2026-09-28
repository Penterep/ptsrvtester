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

    # Record enumeration
    Subdomains = "PTV-DNS-SUBDOMAINS"                 # subdomains discovered via brute force
    SpfMissing = "PTV-DNS-SPFMISSING"                 # no SPF record (email spoofing surface)
    SpfWeak = "PTV-DNS-SPFWEAK"                       # SPF present but +all / no fail policy
    DmarcMissing = "PTV-DNS-DMARCMISSING"             # no DMARC record
    DmarcWeak = "PTV-DNS-DMARCWEAK"                   # DMARC policy p=none (monitoring only)
    CaaMissing = "PTV-DNS-CAAMISSING"                 # no CAA record (any CA may issue)
    Wildcard = "PTV-DNS-WILDCARD"                     # wildcard record (masks enumeration)

    # Zone transfer
    ZoneTransfer = "PTV-DNS-ZONETRANSFER"             # AXFR allowed (full zone leak)
    IncrementalTransfer = "PTV-DNS-IXFR"              # IXFR allowed (zone leak via increments)

    # Recursion & resolver abuse
    # (OpenRecursion, above, is emitted here by the RECURSION module)
    Amplification = "PTV-DNS-AMPLIFICATION"           # out-of-zone recursion usable for reflection/amplification
    CacheSnoop = "PTV-DNS-CACHESNOOP"                 # non-recursive RD=0 reveals cache contents

    # Cache-poisoning / spoofing resilience
    # (source-port / TXID / 0x20 / out-of-bailiwick need an authoritative probe
    #  server to measure — deferred to a future implementation)
    NoCookie = "PTV-DNS-NOCOOKIE"                     # no DNS cookies (weaker off-path spoofing protection)

    # DNSSEC (KeyTrap CVE-2023-50387 is version-covered by KnownCve; an active
    #  test needs an authoritative probe server — deferred)
    DnssecMissing = "PTV-DNS-NODNSSEC"                # zone not DNSSEC-signed
    DnssecInvalid = "PTV-DNS-DNSSECINVALID"           # signed but signatures do not validate
    WeakDnssecAlg = "PTV-DNS-WEAKDNSSECALG"           # deprecated algorithm (RSA/MD5, DSA, SHA-1)
    RrsigExpired = "PTV-DNS-RRSIGEXPIRED"             # an RRSIG has already expired
    RrsigExpiring = "PTV-DNS-RRSIGEXPIRING"           # an RRSIG expires soon
    DnssecChain = "PTV-DNS-DNSSECCHAIN"               # DS (parent) ↔ DNSKEY (child) chain broken
    NsecWalk = "PTV-DNS-NSECWALK"                     # NSEC in use (zone walking possible)
    Nsec3Params = "PTV-DNS-NSEC3PARAMS"               # NSEC3 with non-zero iterations / salt (RFC 9276)

    # Zone walking
    ZoneWalk = "PTV-DNS-ZONEWALK"                     # subdomains enumerated via NSEC/NSEC3 walking
    Nsec3Cracked = "PTV-DNS-NSEC3CRACK"               # NSEC3 hashes cracked offline (names revealed)

    # Amplification / DoS (water-torture flood and NXNSAttack need a probe server
    #  — deferred; NXNSAttack is version-covered by KnownCve)
    AmpFactor = "PTV-DNS-AMPFACTOR"                   # high response/query amplification factor
    NoRrl = "PTV-DNS-NORRL"                           # no Response Rate Limiting observed
    TcpFallback = "PTV-DNS-TCPFALLBACK"               # TCP fallback broken (TCP/53 not answering)

    # Dynamic update (RFC 2136)
    DynUpdate = "PTV-DNS-DYNUPDATE"                   # unauthenticated dynamic update accepted (record injection)
    TsigAcl = "PTV-DNS-TSIGACL"                       # TSIG key not ACL-restricted (can write arbitrary names)
