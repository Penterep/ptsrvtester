"""Result types & vulnerability codes shared by the DNS modules.

Collected here so every ``dns/modules/*.py`` imports them from one place via
the absolute path (the modules are loaded dynamically by :class:`BaseMain` and
have no package parent, so relative imports would fail). Mirrors
``ssh/utils/results.py``.

Modules append finding dicts (each carrying at least ``vuln_code``) to
``ctx.deferred_vulns``, guarded by ``ctx.results_lock``. :meth:`DNS.output` then
emits one ``{"vulnCode": ...}`` entry per distinct code (ptlibs de-duplicates),
mirroring ``ssh/main.py`` — no ``software`` node or ``properties`` are written.
There is no ``ctx.properties`` handle: the JSON ``properties`` object stays empty.
"""
from enum import Enum


class VULNS(Enum):
    """Penterep vulnerability codes emitted by the DNS tests."""

    # Recon / fingerprint
    VersionDisclosure = "PTV-SVC-DNS-VERSIONDISCLOSURE"   # software/build leaked via CHAOS TXT
    NsidDisclosure = "PTV-SVC-DNS-NSID"                   # server instance revealed via NSID
    OpenRecursion = "PTV-SVC-DNS-OPENRECURSION"           # recursion offered to arbitrary clients
    KnownCve = "PTV-SVC-DNS-KNOWNCVE"                     # advertised version matches a known CVE

    # Record enumeration
    Subdomains = "PTV-SVC-DNS-SUBDOMAINS"                 # subdomains discovered via brute force
    SpfMissing = "PTV-SVC-DNS-SPFMISSING"                 # no SPF record (email spoofing surface)
    SpfWeak = "PTV-SVC-DNS-SPFWEAK"                       # SPF present but +all / no fail policy
    DmarcMissing = "PTV-SVC-DNS-DMARCMISSING"             # no DMARC record
    DmarcWeak = "PTV-SVC-DNS-DMARCWEAK"                   # DMARC policy p=none (monitoring only)
    CaaMissing = "PTV-SVC-DNS-CAAMISSING"                 # no CAA record (any CA may issue)
    Wildcard = "PTV-SVC-DNS-WILDCARD"                     # wildcard record (masks enumeration)

    # Zone transfer
    ZoneTransfer = "PTV-SVC-DNS-ZONETRANSFER"             # AXFR allowed (full zone leak)
    IncrementalTransfer = "PTV-SVC-DNS-IXFR"              # IXFR allowed (zone leak via increments)

    # Recursion & resolver abuse
    # (OpenRecursion, above, is emitted here by the RECURSION module)
    Amplification = "PTV-SVC-DNS-AMPLIFICATION"           # out-of-zone recursion usable for reflection/amplification
    CacheSnoop = "PTV-SVC-DNS-CACHESNOOP"                 # non-recursive RD=0 reveals cache contents

    # Cache-poisoning / spoofing resilience
    # (source-port / TXID / 0x20 / out-of-bailiwick need an authoritative probe
    #  server to measure — deferred to a future implementation)
    NoCookie = "PTV-SVC-DNS-NOCOOKIE"                     # no DNS cookies (weaker off-path spoofing protection)

    # DNSSEC (KeyTrap CVE-2023-50387 is version-covered by KnownCve; an active
    #  test needs an authoritative probe server — deferred)
    DnssecMissing = "PTV-SVC-DNS-NODNSSEC"                # zone not DNSSEC-signed
    DnssecInvalid = "PTV-SVC-DNS-DNSSECINVALID"           # signed but signatures do not validate
    WeakDnssecAlg = "PTV-SVC-DNS-WEAKDNSSECALG"           # deprecated algorithm (RSA/MD5, DSA, SHA-1)
    RrsigExpired = "PTV-SVC-DNS-RRSIGEXPIRED"             # an RRSIG has already expired
    RrsigExpiring = "PTV-SVC-DNS-RRSIGEXPIRING"           # an RRSIG expires soon
    DnssecChain = "PTV-SVC-DNS-DNSSECCHAIN"               # DS (parent) ↔ DNSKEY (child) chain broken
    NsecWalk = "PTV-SVC-DNS-NSECWALK"                     # NSEC in use (zone walking possible)
    Nsec3Params = "PTV-SVC-DNS-NSEC3PARAMS"               # NSEC3 with non-zero iterations / salt (RFC 9276)

    # Zone walking
    ZoneWalk = "PTV-SVC-DNS-ZONEWALK"                     # subdomains enumerated via NSEC/NSEC3 walking
    Nsec3Cracked = "PTV-SVC-DNS-NSEC3CRACK"               # NSEC3 hashes cracked offline (names revealed)

    # Amplification / DoS (water-torture flood and NXNSAttack need a probe server
    #  — deferred; NXNSAttack is version-covered by KnownCve)
    AmpFactor = "PTV-SVC-DNS-AMPFACTOR"                   # high response/query amplification factor
    NoRrl = "PTV-SVC-DNS-NORRL"                           # no Response Rate Limiting observed
    TcpFallback = "PTV-SVC-DNS-TCPFALLBACK"               # TCP fallback broken (TCP/53 not answering)

    # Dynamic update (RFC 2136)
    DynUpdate = "PTV-SVC-DNS-DYNUPDATE"                   # unauthenticated dynamic update accepted (record injection)
    TsigAcl = "PTV-SVC-DNS-TSIGACL"                       # TSIG key not ACL-restricted (can write arbitrary names)

    # Encrypted transport (DoT / DoH / DoQ)
    WeakTls = "PTV-SVC-DNS-WEAKTLS"                        # encrypted transport negotiates weak TLS (< 1.2)
    TlsCert = "PTV-SVC-DNS-TLSCERT"                        # invalid TLS certificate (untrusted / expired / name mismatch)

    # Integrity / delegation / takeover
    Takeover = "PTV-SVC-DNS-TAKEOVER"                      # record points to a dangling/unclaimed cloud resource
    LameDelegation = "PTV-SVC-DNS-LAMEDELEGATION"          # NS not authoritative for the zone
    CnameChain = "PTV-SVC-DNS-CNAMECHAIN"                  # excessive or looping CNAME chain
    NsInconsistent = "PTV-SVC-DNS-NSINCONSISTENT"          # name servers disagree on SOA serial / NS set
