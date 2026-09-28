"""Recon / fingerprint probe logic for the DNS modules.

Pure, side-effect-free query helpers (no printing, no ctx) so the thin
``dns/modules/*.py`` recon modules just call one function and format the result.
Mirrors the ``ssh/utils/*_core.py`` split. Everything here talks to ONE target
DNS server (``-tg`` → ``ctx.ip`` / ``ctx.port``).
"""
from __future__ import annotations

import os
import re
import socket
from dataclasses import dataclass

import dns.edns
import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype

# CHAOS-class TXT names that leak build/identity information.
CHAOS_NAMES: tuple[str, ...] = ("version.bind", "hostname.bind", "id.server", "authors.bind")

DEFAULT_TIMEOUT = 5.0
TRANSPORT_TIMEOUT = 4.0


def server_target(ctx) -> tuple[str, int] | None:
    """The ``(ip, port)`` of the target DNS server, or ``None`` when no ``-tg`` was given."""
    ip = getattr(ctx, "ip", None)
    port = getattr(ctx, "port", None) or 53
    return (ip, port) if ip else None


# --------------------------------------------------------------------------- #
# CHAOS TXT: version.bind / hostname.bind / id.server / authors.bind
# --------------------------------------------------------------------------- #
def _txt_values(response) -> list[str]:
    out: list[str] = []
    for rrset in response.answer:
        if rrset.rdtype == dns.rdatatype.TXT:
            for item in rrset.items:
                out.append(item.to_text().strip('"'))
    return out


def chaos_txt(ip: str, port: int, name: str, timeout: float = DEFAULT_TIMEOUT) -> list[str] | None:
    """Query one CHAOS-class TXT record. Returns the value(s), ``[]`` if refused, ``None`` on error."""
    query = dns.message.make_query(name, dns.rdatatype.TXT, rdclass=dns.rdataclass.CH)
    try:
        response = dns.query.udp(query, ip, port=port, timeout=timeout)
    except Exception:
        try:
            response = dns.query.tcp(query, ip, port=port, timeout=timeout)
        except Exception:
            return None
    return _txt_values(response)


def collect_chaos(ip: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> dict[str, list[str] | None]:
    """Query every :data:`CHAOS_NAMES` record. Maps name -> value list (empty if refused) / None."""
    return {name: chaos_txt(ip, port, name, timeout) for name in CHAOS_NAMES}


# --------------------------------------------------------------------------- #
# NSID (server-instance identification, EDNS option 3)
# --------------------------------------------------------------------------- #
def nsid(ip: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> bytes | None:
    """Ask for the EDNS NSID option and return the raw server NSID bytes, or ``None``."""
    query = dns.message.make_query(".", dns.rdatatype.NS)
    query.use_edns(0, payload=4096, options=[dns.edns.GenericOption(dns.edns.OptionType.NSID, b"")])
    try:
        response = dns.query.udp(query, ip, port=port, timeout=timeout)
    except Exception:
        return None
    for opt in response.options:
        if int(opt.otype) == int(dns.edns.OptionType.NSID):
            value = getattr(opt, "nsid", None)
            if value is not None:
                return value
            text = opt.to_text()
            return text[5:].encode() if text.upper().startswith("NSID ") else text.encode()
    return None


def nsid_display(raw: bytes) -> tuple[str, str]:
    """Return ``(ascii_or_placeholder, hex)`` for an NSID byte string."""
    try:
        ascii_val = raw.decode("ascii") if raw.decode("ascii", "ignore").isprintable() else raw.decode("ascii", "replace")
    except Exception:
        ascii_val = "(non-printable)"
    return ascii_val, raw.hex()


# --------------------------------------------------------------------------- #
# EDNS(0): support, advertised UDP payload, DNS cookies (RFC 7873)
# --------------------------------------------------------------------------- #
@dataclass
class EdnsInfo:
    supported: bool = False
    version: int | None = None
    udp_payload: int | None = None
    cookie: bool = False
    error: str | None = None


def edns_probe(ip: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> EdnsInfo:
    """Probe EDNS(0): send a client cookie + large payload, read the server's OPT back."""
    query = dns.message.make_query(".", dns.rdatatype.NS)
    query.use_edns(
        0,
        payload=4096,
        options=[dns.edns.GenericOption(dns.edns.OptionType.COOKIE, os.urandom(8))],
    )
    try:
        response = dns.query.udp(query, ip, port=port, timeout=timeout)
    except Exception as e:
        return EdnsInfo(error=f"{type(e).__name__}: {e}")

    if response.edns < 0:
        return EdnsInfo(supported=False)

    cookie = any(int(o.otype) == int(dns.edns.OptionType.COOKIE) for o in response.options)
    return EdnsInfo(
        supported=True,
        version=response.edns,
        udp_payload=response.payload,
        cookie=cookie,
    )


# --------------------------------------------------------------------------- #
# Transports: UDP/53, TCP/53, DoT/853, DoH/443, DoQ/853
# --------------------------------------------------------------------------- #
# state: True = works, False = not available (refused/timeout), None = not tested
@dataclass
class TransportResult:
    state: bool | None
    detail: str = ""


def _probe_query():
    return dns.message.make_query("example.com", dns.rdatatype.A)


def _try(fn) -> TransportResult:
    try:
        fn()
        return TransportResult(True, "responded")
    except (ConnectionRefusedError, socket.timeout, TimeoutError, OSError, dns.exception.Timeout) as e:
        return TransportResult(False, type(e).__name__)
    except Exception as e:  # library/handshake errors -> report but not "supported"
        return TransportResult(False, f"{type(e).__name__}: {str(e)[:60]}")


def transports(host: str | None, ip: str, port: int, timeout: float = TRANSPORT_TIMEOUT) -> dict[str, TransportResult]:
    """Probe each transport with a benign query; caller labels the results."""
    results: dict[str, TransportResult] = {}
    results["UDP/53"] = _try(lambda: dns.query.udp(_probe_query(), ip, port=port, timeout=timeout))
    results["TCP/53"] = _try(lambda: dns.query.tcp(_probe_query(), ip, port=port, timeout=timeout))
    results["DoT/853"] = _try(
        lambda: dns.query.tls(_probe_query(), ip, port=853, timeout=timeout, server_hostname=host)
    )
    doh_url = f"https://{host or ip}/dns-query"
    results["DoH/443"] = _try(lambda: dns.query.https(_probe_query(), doh_url, timeout=timeout))
    if getattr(getattr(dns, "quic", None), "have_quic", False):
        results["DoQ/853"] = _try(
            lambda: dns.query.quic(_probe_query(), ip, port=853, timeout=timeout, server_hostname=host)
        )
    else:
        results["DoQ/853"] = TransportResult(None, "aioquic not installed")
    return results


# --------------------------------------------------------------------------- #
# Server role: authoritative / recursive / forwarder
# --------------------------------------------------------------------------- #
@dataclass
class RoleInfo:
    recursion_available: bool | None = None   # RA flag echoed
    recursion_answered: bool | None = None     # actually resolved an external name for us
    authoritative: bool | None = None          # AA flag on the probe
    rcode: str | None = None
    error: str | None = None


def role_probe(ip: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> RoleInfo:
    """Send a recursive query for an external name and read RA/AA/answer to classify the server.

    Distinguishing a full recursive resolver from a forwarder is not reliable
    remotely (both recurse from the client's point of view), so the module
    reports the observable signals and flags open recursion.
    """
    query = dns.message.make_query("example.com", dns.rdatatype.A)
    query.flags |= dns.flags.RD
    try:
        response = dns.query.udp(query, ip, port=port, timeout=timeout)
    except Exception as e:
        return RoleInfo(error=f"{type(e).__name__}: {e}")

    return RoleInfo(
        recursion_available=bool(response.flags & dns.flags.RA),
        recursion_answered=(response.rcode() == dns.rcode.NOERROR and len(response.answer) > 0),
        authoritative=bool(response.flags & dns.flags.AA),
        rcode=dns.rcode.to_text(response.rcode()),
    )


# --------------------------------------------------------------------------- #
# Known-CVE matching for the advertised software version
# --------------------------------------------------------------------------- #
@dataclass
class CveEntry:
    cve: str
    summary: str
    # each range: (introduced_inclusive_or_None, fixed_exclusive_or_None)
    ranges: list[tuple[tuple[int, ...] | None, tuple[int, ...] | None]]


# Seed table — INDICATIVE, keyed off the ADVERTISED version (which may be hidden
# or spoofed). Not exhaustive; every entry cites the fixed version(s) so it can
# be verified and extended. A range is (introduced_inclusive | None, fixed_exclusive
# | None): None-introduced means "all earlier versions", None-fixed means "not
# fixed / open-ended". A version matches an entry if it falls in ANY of its ranges.
KNOWN_CVES: dict[str, list[CveEntry]] = {
    "bind": [
        CveEntry("CVE-2020-8625",
                 "GSSAPI SPNEGO buffer overflow in TKEY (RCE/DoS)",
                 [((9, 5, 0), (9, 11, 28)), ((9, 12, 0), (9, 16, 12)), ((9, 17, 0), (9, 17, 2))]),
        CveEntry("CVE-2021-25220",
                 "cache poisoning via forwarder (spoofed NS records cached)",
                 [((9, 11, 0), (9, 16, 27)), ((9, 18, 0), (9, 18, 1))]),
        CveEntry("CVE-2022-2795",
                 "CPU exhaustion resolving crafted large delegations",
                 [(None, (9, 16, 33)), ((9, 18, 0), (9, 18, 7)), ((9, 19, 0), (9, 19, 5))]),
        CveEntry("CVE-2022-3080",
                 "resolver crash on stale-cache + prefetch (assertion)",
                 [((9, 16, 11), (9, 16, 33)), ((9, 18, 0), (9, 18, 7)), ((9, 19, 0), (9, 19, 5))]),
        CveEntry("CVE-2023-2828",
                 "named cache can be abused to exhaust the resolver's memory",
                 [(None, (9, 16, 42)), ((9, 18, 0), (9, 18, 16)), ((9, 19, 0), (9, 19, 14))]),
        CveEntry("CVE-2023-3341",
                 "control-channel stack exhaustion crashes named",
                 [(None, (9, 16, 44)), ((9, 18, 0), (9, 18, 19)), ((9, 19, 0), (9, 19, 17))]),
        CveEntry("CVE-2023-50387 (KeyTrap)",
                 "DNSSEC validation CPU exhaustion (protocol-wide)",
                 [(None, (9, 16, 48)), ((9, 18, 0), (9, 18, 24)), ((9, 19, 0), (9, 19, 21))]),
    ],
    "dnsmasq": [
        CveEntry("CVE-2017-14491",
                 "2-byte then unrestricted heap overflow in DNS handling (RCE)",
                 [(None, (2, 78))]),
        CveEntry("CVE-2020-25681..25687 (DNSpooq)",
                 "buffer overflows / cache poisoning in DNS handling",
                 [(None, (2, 83))]),
        CveEntry("CVE-2021-3448",
                 "fixed upstream source port weakens cache-poisoning resistance",
                 [(None, (2, 85))]),
    ],
    "unbound": [
        CveEntry("CVE-2020-12662 (NXNSAttack)",
                 "recursion amplification via delegations with many NS",
                 [(None, (1, 10, 1))]),
        CveEntry("CVE-2022-30698 / CVE-2022-30699",
                 "delegation-cache poisoning via crafted responses",
                 [(None, (1, 16, 2))]),
        CveEntry("CVE-2023-50387 (KeyTrap)",
                 "DNSSEC validation CPU exhaustion (protocol-wide)",
                 [(None, (1, 19, 1))]),
        CveEntry("CVE-2024-33655 (DNSBomb)",
                 "pulsing-DoS amplification via response batching",
                 [(None, (1, 20, 0))]),
    ],
    "powerdns-recursor": [
        CveEntry("CVE-2020-25829",
                 "Recursor cache pollution via crafted answers",
                 [(None, (4, 1, 18)), ((4, 2, 0), (4, 2, 5)), ((4, 3, 0), (4, 3, 5))]),
        CveEntry("CVE-2023-50387 (KeyTrap)",
                 "DNSSEC validation CPU exhaustion (protocol-wide)",
                 [((4, 8, 0), (4, 8, 6)), ((4, 9, 0), (4, 9, 3)), ((5, 0, 0), (5, 0, 2))]),
    ],
    "powerdns-auth": [
        # Authoritative server: fill in as needed (no seed entries yet).
    ],
    "knot-resolver": [
        CveEntry("CVE-2022-40188",
                 "Knot Resolver denial of service via crafted responses",
                 [(None, (5, 5, 3))]),
        CveEntry("CVE-2023-50387 (KeyTrap)",
                 "DNSSEC validation CPU exhaustion (protocol-wide)",
                 [(None, (5, 7, 1))]),
    ],
    "knot-dns": [
        # Knot DNS (authoritative): fill in as needed (no seed entries yet).
    ],
    # Windows DNS does not answer CHAOS TXT, so it cannot be version-fingerprinted
    # remotely here; SIGRed (CVE-2020-1350) is listed for reference only.
    "windows": [],
}


_VERSION_RE = re.compile(r"(\d+(?:\.\d+){1,3})")


def identify_product(version_string: str) -> tuple[str | None, tuple[int, ...] | None, str]:
    """Best-effort ``(product, version_tuple, note)`` from a ``version.bind`` string.

    Product is matched by keyword (with PowerDNS/Knot split into their resolver
    vs authoritative variants, which have different version schemes and CVEs); a
    purely numeric string is assumed to be BIND (whose ``version.bind`` is
    numeric-only). Returns ``product=None`` when it cannot be identified. The
    parse is heuristic and easily fooled/hidden.
    """
    s = version_string.strip()
    low = s.lower()
    product: str | None = None
    note = ""
    if "dnsmasq" in low:
        product = "dnsmasq"
    elif "unbound" in low:
        product = "unbound"
    elif "powerdns" in low or "pdns" in low:
        if "recursor" in low:
            product = "powerdns-recursor"
        elif "authoritative" in low or "auth" in low:
            product = "powerdns-auth"
        else:
            product = "powerdns"
    elif "knot" in low:
        product = "knot-resolver" if "resolver" in low else "knot-dns"
    elif "microsoft" in low or "windows" in low:
        product = "windows"

    m = _VERSION_RE.search(s)
    version = tuple(int(p) for p in m.group(1).split(".")) if m else None

    if product is None and version is not None and re.fullmatch(r"[\d.]+(?:[-+].*)?", s):
        product = "bind"
        note = "assumed BIND (numeric-only version.bind)"
    return product, version, note


def _pad(t: tuple[int, ...], n: int) -> tuple[int, ...]:
    return tuple(t) + (0,) * (n - len(t))


def _in_range(version: tuple[int, ...], introduced, fixed) -> bool:
    """True if *version* is at/after *introduced* (or None) and before *fixed* (or None).

    Bounds and version are zero-padded to a common length so that a 2-part
    version like ``9.18`` compares correctly against a 3-part bound ``9.18.16``.
    """
    n = max(len(version), len(introduced or ()), len(fixed or ()))
    v = _pad(version, n)
    if introduced is not None and v < _pad(introduced, n):
        return False
    if fixed is not None and v >= _pad(fixed, n):
        return False
    return True


def match_cves(product: str | None, version: tuple[int, ...] | None) -> list[CveEntry]:
    """Return the seed-table CVEs whose affected range covers *version* for *product*."""
    if not product or version is None:
        return []
    matches: list[CveEntry] = []
    for entry in KNOWN_CVES.get(product, []):
        if any(_in_range(version, lo, hi) for (lo, hi) in entry.ranges):
            matches.append(entry)
    return matches
