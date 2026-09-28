"""Recursion & resolver-abuse probe logic for the DNS modules.

Pure, side-effect-free helpers (no printing, no ctx). All probes talk to ONE
target server (``-tg`` → ``ctx.ip`` / ``ctx.port``) with hand-built messages so
the RD flag and EDNS payload can be controlled directly. Mirrors the other
``*_core.py`` files.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

DEFAULT_TIMEOUT = 5.0

# External names used to prove the server recurses for zones it is not
# authoritative for (open recursion) and to probe the cache.
EXTERNAL_NAMES: tuple[str, ...] = (
    "google.com", "cloudflare.com", "microsoft.com", "amazon.com",
    "facebook.com", "wikipedia.org", "github.com", "apple.com",
)

# Small queries that elicit large recursive responses (amplification vectors).
AMP_QUERIES: tuple[tuple[str, str], ...] = (
    ("google.com", "TXT"),
    ("cloudflare.com", "DNSKEY"),
    ("org", "DNSKEY"),
    ("isc.org", "ANY"),
)


@dataclass
class RecursionProbe:
    name: str
    ra: bool | None          # RA flag echoed by the server
    answered: bool | None     # returned an answer for the external name
    authoritative: bool | None = None  # AA flag — an authoritative in-zone answer, not recursion
    rcode: str = ""


def open_recursion(ip: str, port: int, names=EXTERNAL_NAMES, timeout: float = DEFAULT_TIMEOUT) -> tuple[bool, list[RecursionProbe]]:
    """Send RD=1 queries for external names.

    Open recursion = the server RECURSED for a name it is not authoritative for:
    RA set, an answer returned, and AA clear (an AA=1 answer means the server is
    authoritative for that name, e.g. an NS that happens to host it — not
    recursion).
    """
    probes: list[RecursionProbe] = []
    for name in names:
        query = dns.message.make_query(name, dns.rdatatype.A)
        query.flags |= dns.flags.RD
        try:
            resp = dns.query.udp(query, ip, port=port, timeout=timeout)
            probes.append(RecursionProbe(
                name=name,
                ra=bool(resp.flags & dns.flags.RA),
                answered=(resp.rcode() == dns.rcode.NOERROR and len(resp.answer) > 0),
                authoritative=bool(resp.flags & dns.flags.AA),
                rcode=dns.rcode.to_text(resp.rcode()),
            ))
        except Exception as e:
            probes.append(RecursionProbe(name=name, ra=None, answered=None, rcode=f"error: {type(e).__name__}"))
    is_open = any(p.ra and p.answered and not p.authoritative for p in probes)
    return is_open, probes


@dataclass
class AmpResult:
    name: str
    rtype: str
    request_size: int
    response_size: int
    factor: float
    answered: bool
    authoritative: bool = False   # AA=1 → answered from its own zone, not recursion
    truncated: bool = False

    @property
    def reflectable(self) -> bool:
        """Answered by RECURSING for an out-of-zone name — the amplification case."""
        return self.answered and not self.authoritative


def amplification(ip: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> list[AmpResult]:
    """Measure response-vs-query size for out-of-zone queries (reflection/amplification)."""
    results: list[AmpResult] = []
    for name, rtype in AMP_QUERIES:
        query = dns.message.make_query(name, rtype, use_edns=0, payload=4096)
        query.flags |= dns.flags.RD
        request_size = len(query.to_wire())
        try:
            resp = dns.query.udp(query, ip, port=port, timeout=timeout)
        except Exception:
            continue
        response_size = len(resp.to_wire())
        results.append(AmpResult(
            name=name,
            rtype=rtype,
            request_size=request_size,
            response_size=response_size,
            factor=round(response_size / request_size, 1) if request_size else 0.0,
            answered=(resp.rcode() == dns.rcode.NOERROR and len(resp.answer) > 0),
            authoritative=bool(resp.flags & dns.flags.AA),
            truncated=bool(resp.flags & dns.flags.TC),
        ))
    return results


def best_amplification(results: list[AmpResult]) -> AmpResult | None:
    """The out-of-zone (recursed) answer with the largest amplification factor, if any."""
    reflectable = [r for r in results if r.reflectable]
    return max(reflectable, key=lambda r: r.factor) if reflectable else None


@dataclass
class SnoopResult:
    name: str
    cached: bool | None       # answered from cache to a non-recursive query (AA=0)
    ttl: int | None = None    # remaining TTL (lower than the record max = it aged in cache)
    rcode: str = ""


def cache_snoop(ip: str, port: int, names=EXTERNAL_NAMES, timeout: float = DEFAULT_TIMEOUT) -> list[SnoopResult]:
    """Send non-recursive (RD=0) queries; a non-authoritative answer means the name is cached.

    An AA=1 answer is the server being authoritative for that name (not a cache
    hit), so it does not count as cache snooping.
    """
    out: list[SnoopResult] = []
    for name in names:
        query = dns.message.make_query(name, dns.rdatatype.A)
        query.flags &= ~dns.flags.RD  # explicitly non-recursive
        try:
            resp = dns.query.udp(query, ip, port=port, timeout=timeout)
        except Exception as e:
            out.append(SnoopResult(name=name, cached=None, rcode=f"error: {type(e).__name__}"))
            continue
        authoritative = bool(resp.flags & dns.flags.AA)
        cached = resp.rcode() == dns.rcode.NOERROR and len(resp.answer) > 0 and not authoritative
        ttl = min((rr.ttl for rr in resp.answer), default=None) if cached else None
        out.append(SnoopResult(name=name, cached=cached, ttl=ttl, rcode=dns.rcode.to_text(resp.rcode())))
    return out
