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

from .helpers import text_or_file

DEFAULT_TIMEOUT = 5.0
GUARD_TIMEOUT = 4.0

EXTERNAL_NAMES: tuple[str, ...] = (
    "google.com", "cloudflare.com", "microsoft.com", "amazon.com",
    "facebook.com", "wikipedia.org", "github.com", "apple.com",
)

AMP_QUERIES: tuple[tuple[str, str], ...] = (
    ("google.com", "TXT"),
    ("cloudflare.com", "DNSKEY"),
    ("org", "DNSKEY"),
    ("isc.org", "ANY"),
)


# --------------------------------------------------------------------------- #
# Probe-target selection + reachability guard
#
# The resolver-probe tests (ROLE / RECURSION / AMPLIFICATION / CACHESNOOP) need a
# name the target can resolve. Hard-coded external names time out against an
# internal DNS with no internet; so when -d/-dl is given those domains are used
# instead, and a pre-flight guard bails with a clear message if nothing resolves.
# --------------------------------------------------------------------------- #
def probe_domains(ctx) -> list[str]:
    """The -d / -dl domains, if any (used instead of the built-in external names)."""
    return [d.strip() for d in text_or_file(getattr(ctx.args, "domain", None),
                                            getattr(ctx.args, "domain_file", None)) if d.strip()]


def probe_resolves(ip: str, port: int, name: str, timeout: float = GUARD_TIMEOUT) -> bool:
    """True if the target returns a usable response for *name* (NOERROR/NXDOMAIN/REFUSED).

    False on timeout/unreachable or SERVFAIL — i.e. the resolver could not complete
    the lookup (typical of an internal DNS with no path to the name).
    """
    query = dns.message.make_query(name, dns.rdatatype.A)
    query.flags |= dns.flags.RD
    try:
        resp = dns.query.udp(query, ip, port=port, timeout=timeout)
    except Exception:
        return False
    return resp.rcode() != dns.rcode.SERVFAIL


def resolve_guard(ctx, ip: str, port: int, name: str, timeout: float = GUARD_TIMEOUT) -> None:
    """Pre-flight: if the target cannot resolve *name*, end the run with a clear error.

    No -d given  -> likely an internal DNS without internet: tell the user to pass
    -d <internal-domain>. -d given but still unresolvable -> service unavailable or
    the domain is invalid. Returns normally when resolution works.
    """
    if probe_resolves(ip, port, name, timeout):
        return
    if probe_domains(ctx):
        ctx.ptjsonlib.end_error(
            f"The DNS service at {ip} did not resolve '{name}' — the service is unavailable "
            f"or '{name}' is not a valid / served domain.", ctx.json)
    else:
        ctx.ptjsonlib.end_error(
            f"Could not resolve '{name}' via {ip}. This looks like an internal DNS without "
            f"internet access — re-run with -d <internal-domain> so the resolver tests use a "
            f"name it can resolve.", ctx.json)


@dataclass
class RecursionProbe:
    name: str
    ra: bool | None
    answered: bool | None
    authoritative: bool | None = None
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
    authoritative: bool = False
    truncated: bool = False

    @property
    def reflectable(self) -> bool:
        """Answered by RECURSING for an out-of-zone name — the amplification case."""
        return self.answered and not self.authoritative


def amplification(ip: str, port: int, domains: list[str] | None = None,
                  timeout: float = DEFAULT_TIMEOUT) -> list[AmpResult]:
    """Measure response-vs-query size for ANY/DNSKEY/TXT (reflection/amplification).

    With *domains* (from -d) the record types are queried against those domains so
    the test works on an internal DNS; otherwise the built-in external AMP_QUERIES
    are used.
    """
    if domains:
        queries = [(d, rt) for d in domains for rt in ("ANY", "DNSKEY", "TXT")]
    else:
        queries = list(AMP_QUERIES)
    results: list[AmpResult] = []
    for name, rtype in queries:
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
    cached: bool | None
    ttl: int | None = None
    rcode: str = ""


def cache_snoop(ip: str, port: int, names=EXTERNAL_NAMES, timeout: float = DEFAULT_TIMEOUT) -> list[SnoopResult]:
    """Send non-recursive (RD=0) queries; a non-authoritative answer means the name is cached.

    An AA=1 answer is the server being authoritative for that name (not a cache
    hit), so it does not count as cache snooping.
    """
    out: list[SnoopResult] = []
    for name in names:
        query = dns.message.make_query(name, dns.rdatatype.A)
        query.flags &= ~dns.flags.RD
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
