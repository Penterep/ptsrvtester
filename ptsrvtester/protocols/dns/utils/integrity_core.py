"""Integrity / delegation / takeover probe logic for the DNS modules.

All remotely observable: subdomain-takeover fingerprints, lame-delegation checks
(query each NS directly), CNAME chain/loop following, and NS/SOA consistency
across the zone's name servers.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver

from . import zonexfer_core as zx

DEFAULT_TIMEOUT = 5.0
CNAME_CAP = 12

TAKEOVER_SIGNATURES: list[dict] = [
    {"service": "GitHub Pages", "cnames": [".github.io"], "fingerprint": "There isn't a GitHub Pages site here"},
    {"service": "AWS S3", "cnames": [".s3.amazonaws.com", "s3-website", ".s3-", ".s3."], "fingerprint": "NoSuchBucket"},
    {"service": "Heroku", "cnames": [".herokuapp.com", ".herokudns.com"], "fingerprint": "No such app"},
    {"service": "Azure", "cnames": [".azurewebsites.net", ".cloudapp.net", ".cloudapp.azure.com",
                                     ".trafficmanager.net", ".blob.core.windows.net", ".azureedge.net"],
     "fingerprint": "404 Web Site not found"},
    {"service": "Fastly", "cnames": [".fastly.net"], "fingerprint": "Fastly error: unknown domain"},
    {"service": "Shopify", "cnames": [".myshopify.com"], "fingerprint": "Sorry, this shop is currently unavailable"},
    {"service": "Zendesk", "cnames": [".zendesk.com"], "fingerprint": "Help Center Closed"},
    {"service": "Surge.sh", "cnames": [".surge.sh"], "fingerprint": "project not found"},
    {"service": "Bitbucket", "cnames": [".bitbucket.io"], "fingerprint": "Repository not found"},
    {"service": "Pantheon", "cnames": [".pantheonsite.io"], "fingerprint": "The gods are wise"},
    {"service": "Tumblr", "cnames": [".domains.tumblr.com"], "fingerprint": "Whatever you were looking for doesn't currently exist"},
    {"service": "Wordpress", "cnames": [".wordpress.com"], "fingerprint": "Do you want to register"},
    {"service": "Ghost", "cnames": [".ghost.io"], "fingerprint": "The thing you were looking for is no longer here"},
    {"service": "Readthedocs", "cnames": [".readthedocs.io"], "fingerprint": "unknown to Read the Docs"},
]


@dataclass
class TakeoverResult:
    name: str
    cname: str | None = None
    service: str | None = None
    dangling: bool = False
    fingerprint_hit: bool = False
    vulnerable: bool = False
    detail: str = ""


def _match_service(target: str) -> dict | None:
    low = target.lower()
    for sig in TAKEOVER_SIGNATURES:
        if any(c in low for c in sig["cnames"]):
            return sig
    return None


def takeover_check(resolver, name: str, do_http: bool = True, timeout: float = DEFAULT_TIMEOUT) -> TakeoverResult:
    """Check one name for subdomain-takeover indicators (dangling CNAME / SaaS fingerprint)."""
    result = TakeoverResult(name=name)
    try:
        cnames = resolver.resolve(name, "CNAME")
        result.cname = cnames[0].to_text().rstrip(".")
    except Exception:
        result.cname = None

    if not result.cname:
        result.detail = "no CNAME"
        return result

    sig = _match_service(result.cname)
    result.service = sig["service"] if sig else None

    try:
        resolver.resolve(result.cname, "A")
        target_resolves = True
    except dns.resolver.NXDOMAIN:
        target_resolves = False
    except Exception:
        target_resolves = True
    result.dangling = not target_resolves

    if sig and do_http:
        result.fingerprint_hit = _http_fingerprint(name, sig["fingerprint"], timeout)

    if result.dangling:
        result.vulnerable = True
        result.detail = f"dangling CNAME → {result.cname} (NXDOMAIN)"
    elif sig and result.fingerprint_hit:
        result.vulnerable = True
        result.detail = f"points to {sig['service']} and shows the unclaimed fingerprint"
    elif sig:
        result.detail = f"points to {sig['service']} (verify it is claimed)"
    else:
        result.detail = f"CNAME → {result.cname}"
    return result


def _http_fingerprint(name: str, fingerprint: str, timeout: float) -> bool:
    try:
        import httpx
    except Exception:
        return False
    for scheme in ("https", "http"):
        try:
            r = httpx.get(f"{scheme}://{name}", timeout=timeout, verify=False, follow_redirects=True)
            if fingerprint.lower() in r.text.lower():
                return True
        except Exception:
            continue
    return False


def _query(ip: str, qname: str, rdtype, rd: bool, timeout: float):
    q = dns.message.make_query(qname, rdtype)
    if not rd:
        q.flags &= ~dns.flags.RD
    try:
        return dns.query.udp(q, ip, timeout=timeout)
    except Exception:
        try:
            return dns.query.tcp(q, ip, timeout=timeout)
        except Exception:
            return None


@dataclass
class LameResult:
    ns: str
    ip: str | None
    ok: bool
    status: str


def lame_delegations(resolver, domain: str, timeout: float = DEFAULT_TIMEOUT) -> list[LameResult]:
    """For each delegated NS, check it is actually authoritative for the zone (AA=1 SOA)."""
    out: list[LameResult] = []
    servers = zx.get_nameservers(resolver, domain, None)
    for ns in servers:
        if not ns.ips:
            out.append(LameResult(ns.host.rstrip("."), None, False, "no A/AAAA for NS (broken delegation)"))
            continue
        ns_ok = False
        status = "no response"
        for ip in ns.ips:
            resp = _query(ip, domain, dns.rdatatype.SOA, rd=False, timeout=timeout)
            if resp is None:
                status = "no response"
                continue
            rc = dns.rcode.to_text(resp.rcode())
            if resp.rcode() != dns.rcode.NOERROR:
                status = f"{rc}"
                continue
            authoritative = bool(resp.flags & dns.flags.AA)
            has_soa = any(rr.rdtype == dns.rdatatype.SOA for rr in resp.answer)
            if authoritative and has_soa:
                ns_ok = True
                status = "authoritative"
                break
            status = "responds but not authoritative (AA=0)" if not authoritative else "no SOA"
        out.append(LameResult(ns.host.rstrip("."), ns.ips[0], ns_ok, status))
    return out


@dataclass
class ChainResult:
    chain: list[str] = field(default_factory=list)
    loop: bool = False
    truncated: bool = False


def cname_chain(resolver, name: str, cap: int = CNAME_CAP, timeout: float = DEFAULT_TIMEOUT) -> ChainResult:
    """Follow the CNAME chain; detect loops (revisited name) and excessive length."""
    result = ChainResult(chain=[name.rstrip(".")])
    seen = {name.rstrip(".").lower()}
    current = name
    while True:
        try:
            ans = resolver.resolve(current, "CNAME")
            target = ans[0].to_text().rstrip(".")
        except Exception:
            break
        result.chain.append(target)
        if target.lower() in seen:
            result.loop = True
            break
        seen.add(target.lower())
        current = target
        if len(result.chain) > cap:
            result.truncated = True
            break
    return result


@dataclass
class NsView:
    ns: str
    ip: str | None
    reachable: bool
    serial: int | None = None
    ns_set: frozenset = field(default_factory=frozenset)


def ns_consistency(resolver, domain: str, timeout: float = DEFAULT_TIMEOUT) -> tuple[list[NsView], bool, list[str]]:
    """Query each NS for SOA serial + NS set; return (views, consistent, notes)."""
    views: list[NsView] = []
    servers = zx.get_nameservers(resolver, domain, None)
    for ns in servers:
        ip = ns.ips[0] if ns.ips else None
        if ip is None:
            views.append(NsView(ns.host.rstrip("."), None, False))
            continue
        soa = _query(ip, domain, dns.rdatatype.SOA, rd=False, timeout=timeout)
        nsr = _query(ip, domain, dns.rdatatype.NS, rd=False, timeout=timeout)
        serial = None
        if soa is not None:
            for rr in soa.answer:
                if rr.rdtype == dns.rdatatype.SOA:
                    serial = int(rr[0].serial)
        ns_set = frozenset()
        if nsr is not None:
            names = [i.to_text().lower().rstrip(".") for rr in nsr.answer if rr.rdtype == dns.rdatatype.NS for i in rr]
            ns_set = frozenset(names)
        views.append(NsView(ns.host.rstrip("."), ip, soa is not None, serial, ns_set))

    reachable = [v for v in views if v.reachable]
    notes: list[str] = []
    serials = {v.serial for v in reachable if v.serial is not None}
    if len(serials) > 1:
        notes.append("SOA serials differ across name servers: " + ", ".join(str(s) for s in sorted(serials)))
    ns_sets = {v.ns_set for v in reachable if v.ns_set}
    if len(ns_sets) > 1:
        notes.append("NS record sets differ across name servers")
    if len(reachable) < len(views):
        notes.append(f"{len(views) - len(reachable)} of {len(views)} name servers did not answer")
    consistent = not notes
    return views, consistent, notes
