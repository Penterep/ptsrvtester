"""Record-enumeration probe logic for the DNS modules.

Pure, side-effect-free query helpers (no printing, no ctx) so the thin
``dns/modules/*.py`` enumeration modules just call one function and format the
result. Mirrors ``fingerprint_core.py`` / the ``ssh/utils/*_core.py`` split.

Queries go through a resolver pinned to the ``-tg`` server when one was given,
otherwise the system resolver (see :func:`resolver_for`).
"""
from __future__ import annotations

import ipaddress
import secrets
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

import dns.exception
import dns.resolver
import dns.reversename

from .helpers import make_resolver

# Default record types for the RECORDS test.
DEFAULT_RECORD_TYPES: tuple[str, ...] = ("A", "AAAA", "MX", "TXT", "CNAME", "NS", "SRV", "SOA")

# Common DKIM selectors tried when the operator does not supply --dkim-selectors.
DEFAULT_DKIM_SELECTORS: tuple[str, ...] = (
    "default", "google", "selector1", "selector2", "k1", "dkim", "mail",
    "smtp", "s1", "s2", "mandrill", "protonmail", "protonmail2", "fm1", "zoho",
)

# Safety cap: never sweep more than this many addresses in one PTR sweep.
PTR_SWEEP_CAP = 1024


def resolver_for(ctx, timeout: float = 5.0) -> dns.resolver.Resolver:
    """A resolver pinned to the ``-tg`` server (``ctx.ip``/``ctx.port``), else the system one."""
    ip = getattr(ctx, "ip", None)
    port = getattr(ctx, "port", None) or 53
    return make_resolver(ip, port, timeout)


def lookup_records(resolver, domain: str, rtypes) -> dict[str, list[str]]:
    """Resolve each record type for *domain*. Maps rtype -> value list (``[]`` if none)."""
    out: dict[str, list[str]] = {}
    for rtype in rtypes:
        try:
            answers = resolver.resolve(domain, rtype)
            out[rtype] = [r.to_text() for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            out[rtype] = []
        except dns.exception.Timeout:
            out[rtype] = ["<timeout>"]
        except Exception:
            out[rtype] = []
    return out


def parse_range(spec: str) -> tuple[list[str], str | None]:
    """Expand *spec* into a list of IPv4/IPv6 addresses.

    Accepts a single IP, CIDR (``192.0.2.0/24``), or ``start-end`` /
    ``start-lastoctet`` range. Returns ``(addresses, note)`` where *note* warns
    when the list was capped at :data:`PTR_SWEEP_CAP`.
    """
    spec = spec.strip()
    note: str | None = None
    addrs: list[str] = []

    if "/" in spec:
        net = ipaddress.ip_network(spec, strict=False)
        hosts = list(net.hosts()) or [net.network_address]
        addrs = [str(h) for h in hosts]
    elif "-" in spec:
        start_s, end_s = (p.strip() for p in spec.split("-", 1))
        start = ipaddress.ip_address(start_s)
        if end_s.isdigit():
            end = ipaddress.ip_address(".".join(start_s.split(".")[:-1] + [end_s]))
        else:
            end = ipaddress.ip_address(end_s)
        if int(end) < int(start):
            start, end = end, start
        addrs = [str(ipaddress.ip_address(i)) for i in range(int(start), int(end) + 1)]
    else:
        addrs = [str(ipaddress.ip_address(spec))]

    if len(addrs) > PTR_SWEEP_CAP:
        note = f"range capped at {PTR_SWEEP_CAP} addresses (was {len(addrs)})"
        addrs = addrs[:PTR_SWEEP_CAP]
    return addrs, note


def _ptr_one(resolver, ip: str) -> tuple[str, list[str]] | None:
    try:
        rev = dns.reversename.from_address(ip)
        answers = resolver.resolve(rev, "PTR")
        return ip, [r.to_text().rstrip(".") for r in answers]
    except Exception:
        return None


def ptr_sweep(resolver, ips: list[str], threads: int = 10) -> dict[str, list[str]]:
    """Reverse-resolve every address; returns ``{ip: [names]}`` for the ones with a PTR."""
    results: dict[str, list[str]] = {}
    with ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
        futures = [pool.submit(_ptr_one, resolver, ip) for ip in ips]
        for fut in as_completed(futures):
            got = fut.result()
            if got:
                results[got[0]] = got[1]
    return results


def whois_lookup(domain: str) -> str | None:
    """Return the raw WHOIS text for *domain*, or ``None`` on failure."""
    try:
        import whois
    except Exception:
        return None
    try:
        info = whois.whois(domain)
    except Exception:
        return None
    text = getattr(info, "text", None)
    return text if text else (str(info) if info else None)


@dataclass
class WildcardInfo:
    present: bool = False
    a: set[str] = field(default_factory=set)
    aaaa: set[str] = field(default_factory=set)
    cname: set[str] = field(default_factory=set)
    sample: str | None = None


def wildcard_detect(resolver, domain: str, probes: int = 3) -> WildcardInfo:
    """Query random non-existent labels; if they resolve, the zone has a wildcard."""
    info = WildcardInfo()
    for _ in range(probes):
        label = "ptsrv-" + secrets.token_hex(6)
        fqdn = f"{label}.{domain}"
        info.sample = fqdn
        for rtype, bucket in (("A", info.a), ("AAAA", info.aaaa), ("CNAME", info.cname)):
            try:
                for r in resolver.resolve(fqdn, rtype):
                    bucket.add(r.to_text().rstrip("."))
                    info.present = True
            except Exception:
                continue
        if info.present:
            break
    return info



def _resolve_sub(resolver, fqdn: str) -> dict[str, list[str]]:
    records: dict[str, list[str]] = {}
    for rtype in ("A", "AAAA", "CNAME"):
        try:
            records[rtype] = [r.to_text().rstrip(".") for r in resolver.resolve(fqdn, rtype)]
        except Exception:
            continue
    return records


def brute_subdomains(
    resolver, domain: str, labels: list[str], threads: int = 10,
    wildcard: WildcardInfo | None = None,
) -> tuple[list[tuple[str, dict[str, list[str]]]], int]:
    """Resolve ``<label>.<domain>`` for each label; returns ``(found, wildcard_filtered)``.

    A hit whose A/AAAA/CNAME answer equals the wildcard baseline is treated as
    wildcard noise and counted in *wildcard_filtered* instead of *found*.
    """
    found: list[tuple[str, dict[str, list[str]]]] = []
    filtered = 0
    wc = wildcard if (wildcard and wildcard.present) else None

    def work(label: str):
        fqdn = f"{label.strip()}.{domain}"
        recs = _resolve_sub(resolver, fqdn)
        return (fqdn, recs) if recs else None

    clean = [l for l in labels if l.strip()]
    with ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
        futures = [pool.submit(work, l) for l in clean]
        for fut in as_completed(futures):
            got = fut.result()
            if not got:
                continue
            fqdn, recs = got
            if wc and _is_wildcard_noise(recs, wc):
                filtered += 1
                continue
            found.append((fqdn, recs))
    found.sort(key=lambda t: t[0])
    return found, filtered


def _is_wildcard_noise(recs: dict[str, list[str]], wc: WildcardInfo) -> bool:
    a = set(recs.get("A", []))
    aaaa = set(recs.get("AAAA", []))
    cname = set(recs.get("CNAME", []))
    if a and wc.a and a <= wc.a:
        return True
    if aaaa and wc.aaaa and aaaa <= wc.aaaa:
        return True
    if cname and wc.cname and cname <= wc.cname:
        return True
    return False


@dataclass
class EmailSecurity:
    spf: str | None = None
    spf_all: str | None = None
    dmarc: str | None = None
    dmarc_policy: str | None = None
    dkim: dict[str, str] = field(default_factory=dict)


def _txt_strings(resolver, name: str) -> list[str]:
    out: list[str] = []
    try:
        for r in resolver.resolve(name, "TXT"):
            out.append(r.to_text().strip('"').replace('" "', ""))
    except Exception:
        pass
    return out


_SPF_ALL = {"-all": "fail", "~all": "softfail", "?all": "neutral", "+all": "pass"}


def email_security(resolver, domain: str, selectors=DEFAULT_DKIM_SELECTORS) -> EmailSecurity:
    """Look up SPF (TXT), DMARC (_dmarc TXT) and DKIM (<selector>._domainkey TXT)."""
    result = EmailSecurity()

    for txt in _txt_strings(resolver, domain):
        if txt.lower().startswith("v=spf1"):
            result.spf = txt
            low = txt.lower()
            for token, meaning in _SPF_ALL.items():
                if token in low:
                    result.spf_all = meaning
                    break
            break

    for txt in _txt_strings(resolver, f"_dmarc.{domain}"):
        if txt.lower().startswith("v=dmarc1"):
            result.dmarc = txt
            for part in txt.split(";"):
                part = part.strip().lower()
                if part.startswith("p="):
                    result.dmarc_policy = part[2:].strip()
                    break
            break

    for selector in selectors:
        for txt in _txt_strings(resolver, f"{selector}._domainkey.{domain}"):
            low = txt.lower()
            if low.startswith("v=dkim1") or "p=" in low:
                result.dkim[selector] = txt
                break
    return result


def caa_records(resolver, domain: str) -> list[str]:
    """Return the CAA record values for *domain* (empty list if none set)."""
    try:
        return [r.to_text() for r in resolver.resolve(domain, "CAA")]
    except Exception:
        return []
