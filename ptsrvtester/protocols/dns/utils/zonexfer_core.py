"""Zone-transfer probe logic for the DNS modules (AXFR / IXFR).

Pure, side-effect-free helpers (no printing, no ctx) so the thin
``dns/modules/*.py`` transfer modules just call one function and format the
result. Mirrors ``fingerprint_core.py`` / ``enum_core.py``.

Zone transfers always run over TCP (dnspython's ``dns.query.xfr`` uses TCP), so
trying every authoritative name server — primaries and secondaries alike —
directly answers "is AXFR allowed anywhere, including a misconfigured secondary,
over TCP?".
"""
from __future__ import annotations

from dataclasses import dataclass, field

import dns.name
import dns.query
import dns.rdatatype
import dns.resolver
import dns.zone

XFR_TIMEOUT = 10.0
SAMPLE_LIMIT = 25


@dataclass
class NameServer:
    host: str
    ips: list[str] = field(default_factory=list)
    is_primary: bool = False


@dataclass
class XfrResult:
    server: str
    ip: str
    is_primary: bool
    allowed: bool
    record_count: int | None = None
    sample: list[str] = field(default_factory=list)
    incremental: bool | None = None
    error: str | None = None


def get_soa(resolver, domain: str) -> tuple[str | None, int | None]:
    """Return the SOA ``(primary_mname, serial)`` for *domain*, or ``(None, None)``."""
    try:
        answer = resolver.resolve(domain, "SOA")
        rr = answer[0]
        return rr.mname.to_text().lower(), int(rr.serial)
    except Exception:
        return None, None


def get_nameservers(resolver, domain: str, primary: str | None) -> list[NameServer]:
    """Resolve the domain's NS records to name servers with their IPs, marking the primary."""
    servers: list[NameServer] = []
    try:
        ns_answer = resolver.resolve(domain, "NS")
    except Exception:
        return servers

    for rr in ns_answer:
        host = rr.to_text().lower()
        ns = NameServer(host=host, is_primary=(primary is not None and host == primary))
        for rtype in ("A", "AAAA"):
            try:
                ns.ips.extend(r.to_text() for r in resolver.resolve(host.rstrip("."), rtype))
            except Exception:
                continue
        servers.append(ns)
    return servers


def try_axfr(ip: str, zone: str, host: str, is_primary: bool, timeout: float = XFR_TIMEOUT) -> XfrResult:
    """Attempt a full AXFR of *zone* from *ip* over TCP."""
    label = f"{host.rstrip('.')} ({ip})"
    try:
        xfr = dns.query.xfr(ip, zone, timeout=timeout, lifetime=timeout)
        z = dns.zone.from_xfr(xfr)
        names = sorted(n.to_text() for n in z.nodes.keys())
        return XfrResult(server=label, ip=ip, is_primary=is_primary, allowed=True,
                         record_count=len(names), sample=names[:SAMPLE_LIMIT])
    except Exception as e:
        return XfrResult(server=label, ip=ip, is_primary=is_primary, allowed=False,
                         error=f"{type(e).__name__}: {e}")


def try_ixfr(ip: str, zone: str, host: str, is_primary: bool, serial: int,
             timeout: float = XFR_TIMEOUT) -> XfrResult:
    """Attempt an incremental IXFR of *zone* from *ip* (asking for changes since *serial*).

    Per RFC 1995 a server may answer IXFR with a full AXFR-style zone; either way
    a non-refused reply that yields records is a zone-transfer exposure. We flag
    whether the reply looked truly incremental (IXFR) or a full fallback.
    """
    label = f"{host.rstrip('.')} ({ip})"
    try:
        gen = dns.query.xfr(ip, zone, rdtype=dns.rdatatype.IXFR, serial=serial,
                            timeout=timeout, lifetime=timeout)
        messages = list(gen)
        record_count = sum(len(m.answer) for m in messages)
        if record_count == 0:
            return XfrResult(server=label, ip=ip, is_primary=is_primary, allowed=False,
                             error="no records returned")
        soa_count = sum(
            1 for m in messages for rr in m.answer if rr.rdtype == dns.rdatatype.SOA
        )
        incremental = soa_count > 2
        return XfrResult(server=label, ip=ip, is_primary=is_primary, allowed=True,
                         record_count=record_count, incremental=incremental)
    except Exception as e:
        return XfrResult(server=label, ip=ip, is_primary=is_primary, allowed=False,
                         error=f"{type(e).__name__}: {e}")


def transfer_targets(resolver, domain: str, extra_server: tuple[str, str] | None = None) -> tuple[list[NameServer], str | None, int | None]:
    """Build the list of name servers to try, plus the SOA primary/serial.

    *extra_server* is an optional ``(host_label, ip)`` for an explicit ``-tg``
    server the operator wants tried directly (e.g. a suspected secondary).
    """
    primary, serial = get_soa(resolver, domain)
    servers = get_nameservers(resolver, domain, primary)
    if extra_server is not None:
        host, ip = extra_server
        known_ips = {i for ns in servers for i in ns.ips}
        if ip not in known_ips:
            servers.append(NameServer(host=host, ips=[ip], is_primary=False))
    return servers, primary, serial