"""DNSSEC probe logic for the DNS modules.

DNSSEC material (DNSKEY / DS / RRSIG / NSEC / NSEC3) is public, so these checks
work from a plain remote client. Queries carry the DO bit (``want_dnssec``) and
go to the zone's authoritative servers directly (accurate, no resolver
interference), falling back to a supplied resolver IP. Mirrors the other
``*_core.py`` files.

KeyTrap (CVE-2023-50387) is intentionally NOT here: it is an active
CPU-exhaustion attack against a validating resolver that needs a controlled
authoritative server serving a malicious zone (deferred to a future probe
server). Version-based KeyTrap detection already lives in the CVE module.
"""
from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver

DEFAULT_TIMEOUT = 5.0
RRSIG_WARN_DAYS = 7

"""DNSKEY/DS algorithms considered deprecated (RSA/MD5, DSA, SHA-1 based)."""
DEPRECATED_ALGS: dict[int, str] = {
    1: "RSAMD5", 3: "DSA", 5: "RSASHA1", 6: "DSA-NSEC3-SHA1", 7: "RSASHA1-NSEC3-SHA1",
}

"""Recommended modern algorithms (ECDSA / EdDSA)."""
MODERN_ALGS = {13, 14, 15, 16}

"""DS digest types: 1 = SHA-1 (weak), 2 = SHA-256, 3 = GOST (weak), 4 = SHA-384."""
DS_DIGEST_NAMES = {1: "SHA-1", 2: "SHA-256", 3: "GOST", 4: "SHA-384"}
_DS_DIGEST_FOR_MAKE = {1: "SHA1", 2: "SHA256", 4: "SHA384"}


def resolve_auth_servers(resolver: dns.resolver.Resolver, domain: str) -> list[str]:
    """Resolve the domain's authoritative NS records to a list of IPs."""
    ips: list[str] = []
    try:
        ns_answer = resolver.resolve(domain, "NS")
    except Exception:
        return ips
    for rr in ns_answer:
        host = rr.to_text().rstrip(".")
        for rtype in ("A", "AAAA"):
            try:
                ips.extend(r.to_text() for r in resolver.resolve(host, rtype))
            except Exception:
                continue
    return ips


def servers_for(resolver: dns.resolver.Resolver, domain: str, extra_ip: str | None = None) -> list[str]:
    """Authoritative server IPs for *domain*, with an optional ``-tg`` server as fallback."""
    servers = resolve_auth_servers(resolver, domain)
    if extra_ip and extra_ip not in servers:
        servers.append(extra_ip)
    return servers


def query_do(servers: list[str], name: str, rdtype, timeout: float = DEFAULT_TIMEOUT):
    """Send a DO-bit query for *name*/*rdtype* to the first responsive server (UDP, TCP on TC)."""
    query = dns.message.make_query(name, rdtype, want_dnssec=True, payload=4096)
    for ip in servers:
        try:
            resp = dns.query.udp(query, ip, timeout=timeout)
            if resp.flags & dns.flags.TC:
                resp = dns.query.tcp(query, ip, timeout=timeout)
            return resp
        except Exception:
            continue
    return None


def _rrset(response, rdtype):
    if response is None:
        return None
    for rr in response.answer:
        if rr.rdtype == rdtype:
            return rr
    return None


@dataclass
class DnskeySet:
    dnskey: object | None = None
    rrsig: object | None = None
    valid: bool | None = None
    error: str | None = None


def get_dnskey(servers: list[str], domain: str) -> DnskeySet:
    """Fetch DNSKEY + its RRSIG and validate the self-signature."""
    resp = query_do(servers, domain, dns.rdatatype.DNSKEY)
    if resp is None:
        return DnskeySet(error="no response from authoritative servers")
    dnskey = _rrset(resp, dns.rdatatype.DNSKEY)
    rrsig = _rrset(resp, dns.rdatatype.RRSIG)
    result = DnskeySet(dnskey=dnskey, rrsig=rrsig)
    if dnskey is None:
        return result
    if rrsig is None:
        result.valid = False
        result.error = "DNSKEY present but no RRSIG"
        return result
    try:
        name = dns.name.from_text(domain)
        dns.dnssec.validate(dnskey, rrsig, {name: dnskey})
        result.valid = True
    except Exception as e:
        result.valid = False
        result.error = f"{type(e).__name__}: {e}"
    return result


@dataclass
class AlgInfo:
    key_tag: int
    algorithm: int
    name: str
    role: str
    deprecated: bool
    modern: bool


def key_algorithms(dnskey_rrset) -> list[AlgInfo]:
    out: list[AlgInfo] = []
    for key in dnskey_rrset:
        alg = int(key.algorithm)
        try:
            name = dns.dnssec.algorithm_to_text(key.algorithm)
        except Exception:
            name = f"alg{alg}"
        out.append(AlgInfo(
            key_tag=dns.dnssec.key_id(key),
            algorithm=alg,
            name=name,
            role="KSK" if (key.flags & 0x0001) else "ZSK",
            deprecated=alg in DEPRECATED_ALGS,
            modern=alg in MODERN_ALGS,
        ))
    return out


@dataclass
class SigInfo:
    covers: str
    key_tag: int
    expiration: int
    days_left: float
    expired: bool
    expiring: bool


def rrsig_expiry(servers: list[str], domain: str, warn_days: int = RRSIG_WARN_DAYS) -> list[SigInfo]:
    """Collect RRSIG expirations for the DNSKEY and SOA rrsets."""
    now = time.time()
    infos: list[SigInfo] = []
    for rdtype in (dns.rdatatype.DNSKEY, dns.rdatatype.SOA):
        resp = query_do(servers, domain, rdtype)
        sig = _rrset(resp, dns.rdatatype.RRSIG)
        if sig is None:
            continue
        for rr in sig:
            exp = int(rr.expiration)
            days = (exp - now) / 86400.0
            infos.append(SigInfo(
                covers=dns.rdatatype.to_text(rr.type_covered),
                key_tag=int(rr.key_tag),
                expiration=exp,
                days_left=round(days, 1),
                expired=days < 0,
                expiring=(0 <= days < warn_days),
            ))
    return infos


@dataclass
class DsMatch:
    key_tag: int
    algorithm: int
    digest_type: int
    digest_name: str
    matched: bool | None

def chain_of_trust(servers: list[str], resolver: dns.resolver.Resolver, domain: str, dnskey_rrset) -> tuple[list[DsMatch], bool]:
    """Compare parent DS records against the child DNSKEYs. Returns (matches, ds_present)."""
    try:
        ds_answer = resolver.resolve(domain, "DS")
        ds_rrset = list(ds_answer)
    except Exception:
        return [], False
    if not ds_rrset:
        return [], False

    name = dns.name.from_text(domain)
    matches: list[DsMatch] = []
    for ds in ds_rrset:
        digest_name = DS_DIGEST_NAMES.get(ds.digest_type, f"type{ds.digest_type}")
        matched: bool | None = False
        make_alg = _DS_DIGEST_FOR_MAKE.get(ds.digest_type)
        if dnskey_rrset is not None and make_alg is not None:
            for key in dnskey_rrset:
                if dns.dnssec.key_id(key) == ds.key_tag:
                    try:
                        computed = dns.dnssec.make_ds(name, key, make_alg)
                        if computed.digest == ds.digest:
                            matched = True
                            break
                    except Exception:
                        matched = None
        elif make_alg is None:
            matched = None
        matches.append(DsMatch(int(ds.key_tag), int(ds.algorithm), int(ds.digest_type), digest_name, matched))
    return matches, True


@dataclass
class DenialInfo:
    kind: str | None = None
    nsec_walkable: bool | None = None
    nsec_owner: str | None = None
    nsec_next: str | None = None
    nsec3_iterations: int | None = None
    nsec3_salt: str | None = None
    error: str | None = None


def denial_of_existence(servers: list[str], domain: str) -> DenialInfo:
    """Query a random non-existent name and classify NSEC vs NSEC3 (+ NSEC3 params).

    For NSEC it distinguishes CLASSIC NSEC (owner is a real predecessor name →
    the zone can be walked) from minimal-covering "black lies" (the server
    synthesises an NSEC whose owner is the queried name itself → not walkable).
    """
    label = "ptsrv-" + secrets.token_hex(6)
    qname = f"{label}.{domain}".rstrip(".").lower() + "."
    resp = query_do(servers, f"{label}.{domain}", dns.rdatatype.A)
    if resp is None:
        return DenialInfo(error="no response from authoritative servers")
    for rr in resp.authority:
        if rr.rdtype == dns.rdatatype.NSEC:
            owner = rr.name.to_text().lower()
            nxt = rr[0].next.to_text().lower()
            walkable = owner != qname
            return DenialInfo(kind="NSEC", nsec_walkable=walkable,
                              nsec_owner=owner.rstrip("."), nsec_next=nxt.rstrip("."))
        if rr.rdtype == dns.rdatatype.NSEC3:
            first = rr[0]
            salt = first.salt
            return DenialInfo(
                kind="NSEC3",
                nsec3_iterations=int(first.iterations),
                nsec3_salt=(salt.hex() if salt else "-"),
            )
    return DenialInfo(kind=None)