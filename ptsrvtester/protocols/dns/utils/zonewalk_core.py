"""Zone-walking probe logic for the DNS modules (NSEC enumeration + NSEC3 hashes).

Builds on ``dnssec_core`` (authoritative DO-bit queries). Two techniques:

* NSEC — follow the ``next`` chain from the apex to enumerate every name in
  plaintext (classic NSEC only; minimal-covering "black lies" is not walkable).
* NSEC3 — collect the NSEC3 hash chain by probing random names; the names stay
  hashed until cracked offline (see :func:`crack_nsec3`).
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field

import dns.dnssec
import dns.name
import dns.rdatatype

from . import dnssec_core as dc

# Common labels tried when the operator does not pass a wordlist (-sub) for NSEC3 cracking.
DEFAULT_LABELS: tuple[str, ...] = (
    "www", "mail", "ns", "ns1", "ns2", "smtp", "webmail", "vpn", "ftp", "dev",
    "test", "staging", "api", "admin", "portal", "remote", "gw", "mx", "mx1",
    "autodiscover", "cpanel", "intranet", "git", "db", "backup", "proxy",
)

NSEC_WALK_CAP = 5000
NSEC3_PROBES = 60


def _nsec_next(servers, name: str):
    """Return the NSEC ``next`` owner for *name* (from answer, else covering authority)."""
    resp = dc.query_do(servers, name, dns.rdatatype.NSEC)
    if resp is None:
        return None
    target = name.rstrip(".").lower() + "."
    for rr in resp.answer:
        if rr.rdtype == dns.rdatatype.NSEC and rr.name.to_text().lower() == target:
            return rr[0].next.to_text().lower()
    for rr in resp.authority:
        if rr.rdtype == dns.rdatatype.NSEC:
            return rr[0].next.to_text().lower()
    return None


def walk_nsec(servers, domain: str, cap: int = NSEC_WALK_CAP) -> tuple[list[str], bool]:
    """Walk the NSEC chain from the apex. Returns (names, truncated)."""
    apex = domain.rstrip(".").lower() + "."
    names: list[str] = [apex.rstrip(".")]
    seen: set[str] = {apex}
    current = apex
    truncated = False
    while True:
        nxt = _nsec_next(servers, current.rstrip("."))
        if not nxt or nxt == apex or nxt in seen:
            break
        seen.add(nxt)
        names.append(nxt.rstrip("."))
        current = nxt
        if len(names) >= cap:
            truncated = True
            break
    return names, truncated


@dataclass
class Nsec3Params:
    algorithm: int
    iterations: int
    salt: bytes
    salt_hex: str = field(default="-")


def collect_nsec3(servers, domain: str, probes: int = NSEC3_PROBES) -> tuple[Nsec3Params | None, set[str]]:
    """Probe random names and collect distinct NSEC3 owner hashes (base32hex, lowercase)."""
    params: Nsec3Params | None = None
    hashes: set[str] = set()
    for _ in range(probes):
        label = "ptsrv-" + secrets.token_hex(6)
        resp = dc.query_do(servers, f"{label}.{domain}", dns.rdatatype.A)
        if resp is None:
            continue
        for rr in resp.authority:
            if rr.rdtype != dns.rdatatype.NSEC3:
                continue
            if params is None:
                salt = rr[0].salt or b""
                params = Nsec3Params(
                    algorithm=int(rr[0].algorithm),
                    iterations=int(rr[0].iterations),
                    salt=salt,
                    salt_hex=(salt.hex() if salt else "-"),
                )
            owner = rr.name.to_text().split(".", 1)[0].lower()
            hashes.add(owner)
    return params, hashes


def nsec3_hash_name(fqdn: str, params: Nsec3Params) -> str:
    """Compute the NSEC3 hash (base32hex, lowercase) of *fqdn* under the zone params."""
    salt = params.salt if params.salt else None
    return dns.dnssec.nsec3_hash(fqdn, salt, params.iterations, params.algorithm).lower()


def crack_nsec3(hashes: set[str], params: Nsec3Params, domain: str, labels) -> dict[str, str]:
    """Dictionary-crack collected NSEC3 hashes. Returns ``{hash: revealed_fqdn}``."""
    revealed: dict[str, str] = {}
    candidates = [domain.rstrip(".")] + [f"{l.strip()}.{domain}".rstrip(".") for l in labels if l.strip()]
    for fqdn in candidates:
        try:
            h = nsec3_hash_name(fqdn, params)
        except Exception:
            continue
        if h in hashes:
            revealed[h] = fqdn
    return revealed