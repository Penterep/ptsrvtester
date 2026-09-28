"""Dynamic update (RFC 2136) probe logic for the DNS modules.

These are WRITE tests, so they are opt-in and always clean up:

* DYNUPDATE — try an UNauthenticated update that adds a unique benign TXT record,
  verify it, then delete it.
* TSIGUPDATE — with an operator-supplied TSIG key, test whether the key's update
  scope is ACL-restricted (or lets it write arbitrary names).
* the GSS-TSIG detection uses a PREREQUISITE-ONLY update (RFC 2136 §2.4) which
  makes no changes — it only reveals whether the server enforces authenticated
  update.

Updates are sent to the zone's SOA primary (MNAME) first, then other
authoritative servers.
"""
from __future__ import annotations

import secrets

import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.tsig
import dns.tsigkeyring
import dns.update

from . import dnssec_core as dc
from . import zonexfer_core as zx

DEFAULT_TIMEOUT = 5.0
TEST_TXT = "ptsrvtester-authorized-dynamic-update-test-delete-me"

_TSIG_ALGS = {
    "hmac-md5": dns.tsig.HMAC_MD5,
    "hmac-sha1": dns.tsig.HMAC_SHA1,
    "hmac-sha224": dns.tsig.HMAC_SHA224,
    "hmac-sha256": dns.tsig.HMAC_SHA256,
    "hmac-sha384": dns.tsig.HMAC_SHA384,
    "hmac-sha512": dns.tsig.HMAC_SHA512,
}


def primary_ips(resolver, domain: str) -> list[str]:
    """SOA-primary (MNAME) IPs first, then the other authoritative servers."""
    mname, _ = zx.get_soa(resolver, domain)
    ips: list[str] = []
    if mname:
        host = mname.rstrip(".")
        for rtype in ("A", "AAAA"):
            try:
                ips.extend(r.to_text() for r in resolver.resolve(host, rtype))
            except Exception:
                continue
    for ip in dc.resolve_auth_servers(resolver, domain):
        if ip not in ips:
            ips.append(ip)
    return ips


def test_name(zone: str) -> str:
    return f"ptsrv-dynupd-{secrets.token_hex(4)}.{zone.rstrip('.')}"


def parse_tsig(spec: str):
    """Parse ``name:secret`` or ``name:alg:secret`` into (keyring, keyname, algorithm)."""
    parts = spec.split(":")
    if len(parts) == 2:
        name, secret = parts
        alg = "hmac-sha256"
    elif len(parts) == 3:
        name, alg, secret = parts
    else:
        raise ValueError("expected name:secret or name:algorithm:secret")
    alg = alg.lower()
    if alg not in _TSIG_ALGS:
        raise ValueError(f"unknown TSIG algorithm '{alg}' (use one of: {', '.join(_TSIG_ALGS)})")
    keyring = dns.tsigkeyring.from_text({name: secret})
    return keyring, name, _TSIG_ALGS[alg]


def _send(msg, ip: str, timeout: float):
    try:
        return dns.query.tcp(msg, ip, timeout=timeout)
    except Exception:
        try:
            return dns.query.udp(msg, ip, timeout=timeout)
        except Exception:
            return None


def _update_msg(zone: str, tsig=None):
    if tsig is not None:
        keyring, keyname, alg = tsig
        return dns.update.UpdateMessage(zone, keyring=keyring, keyname=keyname, keyalgorithm=alg)
    return dns.update.UpdateMessage(zone)


def add_txt(ip: str, zone: str, name: str, tsig=None, timeout: float = DEFAULT_TIMEOUT) -> int | None:
    """Send an UPDATE adding a benign TXT record; return the response rcode (or None)."""
    upd = _update_msg(zone, tsig)
    upd.add(name, 60, "TXT", TEST_TXT)
    resp = _send(upd, ip, timeout)
    return resp.rcode() if resp is not None else None


def delete_name(ip: str, zone: str, name: str, tsig=None, timeout: float = DEFAULT_TIMEOUT) -> int | None:
    """Send an UPDATE deleting *name* (cleanup); return the response rcode (or None)."""
    upd = _update_msg(zone, tsig)
    upd.delete(name)
    resp = _send(upd, ip, timeout)
    return resp.rcode() if resp is not None else None


def verify_present(ip: str, name: str, timeout: float = DEFAULT_TIMEOUT) -> bool:
    """Query *name* TXT directly at *ip* and report whether our test record is there."""
    q = dns.message.make_query(name, dns.rdatatype.TXT)
    try:
        resp = dns.query.udp(q, ip, timeout=timeout)
    except Exception:
        return False
    return any(TEST_TXT in it.to_text() for rr in resp.answer if rr.rdtype == dns.rdatatype.TXT for it in rr.items)


def prereq_probe(ip: str, zone: str, timeout: float = DEFAULT_TIMEOUT) -> int | None:
    """Send a PREREQUISITE-ONLY update (no changes) to reveal whether auth is enforced."""
    upd = _update_msg(zone)
    upd.present(zone)  # prerequisite: the zone apex is in use — makes no modification
    resp = _send(upd, ip, timeout)
    return resp.rcode() if resp is not None else None