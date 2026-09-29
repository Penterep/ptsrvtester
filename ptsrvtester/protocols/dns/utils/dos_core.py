"""Amplification / DoS probe logic for the DNS modules.

Only the safe, bounded, remotely-observable checks live here:

* amplification factor of the server's own answers (ANY / DNSKEY / large TXT);
* Response Rate Limiting detection via a small bounded burst of identical
  queries (opt-in, active but not a flood);
* truncation (TC) + TCP-fallback correctness.

Water-torture / random-subdomain flooding (an actual capacity DoS) and
NXNSAttack (needs a controlled malicious delegation) are intentionally NOT here
— deferred to a future probe server; NXNSAttack is version-covered by the CVE
module.
"""
from __future__ import annotations

import select
import socket
import time
from dataclasses import dataclass

import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

DEFAULT_TIMEOUT = 5.0


@dataclass
class AmpMeasure:
    rtype: str
    request_size: int
    response_size: int
    factor: float
    answered: bool
    minimized: bool = False


def amplification_factors(servers: list[str], name: str, timeout: float = DEFAULT_TIMEOUT) -> list[AmpMeasure]:
    """Measure response/query byte ratio for ANY, DNSKEY and TXT against the first server."""
    out: list[AmpMeasure] = []
    for rtype_name in ("ANY", "DNSKEY", "TXT"):
        rdtype = dns.rdatatype.from_text(rtype_name)
        query = dns.message.make_query(name, rdtype, want_dnssec=True, payload=4096)
        req = len(query.to_wire())
        resp = None
        for ip in servers:
            try:
                resp = dns.query.udp(query, ip, timeout=timeout)
                break
            except Exception:
                continue
        if resp is None:
            continue
        size = len(resp.to_wire())
        answered = resp.rcode() == dns.rcode.NOERROR and len(resp.answer) > 0
        minimized = rtype_name == "ANY" and size < 256
        out.append(AmpMeasure(rtype_name, req, size, round(size / req, 1) if req else 0.0, answered, minimized))
    return out


def best_factor(measures: list[AmpMeasure]) -> AmpMeasure | None:
    answered = [m for m in measures if m.answered]
    return max(answered, key=lambda m: m.factor) if answered else None


@dataclass
class RrlResult:
    sent: int
    received: int
    truncated: int
    rrl_detected: bool
    error: str | None = None


def rrl_probe(ip: str, name: str, count: int = 100, deadline: float = 3.0) -> RrlResult:
    """Fire a bounded burst of identical queries; RRL shows up as drops or TC-slip responses.

    Sends *count* identical (qname/qtype) queries with random IDs from one socket,
    then collects replies until *deadline*. Fewer replies than sent, or truncated
    (slip) replies, indicate Response Rate Limiting.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError as e:
        return RrlResult(0, 0, 0, False, error=str(e))
    sock.setblocking(False)
    sent = 0
    try:
        for _ in range(count):
            q = dns.message.make_query(name, dns.rdatatype.A)
            try:
                sock.sendto(q.to_wire(), (ip, 53))
                sent += 1
            except OSError:
                break

        received = truncated = 0
        end = time.time() + deadline
        while time.time() < end and received < sent:
            remaining = end - time.time()
            r, _, _ = select.select([sock], [], [], max(0.0, remaining))
            if not r:
                break
            try:
                data, _ = sock.recvfrom(4096)
            except OSError:
                break
            try:
                msg = dns.message.from_wire(data)
            except Exception:
                continue
            received += 1
            if msg.flags & dns.flags.TC:
                truncated += 1
    finally:
        sock.close()

    rrl = sent > 0 and (received < sent * 0.8 or truncated > 0)
    return RrlResult(sent, received, truncated, rrl)


@dataclass
class TcpFallbackResult:
    udp_truncated: bool | None = None
    udp_size: int | None = None
    tcp_ok: bool | None = None
    tcp_error: str | None = None


def tcp_fallback(ip: str, name: str, timeout: float = DEFAULT_TIMEOUT) -> TcpFallbackResult:
    """Check TC behaviour (bufsize 512 on a large record) and that TCP queries work."""
    result = TcpFallbackResult()

    big = dns.message.make_query(name, dns.rdatatype.DNSKEY, want_dnssec=True, payload=512)
    try:
        ru = dns.query.udp(big, ip, timeout=timeout)
        result.udp_size = len(ru.to_wire())
        result.udp_truncated = bool(ru.flags & dns.flags.TC)
    except Exception:
        pass

    try:
        rt = dns.query.tcp(dns.message.make_query(name, dns.rdatatype.SOA), ip, timeout=timeout)
        result.tcp_ok = rt.rcode() in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN)
    except Exception as e:
        result.tcp_ok = False
        result.tcp_error = f"{type(e).__name__}: {e}"
    return result