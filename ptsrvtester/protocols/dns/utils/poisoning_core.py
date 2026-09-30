"""Cache-poisoning / spoofing-resilience probe logic for the DNS modules.

Only the checks that can be performed reliably from a plain remote client live
here — currently DNS cookies (RFC 7873).

The other anti-spoofing properties (source-port randomization, TXID entropy,
0x20 case randomization, out-of-bailiwick acceptance, SAD DNS) describe the
resolver's OUTBOUND behaviour and can only be measured by being / controlling
the authoritative server it queries. Those tests are deferred until an embedded
authoritative probe server is implemented; they were removed rather than shipped
as inconclusive remote checks.
"""
from __future__ import annotations

import os

import dns.edns
import dns.flags
import dns.message
import dns.query
import dns.rdatatype

DEFAULT_TIMEOUT = 5.0


def cookie_probe(ip: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """Send an EDNS query with an 8-byte client cookie; report the server's COOKIE echo.

    ``server_cookie`` True means the server returned a full client+server cookie
    (>=16 bytes) — RFC 7873 support that hardens against off-path spoofing.
    """
    query = dns.message.make_query("example.com", dns.rdatatype.A)
    query.flags |= dns.flags.RD
    query.use_edns(0, payload=4096, options=[dns.edns.GenericOption(dns.edns.OptionType.COOKIE, os.urandom(8))])
    try:
        resp = dns.query.udp(query, ip, port=port, timeout=timeout)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}
    for opt in resp.options:
        if int(opt.otype) == int(dns.edns.OptionType.COOKIE):
            length = len(opt.to_wire())
            return {"present": True, "length": length, "server_cookie": length >= 16}
    return {"present": False, "length": 0, "server_cookie": False}
