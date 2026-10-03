"""DOQ — DNS over QUIC (853/udp, RFC 9250): availability.

Attempts a DoQ query over QUIC. QUIC mandates TLS 1.3, so availability implies a
modern encrypted transport. Needs the optional ``aioquic`` package; without it
the test reports "not tested". Detailed certificate extraction over QUIC is
limited, so this focuses on availability (the DoT/DoH tests cover TLS/cert
detail).
"""
from ptsrvtester.protocols.dns.utils import transport_tls_core as tt

import dns
import dns.message
import dns.query
import dns.rdatatype

__MODULELABEL__ = "DNS over QUIC (DoQ, 853)"
__MODULECODE__ = "DOQ"
__ORDER__ = 920


def run(ctx):
    ip = getattr(ctx, "ip", None)
    if not ip:
        ctx.out("This test needs a target DNS server; pass -tg <server> (ideally a hostname).", "WARNING", indent=4)
        return
    host = getattr(ctx, "host", None) or ip

    have_quic = getattr(getattr(dns, "quic", None), "have_quic", False)
    if not have_quic:
        ctx.out("DoQ not tested — the optional 'aioquic' package is not installed.", "WARNING", indent=4)
        with ctx.results_lock:
            ctx.properties["doq"] = "not tested (aioquic missing)"
        return

    try:
        dns.query.quic(dns.message.make_query("example.com", dns.rdatatype.A),
                       ip, port=853, timeout=6, server_hostname=host)
        ctx.out("DoQ/853 available — DNS over QUIC answers (QUIC mandates TLS 1.3).", "OK", indent=4)
        if tt.is_ip(host):
            ctx.out("Target is an IP address — pass the full hostname (-tg <fqdn>) to validate the "
                    "certificate name.", "ADDITIONS", colortext=True, indent=8)
        with ctx.results_lock:
            ctx.properties["doq"] = "available (TLS 1.3 / QUIC)"
    except Exception as e:
        ctx.out(f"DoQ/853 not available ({type(e).__name__}).", "TITLE", indent=4)
        with ctx.results_lock:
            ctx.properties["doq"] = "unavailable"