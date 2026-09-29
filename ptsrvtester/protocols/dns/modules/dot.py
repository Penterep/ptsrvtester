"""DOT — DNS over TLS (853): availability, TLS version/cipher, certificate.

Handshakes to the server on 853, reports the negotiated TLS version and cipher,
and the certificate (issuer, expiry, SAN, validity), then confirms it actually
answers DNS over TLS. Weak TLS (< 1.2) → PTV-DNS-WEAKTLS; an invalid/expired/
name-mismatched certificate → PTV-DNS-TLSCERT. Verification needs a hostname
target (-tg <fqdn>).
"""
from ptsrvtester.protocols.dns.utils import transport_tls_core as tt

import dns.message
import dns.query
import dns.rdatatype

__MODULELABEL__ = "DNS over TLS (DoT, 853)"
__MODULECODE__ = "DOT"
__ORDER__ = 900


def run(ctx):
    ip = getattr(ctx, "ip", None)
    if not ip:
        ctx.out("This test needs a target DNS server; pass -tg <server> (ideally a hostname).", "WARNING", indent=4)
        return
    host = getattr(ctx, "host", None) or ip

    probe = tt.tls_probe(ip, 853, host, alpn=["dot"])
    if not probe.connected:
        ctx.out(f"DoT/853 not available ({probe.error}).", "TEXT", indent=4)
        with ctx.results_lock:
            ctx.properties["dot"] = "unavailable"
        return

    ctx.out(f"DoT/853 available — {probe.tls_version}, {probe.cipher} ({probe.cipher_bits}-bit)"
            + (f", ALPN {probe.alpn}" if probe.alpn else ""), "OK", indent=4)

    try:
        dns.query.tls(dns.message.make_query(host if "." in host else "example.com", dns.rdatatype.A),
                      ip, port=853, timeout=6, server_hostname=host)
        ctx.out("Confirmed: answers DNS over TLS.", "OK", indent=4)
    except Exception as e:
        ctx.out(f"TLS handshake works but DNS-over-TLS query failed: {type(e).__name__}", "WARNING", indent=4)

    tt.report_tls(ctx, "DoT", host, probe)
    with ctx.results_lock:
        ctx.properties["dot"] = f"{probe.tls_version}, cert {'valid' if probe.verify_ok else 'invalid'}"
