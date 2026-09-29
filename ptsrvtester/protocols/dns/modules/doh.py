"""DOH — DNS over HTTPS (443, /dns-query): availability, TLS, cert, HTTP/2.

Handshakes to the server on 443 (offering ALPN h2/http1.1) to report the TLS
version/cipher, whether HTTP/2 is negotiated, and the certificate; then confirms
it answers DNS over HTTPS at /dns-query. Weak TLS → PTV-DNS-WEAKTLS; invalid
certificate → PTV-DNS-TLSCERT. Verification needs a hostname target (-tg <fqdn>).
"""
from ptsrvtester.protocols.dns.utils import transport_tls_core as tt

import dns.message
import dns.query
import dns.rdatatype

__MODULELABEL__ = "DNS over HTTPS (DoH, 443)"
__MODULECODE__ = "DOH"
__ORDER__ = 910


def run(ctx):
    ip = getattr(ctx, "ip", None)
    if not ip:
        ctx.out("This test needs a target DNS server; pass -tg <server> (ideally a hostname).", "WARNING", indent=4)
        return
    host = getattr(ctx, "host", None) or ip

    probe = tt.tls_probe(ip, 443, host, alpn=["h2", "http/1.1"])
    if not probe.connected:
        ctx.out(f"DoH/443 not available ({probe.error}).", "TEXT", indent=4)
        with ctx.results_lock:
            ctx.properties["doh"] = "unavailable"
        return

    http2 = probe.alpn == "h2"
    ctx.out(f"DoH/443 available — {probe.tls_version}, {probe.cipher} ({probe.cipher_bits}-bit); "
            f"HTTP/2: {'yes' if http2 else 'no (' + str(probe.alpn or 'HTTP/1.1') + ')'}", "OK", indent=4)

    url = f"https://{host}/dns-query"
    try:
        dns.query.https(dns.message.make_query("example.com", dns.rdatatype.A), url, timeout=6)
        ctx.out(f"Confirmed: answers DNS over HTTPS at {url}.", "OK", indent=4)
    except Exception as e:
        ctx.out(f"TLS works but DoH query to /dns-query failed: {type(e).__name__}", "WARNING", indent=4)

    tt.report_tls(ctx, "DoH", host, probe)
    with ctx.results_lock:
        ctx.properties["doh"] = f"{probe.tls_version}, HTTP/2 {'yes' if http2 else 'no'}, cert {'valid' if probe.verify_ok else 'invalid'}"
