"""DOH — DNS over HTTPS (443, /dns-query): availability, TLS, cert, HTTP/2.

A TLS handshake on 443 alone does NOT mean DoH — a normal HTTPS web application
also answers it. So DoH is only reported as available when the server actually
returns a DNS response to a DoH query at /dns-query. If 443 is reachable over
TLS but does not speak DoH, that is reported as a plain HTTPS service (not a
finding). For genuine DoH the TLS version/cipher, HTTP/2 and certificate are
assessed: weak TLS → PTV-DNS-WEAKTLS, invalid cert → PTV-DNS-TLSCERT. Certificate
validation needs a hostname target (-tg <fqdn>).
"""
from ptsrvtester.protocols.dns.utils import transport_tls_core as tt

import dns.message
import dns.query
import dns.rdatatype

__MODULELABEL__ = "DNS over HTTPS (DoH, 443)"
__MODULECODE__ = "DOH"
__ORDER__ = 910


def _doh_answers(host: str, timeout: float = 6.0) -> tuple[bool, str]:
    """True if /dns-query returns a parseable DNS response (genuine DoH).

    Any DNS message counts — even SERVFAIL — because that still proves the
    endpoint speaks DoH; a web app returns an HTTP error / non-DNS body, which
    makes dns.query.https raise.
    """
    url = f"https://{host}/dns-query"
    try:
        resp = dns.query.https(dns.message.make_query("example.com", dns.rdatatype.A), url, timeout=timeout)
        return isinstance(resp, dns.message.Message), ""
    except Exception as e:
        return False, f"{type(e).__name__}"


def run(ctx):
    ip = getattr(ctx, "ip", None)
    if not ip:
        ctx.out("This test needs a target DNS server; pass -tg <server> (ideally a hostname).", "WARNING", indent=4)
        return
    host = getattr(ctx, "host", None) or ip

    probe = tt.tls_probe(ip, 443, host, alpn=["h2", "http/1.1"])
    if not probe.connected:
        ctx.out(f"DoH/443 not available — no TLS service on port 443 ({probe.error}).", "TITLE", indent=4)
        with ctx.results_lock:
            ctx.properties["doh"] = "unavailable"
        return

    # Port 443 has TLS — confirm it actually speaks DoH before calling it available.
    doh_ok, err = _doh_answers(host)
    if not doh_ok:
        ctx.out(f"Port 443 serves HTTPS but NOT DoH — https://{host}/dns-query did not return a DNS "
                f"response ({err or 'no DNS answer'}); likely a web application.", "TITLE", indent=4)
        with ctx.results_lock:
            ctx.properties["doh"] = "no (HTTPS web service on 443, not DoH)"
        return

    http2 = probe.alpn == "h2"
    ctx.out(f"DoH/443 available — answers DNS over HTTPS at /dns-query; {probe.tls_version}, "
            f"{probe.cipher} ({probe.cipher_bits}-bit); HTTP/2: "
            f"{'yes' if http2 else 'no (' + str(probe.alpn or 'HTTP/1.1') + ')'}", "OK", indent=4)

    tt.report_tls(ctx, "DoH", host, probe)
    with ctx.results_lock:
        ctx.properties["doh"] = f"{probe.tls_version}, HTTP/2 {'yes' if http2 else 'no'}, cert {'valid' if probe.verify_ok else 'invalid'}"