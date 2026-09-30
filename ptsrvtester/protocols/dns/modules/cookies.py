"""COOKIES — DNS Cookies (RFC 7873) support.

Sends an EDNS query with a client cookie and checks whether the server returns a
full server cookie. DNS cookies are a lightweight defence against off-path
spoofing and amplification. Absence is reported as PTV-DNS-NOCOOKIE (a hardening
gap). Note: this observes the CLIENT-facing side; a recursive resolver that does
not offer cookies to clients may still use them upstream toward authoritative
servers, which is not observable here.
"""
from ptsrvtester.protocols.dns.utils import poisoning_core as pc
from ptsrvtester.protocols.dns.utils.results import VULNS

__MODULELABEL__ = "DNS cookies (RFC 7873)"
__MODULECODE__ = "COOKIES"
__ORDER__ = 430


def run(ctx):
    ip = getattr(ctx, "ip", None)
    if not ip:
        ctx.out("This test needs a target DNS server; pass -tg <server>.", "WARNING", indent=4)
        return
    port = getattr(ctx, "port", None) or 53

    info = pc.cookie_probe(ip, port)
    if "error" in info:
        ctx.out(f"Cookie probe failed: {info['error']}", "WARNING", indent=4)
        return

    if info.get("server_cookie"):
        ctx.out(f"DNS cookies supported — server cookie returned ({info['length']} bytes).", "OK", indent=4)
        with ctx.results_lock:
            ctx.properties["dns_cookies"] = "supported"
        return

    if info.get("present"):
        ctx.out(f"Only the client cookie was echoed ({info['length']} bytes) — no server cookie.", "VULN", indent=4)
    else:
        ctx.out("Server did not return a DNS cookie (no client-facing cookie protection).", "VULN", indent=4)
    ctx.out("Upstream cookie use toward authoritative servers is separate and not observable here.", "TEXT", indent=4)

    with ctx.results_lock:
        ctx.properties["dns_cookies"] = "not supported (client-facing)"
        ctx.deferred_vulns.append({
            "vuln_code": VULNS.NoCookie.value,
            "vuln_request": "EDNS COOKIE (8-byte client cookie)",
            "vuln_response": "no server cookie returned",
        })