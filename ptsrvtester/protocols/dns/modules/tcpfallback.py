"""TCPFALLBACK — truncation (TC bit) and TCP fallback correctness.

DNS must fall back to TCP when a response is too large for UDP: the server sets
the TC bit and the client retries over TCP/53. This checks that (a) a large
record queried with a 512-byte UDP buffer is truncated (TC set) and (b) TCP/53
actually answers. A broken TCP path (TCP/53 filtered) breaks large answers and
DNSSEC and forces UDP-only (more amplifiable) — PTV-DNS-TCPFALLBACK.
"""
from ptsrvtester.protocols.dns.utils import dnssec_core as dc
from ptsrvtester.protocols.dns.utils import dos_core as dos
from ptsrvtester.protocols.dns.utils import enum_core as ec
from ptsrvtester.protocols.dns.utils.helpers import text_or_file
from ptsrvtester.protocols.dns.utils.results import VULNS

__MODULELABEL__ = "Truncation (TC) & TCP fallback"
__MODULECODE__ = "TCPFALLBACK"
__ORDER__ = 720


def run(ctx):
    domains = [d.strip() for d in text_or_file(ctx.args.domain, ctx.args.domain_file) if d.strip()]
    if not domains:
        ctx.out("This test needs a domain; pass -d <domain> or -dl <file>.", "WARNING", indent=4)
        return

    resolver = ec.resolver_for(ctx)

    for domain in domains:
        ctx.out(domain, "INFO", colortext=True, indent=4)
        servers = dc.servers_for(resolver, domain, getattr(ctx, "ip", None))
        if not servers:
            ctx.out("Could not find authoritative servers for the domain.", "WARNING", indent=8)
            continue

        res = dos.tcp_fallback(servers[0], domain)

        if res.udp_truncated is True:
            ctx.out(f"UDP (bufsize 512): TC set — server truncates large responses correctly.", "OK", indent=8)
        elif res.udp_truncated is False:
            ctx.out(f"UDP (bufsize 512): no TC (response {res.udp_size} B fit, or record small — inconclusive).", "ADDITIONS", colortext=True, indent=8)
        else:
            ctx.out("UDP truncation probe got no response.", "WARNING", indent=8)

        if res.tcp_ok:
            ctx.out("TCP/53 answers — TCP fallback works.", "OK", indent=8)
            with ctx.results_lock:
                ctx.properties.setdefault("tcp_fallback", {})[domain] = "ok"
        else:
            ctx.out(f"TCP/53 does NOT answer ({res.tcp_error or 'no reply'}) — large answers & DNSSEC break, "
                    "and UDP-only is more amplifiable.", "VULN", indent=8)
            with ctx.results_lock:
                ctx.properties.setdefault("tcp_fallback", {})[domain] = "broken"
                ctx.deferred_vulns.append({
                    "vuln_code": VULNS.TcpFallback.value,
                    "vuln_request": f"SOA {domain} over TCP/53",
                    "vuln_response": res.tcp_error or "no reply over TCP",
                })