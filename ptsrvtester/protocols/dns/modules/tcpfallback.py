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
    ctx.debug(f"checking UDP truncation (TC bit) and TCP/53 fallback for {len(domains)} domain(s)")

    for domain in domains:
        ctx.out(domain, "INFO", colortext=True, indent=4)
        ctx.debug(f"Resolving authoritative servers for {domain}")
        servers = dc.servers_for(resolver, domain, getattr(ctx, "ip", None))
        if not servers:
            ctx.out("Could not find authoritative servers for the domain.", "WARNING", indent=8)
            continue

        ctx.debug(f"Send a 512-byte-buffer UDP query + TCP/53 retry to {servers[0]}")
        res = dos.tcp_fallback(servers[0], domain)
        ctx.debug(f"Response: UDP TC={res.udp_truncated}, TCP ok={res.tcp_ok}")

        if res.udp_truncated is True:
            ctx.out(f"UDP (bufsize 512): TC set — server truncates large responses correctly.", "OK", indent=8)
        elif res.udp_truncated is False:
            ctx.out(f"UDP (bufsize 512): no TC (response {res.udp_size} B fit, or record small — inconclusive).", "WARNING", indent=8)
        else:
            ctx.out("UDP truncation probe got no response.", "WARNING", indent=8)

        if res.tcp_ok:
            ctx.out("TCP/53 answers — TCP fallback works.", "OK", indent=8)
        else:
            ctx.out(f"TCP/53 does NOT answer ({res.tcp_error or 'no reply'}) — large answers & DNSSEC break, "
                    "and UDP-only is more amplifiable.", "VULN", indent=8)
            with ctx.results_lock:
                ctx.deferred_vulns.append({"vuln_code": VULNS.TcpFallback.value})