"""IXFR — incremental zone transfer from the domain's name servers.

Asks each authoritative name server for an incremental transfer (IXFR) of the
zone since serial-1. A server that answers leaks zone data
(PTV-DNS-IXFR); per RFC 1995 it may reply with a truly incremental delta or fall
back to a full AXFR-style zone — both are exposures, and the module reports
which it was. If -tg names a specific server, that server is tried too.
"""
from ptsrvtester.protocols.dns.utils import enum_core as ec
from ptsrvtester.protocols.dns.utils import zonexfer_core as zc
from ptsrvtester.protocols.dns.utils.helpers import text_or_file
from ptsrvtester.protocols.dns.utils.results import VULNS

__MODULELABEL__ = "Incremental zone transfer (IXFR)"
__MODULECODE__ = "IXFR"
__ORDER__ = 210


def run(ctx):
    domains = [d.strip() for d in text_or_file(ctx.args.domain, ctx.args.domain_file) if d.strip()]
    if not domains:
        ctx.out("This test needs a domain; pass -d <domain> or -dl <file>.", "WARNING", indent=4)
        return

    resolver = ec.resolver_for(ctx, timeout=zc.XFR_TIMEOUT)
    extra = (ctx.host, ctx.ip) if getattr(ctx, "ip", None) else None
    exposed: list[str] = []

    for domain in domains:
        ctx.out(domain, "INFO", colortext=True, indent=4)
        servers, primary, serial = zc.transfer_targets(resolver, domain, extra)
        if not servers:
            ctx.out("No NS records found for the domain (cannot try IXFR).", "WARNING", indent=8)
            continue
        since = (serial - 1) if serial and serial > 1 else 1

        for ns in servers:
            role = "primary" if ns.is_primary else "secondary"
            if not ns.ips:
                ctx.out(f"{ns.host.rstrip('.'):<32} [{role}] no A/AAAA — skipped", "TITLE", indent=8)
                continue
            for ip in ns.ips:
                res = zc.try_ixfr(ip, domain, ns.host, ns.is_primary, since)
                if res.allowed:
                    kind = "incremental delta" if res.incremental else "full AXFR-style fallback"
                    ctx.out(f"{res.server} [{role}] IXFR ALLOWED — {res.record_count} records ({kind})", "VULN", indent=8)
                    exposed.append(f"{domain}@{res.server}[{role}]")
                else:
                    ctx.out(f"{res.server} [{role}] refused ({res.error})", "OK", indent=8)

    if not exposed:
        return

    with ctx.results_lock:
        ctx.properties["ixfr_allowed"] = exposed
        ctx.deferred_vulns.append({
            "vuln_code": VULNS.IncrementalTransfer.value,
            "vuln_request": "IXFR (incremental zone transfer) over TCP",
            "vuln_response": "; ".join(exposed),
        })