"""AXFR — full zone transfer from the domain's name servers.

Discovers the authoritative name servers for each domain (-d/-dl) and attempts a
full AXFR against every one of them over TCP — primaries and secondaries alike.
A server that answers leaks the entire zone (PTV-DNS-ZONETRANSFER). Because it
tries every NS, it also catches a misconfigured secondary that allows AXFR even
when the primary refuses. If -tg names a specific server, that server is tried
too (e.g. a suspected secondary).
"""
from ptsrvtester.protocols.dns.utils import enum_core as ec
from ptsrvtester.protocols.dns.utils import zonexfer_core as zc
from ptsrvtester.protocols.dns.utils.helpers import text_or_file
from ptsrvtester.protocols.dns.utils.results import VULNS

__MODULELABEL__ = "Zone transfer (AXFR)"
__MODULECODE__ = "AXFR"
__ORDER__ = 200


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
        servers, primary, _ = zc.transfer_targets(resolver, domain, extra)
        if not servers:
            ctx.out("No NS records found for the domain (cannot try AXFR).", "WARNING", indent=8)
            continue

        for ns in servers:
            role = "primary" if ns.is_primary else "secondary"
            if not ns.ips:
                ctx.out(f"{ns.host.rstrip('.'):<32} [{role}] no A/AAAA — skipped", "TITLE", indent=8)
                continue
            for ip in ns.ips:
                res = zc.try_axfr(ip, domain, ns.host, ns.is_primary)
                if res.allowed:
                    ctx.out(f"{res.server} [{role}] AXFR ALLOWED — {res.record_count} records", "VULN", indent=8)
                    for name in res.sample:
                        ctx.out(f"    {name}", "TEXT", indent=8)
                    if res.record_count and res.record_count > len(res.sample):
                        ctx.out(f"    … (+{res.record_count - len(res.sample)} more)", "TEXT", indent=8)
                    exposed.append(f"{domain}@{res.server}[{role}]")
                else:
                    ctx.out(f"{res.server} [{role}] refused ({res.error})", "OK", indent=8)

    if not exposed:
        return

    if any("[secondary]" in e for e in exposed):
        ctx.out("A secondary name server allows AXFR (misconfigured mirror).", "VULN", indent=4)

    with ctx.results_lock:
        ctx.properties["axfr_allowed"] = exposed
        ctx.deferred_vulns.append({
            "vuln_code": VULNS.ZoneTransfer.value,
            "vuln_request": "AXFR (full zone transfer) over TCP",
            "vuln_response": "; ".join(exposed),
        })