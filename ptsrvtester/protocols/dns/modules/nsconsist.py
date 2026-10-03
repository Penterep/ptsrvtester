"""NSCONSIST — NS/SOA consistency across the zone's name servers.

Queries each authoritative NS directly for the zone SOA serial and NS set and
compares them. Differing SOA serials (some servers stale / not replicating) or
differing NS sets (delegation mismatch), or servers that do not answer, mean the
zone is served inconsistently (PTV-DNS-NSINCONSISTENT).
"""
from ptsrvtester.protocols.dns.utils import enum_core as ec
from ptsrvtester.protocols.dns.utils import integrity_core as ig
from ptsrvtester.protocols.dns.utils.helpers import text_or_file
from ptsrvtester.protocols.dns.utils.results import VULNS

__MODULELABEL__ = "NS / SOA consistency"
__MODULECODE__ = "NSCONSIST"
__ORDER__ = 1030


def run(ctx):
    domains = [d.strip() for d in text_or_file(ctx.args.domain, ctx.args.domain_file) if d.strip()]
    if not domains:
        ctx.out("This test needs a domain; pass -d <domain> or -dl <file>.", "WARNING", indent=4)
        return

    resolver = ec.resolver_for(ctx)

    for domain in domains:
        ctx.out(domain, "INFO", colortext=True, indent=4)
        views, consistent, notes = ig.ns_consistency(resolver, domain)
        if not views:
            ctx.out("No NS records found for the domain.", "WARNING", indent=8)
            continue

        for v in views:
            if not v.reachable:
                ctx.out(f"{v.ns}: no answer", "WARNING", indent=8)
            else:
                ctx.out(f"{v.ns}: SOA serial {v.serial}, {len(v.ns_set)} NS records", "TITLE", indent=8)

        if consistent:
            ctx.out("All name servers agree on SOA serial and NS set.", "OK", indent=8)
            with ctx.results_lock:
                ctx.properties.setdefault("ns_consistency", {})[domain] = "consistent"
            continue

        for n in notes:
            ctx.out(n, "VULN", indent=8)
        with ctx.results_lock:
            ctx.properties.setdefault("ns_consistency", {})[domain] = notes
            ctx.deferred_vulns.append({
                "vuln_code": VULNS.NsInconsistent.value,
                "vuln_request": f"per-NS SOA/NS comparison for {domain}",
                "vuln_response": "; ".join(notes),
            })