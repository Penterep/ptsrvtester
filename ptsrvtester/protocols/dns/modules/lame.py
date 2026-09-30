"""LAME — lame delegation (NS delegated but not authoritative).

For each NS the zone delegates to, queries that server directly (RD=0) for the
zone SOA. A properly delegated server answers authoritatively (AA=1); one that
does not respond, refuses, lacks an A/AAAA, or answers non-authoritatively is a
lame delegation (PTV-DNS-LAMEDELEGATION) — it weakens resilience and can aid
hijacking.
"""
from ptsrvtester.protocols.dns.utils import enum_core as ec
from ptsrvtester.protocols.dns.utils import integrity_core as ig
from ptsrvtester.protocols.dns.utils.helpers import text_or_file
from ptsrvtester.protocols.dns.utils.results import VULNS

__MODULELABEL__ = "Lame delegation"
__MODULECODE__ = "LAME"
__ORDER__ = 1010


def run(ctx):
    domains = [d.strip() for d in text_or_file(ctx.args.domain, ctx.args.domain_file) if d.strip()]
    if not domains:
        ctx.out("This test needs a domain; pass -d <domain> or -dl <file>.", "WARNING", indent=4)
        return

    resolver = ec.resolver_for(ctx)

    for domain in domains:
        ctx.out(domain, "INFO", colortext=True, indent=4)
        results = ig.lame_delegations(resolver, domain)
        if not results:
            ctx.out("No NS records found for the domain.", "WARNING", indent=8)
            continue

        lame = [r for r in results if not r.ok]
        for r in results:
            where = f" ({r.ip})" if r.ip else ""
            if r.ok:
                ctx.out(f"{r.ns}{where}: authoritative", "OK", indent=8)
            else:
                ctx.out(f"{r.ns}{where}: LAME — {r.status}", "VULN", indent=8)

        if lame:
            with ctx.results_lock:
                ctx.properties.setdefault("lame_delegation", {})[domain] = [f"{r.ns}: {r.status}" for r in lame]
                ctx.deferred_vulns.append({
                    "vuln_code": VULNS.LameDelegation.value,
                    "vuln_request": f"per-NS authoritative check (RD=0 SOA) for {domain}",
                    "vuln_response": "; ".join(f"{r.ns} ({r.status})" for r in lame),
                })
