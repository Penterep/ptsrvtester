"""WILDCARD — detect wildcard records that mask enumeration.

Queries random non-existent labels under each domain (-d/-dl); if they resolve,
the zone has a wildcard (``*``) record. A wildcard makes subdomain brute force
unreliable (everything "resolves") and can mask typosquatting/catch-all
behaviour — reported as a finding.
"""
from ptsrvtester.protocols.dns.utils import enum_core as ec
from ptsrvtester.protocols.dns.utils.helpers import text_or_file
from ptsrvtester.protocols.dns.utils.results import VULNS

__MODULELABEL__ = "Wildcard record detection"
__MODULECODE__ = "WILDCARD"
__ORDER__ = 160


def run(ctx):
    domains = [d.strip() for d in text_or_file(ctx.args.domain, ctx.args.domain_file) if d.strip()]
    if not domains:
        ctx.out("This test needs a domain; pass -d <domain> or -dl <file>.", "WARNING", indent=4)
        return

    resolver = ec.resolver_for(ctx)
    summary: dict[str, dict] = {}

    for domain in domains:
        ctx.out(domain, "INFO", colortext=True, indent=4)
        wc = ec.wildcard_detect(resolver, domain)
        if not wc.present:
            ctx.out("No wildcard record (random labels do not resolve).", "OK", indent=8)
            summary[domain] = {"wildcard": False}
            continue

        if wc.a:
            ctx.out(f"Wildcard A     {', '.join(sorted(wc.a))}", "VULN", indent=8)
        if wc.aaaa:
            ctx.out(f"Wildcard AAAA  {', '.join(sorted(wc.aaaa))}", "VULN", indent=8)
        if wc.cname:
            ctx.out(f"Wildcard CNAME {', '.join(sorted(wc.cname))}", "VULN", indent=8)
        ctx.out(f"Wildcard present (probe {wc.sample}); it masks subdomain enumeration.", "VULN", indent=8)

        summary[domain] = {"wildcard": True, "a": sorted(wc.a), "aaaa": sorted(wc.aaaa), "cname": sorted(wc.cname)}
        with ctx.results_lock:
            ctx.deferred_vulns.append({
                "vuln_code": VULNS.Wildcard.value,
                "vuln_request": f"random-label probe under {domain}",
                "vuln_response": ", ".join(sorted(wc.a | wc.aaaa | wc.cname)) or "resolves",
            })

    with ctx.results_lock:
        ctx.properties["wildcard"] = summary
