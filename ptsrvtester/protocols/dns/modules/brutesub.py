"""BRUTESUB — subdomain enumeration from a wordlist.

Resolves ``<label>.<domain>`` for each label in -sub against the domain(s) from
-d/-dl. Detects a wildcard first and filters answers that match the wildcard
baseline so catch-all zones do not produce false hits. Discovered subdomains
are reported as a finding (attack surface). Active/opt-in — only when named in
-ts.
"""
from ptsrvtester.protocols.dns.utils import enum_core as ec
from ptsrvtester.protocols.dns.utils.helpers import text_or_file
from ptsrvtester.protocols.dns.utils.results import VULNS

__MODULELABEL__ = "Subdomain brute-force enumeration"
__MODULECODE__ = "BRUTESUB"
__ORDER__ = 130
__RUN_IN_ALL__ = False   # needs -sub and is active enumeration: only when named in -ts


def run(ctx):
    domains = [d.strip() for d in text_or_file(ctx.args.domain, ctx.args.domain_file) if d.strip()]
    if not domains:
        ctx.out("This test needs a domain; pass -d <domain> or -dl <file>.", "WARNING", indent=4)
        return
    if not getattr(ctx.args, "subdomains", None):
        ctx.out("This test needs a wordlist; pass -sub <wordlist>.", "WARNING", indent=4)
        return

    labels = [l.strip() for l in text_or_file(None, ctx.args.subdomains) if l.strip()]
    if not labels:
        ctx.out("Subdomain wordlist is empty.", "WARNING", indent=4)
        return

    resolver = ec.resolver_for(ctx)
    threads = getattr(ctx.args, "threads", 10) or 10
    discovered: dict[str, list[str]] = {}

    for domain in domains:
        ctx.out(domain, "INFO", colortext=True, indent=4)
        wildcard = ec.wildcard_detect(resolver, domain)
        if wildcard.present:
            baseline = ", ".join(sorted(wildcard.a | wildcard.aaaa | wildcard.cname)) or "?"
            ctx.out(f"Wildcard detected ({baseline}); matching hits are filtered out.", "WARNING", indent=8)

        found, filtered = ec.brute_subdomains(resolver, domain, labels, threads, wildcard)
        for fqdn, recs in found:
            summary = ", ".join(f"{rt}={','.join(v)}" for rt, v in recs.items() if v)
            ctx.out(f"{fqdn:<45} {summary}", "OK", indent=8)
        note = f" ({filtered} wildcard hits filtered)" if filtered else ""
        ctx.out(f"Found {len(found)} subdomain(s) from {len(labels)} label(s){note}.", "INFO", colortext=True, indent=8)
        if found:
            discovered[domain] = [f for f, _ in found]

    if not discovered:
        return
    with ctx.results_lock:
        ctx.properties["subdomains"] = discovered
        flat = [s for subs in discovered.values() for s in subs]
        ctx.deferred_vulns.append({
            "vuln_code": VULNS.Subdomains.value,
            "vuln_request": "Subdomain brute force (-sub wordlist)",
            "vuln_response": ", ".join(flat),
        })
