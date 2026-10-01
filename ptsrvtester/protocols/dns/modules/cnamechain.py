"""CNAMECHAIN — excessive or looping CNAME chains.

Follows the CNAME chain for the name (and any -sub labels). A loop (a name
recurs) or an over-long chain wastes resolver work and can break resolution or
enable DoS (PTV-DNS-CNAMECHAIN).
"""
from ptsrvtester.protocols.dns.utils import enum_core as ec
from ptsrvtester.protocols.dns.utils import integrity_core as ig
from ptsrvtester.protocols.dns.utils.helpers import text_or_file
from ptsrvtester.protocols.dns.utils.results import VULNS

__MODULELABEL__ = "CNAME chain / loops"
__MODULECODE__ = "CNAMECHAIN"
__ORDER__ = 1020

# A well-behaved chain is 0-1 hops; more than this is flagged as excessive.
CHAIN_WARN = 8


def run(ctx):
    domains = [d.strip() for d in text_or_file(ctx.args.domain, ctx.args.domain_file) if d.strip()]
    if not domains:
        ctx.out("This test needs a domain; pass -d <domain> or -dl <file>.", "WARNING", indent=4)
        return

    labels = []
    if getattr(ctx.args, "subdomains", None):
        labels = [l.strip() for l in text_or_file(None, ctx.args.subdomains) if l.strip()]

    resolver = ec.resolver_for(ctx)

    for domain in domains:
        ctx.out(domain, "INFO", colortext=True, indent=4)
        names = [domain] + [f"{l}.{domain.rstrip('.')}" for l in labels]
        any_cname = False
        for name in names:
            res = ig.cname_chain(resolver, name)
            hops = len(res.chain) - 1
            if hops == 0:
                continue
            any_cname = True
            arrow = " → ".join(res.chain)
            if res.loop:
                ctx.out(f"CNAME LOOP: {arrow}", "VULN", indent=8)
                _finding(ctx, name, "loop", arrow)
            elif res.truncated or hops > CHAIN_WARN:
                ctx.out(f"Excessive CNAME chain ({hops} hops{'+' if res.truncated else ''}): {arrow}", "VULN", indent=8)
                _finding(ctx, name, f"{hops} hops", arrow)
            else:
                ctx.out(f"CNAME chain ({hops} hop{'s' if hops != 1 else ''}): {arrow}", "TEXT", indent=8)
        if not any_cname:
            ctx.out("No CNAME records among the checked names — nothing to follow.", "OK", indent=8)


def _finding(ctx, name, kind, arrow):
    with ctx.results_lock:
        ctx.deferred_vulns.append({
            "vuln_code": VULNS.CnameChain.value,
            "vuln_request": f"CNAME chain of {name}",
            "vuln_response": f"{kind}: {arrow}",
        })