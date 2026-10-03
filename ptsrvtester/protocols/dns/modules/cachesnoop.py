"""CACHESNOOP — cache snooping via non-recursive (RD=0) queries.

Sends RD=0 queries for popular external names. A server that answers such a
query from cache (instead of refusing/deferring) reveals which names its clients
have recently looked up (PTV-DNS-CACHESNOOP) — an information leak about user
behaviour. The remaining TTL hints at how recently the name was resolved.
"""
from ptsrvtester.protocols.dns.utils import recursion_core as rc
from ptsrvtester.protocols.dns.utils.results import VULNS

__MODULELABEL__ = "Cache snooping (non-recursive RD=0)"
__MODULECODE__ = "CACHESNOOP"
__ORDER__ = 320


def run(ctx):
    ip = getattr(ctx, "ip", None)
    if not ip:
        ctx.out("This test needs a target DNS server; pass -tg <server>.", "WARNING", indent=4)
        return
    port = getattr(ctx, "port", None) or 53

    names = rc.probe_domains(ctx) or list(rc.EXTERNAL_NAMES)
    rc.resolve_guard(ctx, ip, port, names[0])
    results = rc.cache_snoop(ip, port, names)
    cached = [r for r in results if r.cached]

    for r in results:
        if r.cached:
            ctx.out(f"{r.name:<18} in cache (TTL {r.ttl})", "VULN", indent=4)
        elif r.cached is None:
            ctx.out(f"{r.name:<18} {r.rcode}", "TITLE", indent=4)
        else:
            ctx.out(f"{r.name:<18} not cached / not disclosed (rcode {r.rcode})", "TITLE", indent=4)

    if not cached:
        ctx.out("No cache contents disclosed via RD=0 (cache snooping not possible here).", "OK", indent=4)
        with ctx.results_lock:
            ctx.properties["cache_snoop"] = False
        return

    ctx.out(f"Cache snooping possible: {len(cached)} name(s) answered from cache to a non-recursive query.", "VULN", indent=4)
    with ctx.results_lock:
        ctx.properties["cache_snoop"] = {r.name: r.ttl for r in cached}
        ctx.deferred_vulns.append({
            "vuln_code": VULNS.CacheSnoop.value,
            "vuln_request": "RD=0 (non-recursive) queries for popular names",
            "vuln_response": "cached: " + ", ".join(f"{r.name}(TTL {r.ttl})" for r in cached),
        })