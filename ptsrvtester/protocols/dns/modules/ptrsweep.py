"""PTRSWEEP — reverse DNS (PTR) sweep of an address range.

Reverse-resolves every address in -r/--range (single IP, CIDR or start-end).
Discloses internal naming conventions and live hosts. Active (one query per
address, capped) — opt-in, only when named in -ts.
"""
from ptsrvtester.protocols.dns.utils import enum_core as ec

__MODULELABEL__ = "Reverse DNS / PTR sweep"
__MODULECODE__ = "PTRSWEEP"
__ORDER__ = 110
__RUN_IN_ALL__ = False


def run(ctx):
    spec = getattr(ctx.args, "ip_range", None)
    if not spec:
        ctx.out("This test needs an address range; pass -r <IP|CIDR|start-end>.", "WARNING", indent=4)
        return

    try:
        addrs, note = ec.parse_range(spec)
    except ValueError as e:
        ctx.out(f"Invalid range '{spec}': {e}", "ERROR", indent=4)
        return
    if note:
        ctx.out(note, "WARNING", indent=4)

    resolver = ec.resolver_for(ctx)
    threads = getattr(ctx.args, "threads", 10) or 10
    results = ec.ptr_sweep(resolver, addrs, threads)

    if not results:
        ctx.out(f"No PTR records found across {len(addrs)} address(es).", "OK", indent=4)
        return

    for ip in sorted(results, key=lambda x: tuple(int(p) for p in x.split(".")) if x.count(".") == 3 else x):
        ctx.out(f"{ip:<18} {', '.join(results[ip])}", "TITLE", indent=4)
    ctx.out(f"{len(results)} of {len(addrs)} address(es) have a PTR record.", "INFO", colortext=True, indent=4)

    with ctx.results_lock:
        ctx.properties["ptr_sweep"] = {ip: names for ip, names in results.items()}
