"""RECURSION — open recursion for external clients.

Sends RD=1 queries for several names the server is not authoritative for. If it
sets RA and returns answers, it is an open resolver: it recurses for arbitrary
external clients (PTV-DNS-OPENRECURSION), which enables cache poisoning targeting
and reflection/amplification abuse (quantified by the AMPLIFICATION test).
"""
from ptsrvtester.protocols.dns.utils import recursion_core as rc
from ptsrvtester.protocols.dns.utils.results import VULNS

__MODULELABEL__ = "Open recursion for external clients"
__MODULECODE__ = "RECURSION"
__ORDER__ = 300


def run(ctx):
    ip = getattr(ctx, "ip", None)
    if not ip:
        ctx.out("This test needs a target DNS server; pass -tg <server>.", "WARNING", indent=4)
        return
    port = getattr(ctx, "port", None) or 53

    names = rc.probe_domains(ctx) or list(rc.EXTERNAL_NAMES)
    rc.resolve_guard(ctx, ip, port, names[0])
    is_open, probes = rc.open_recursion(ip, port, names)
    for p in probes:
        ra = "yes" if p.ra else "no"
        if p.answered and not p.authoritative:
            ctx.out(f"{p.name:<18} RA={ra:<3} recursed (rcode {p.rcode})", "VULN", indent=4)
        elif p.answered and p.authoritative:
            ctx.out(f"{p.name:<18} RA={ra:<3} authoritative in-zone answer (not recursion)", "TITLE", indent=4)
        elif p.answered is None:
            ctx.out(f"{p.name:<18} {p.rcode}", "TITLE", indent=4)
        else:
            ctx.out(f"{p.name:<18} RA={ra:<3} not resolved (rcode {p.rcode})", "TITLE", indent=4)

    if not is_open:
        ctx.out("Recursion is not open to this client (server does not resolve external names).", "OK", indent=4)
        with ctx.results_lock:
            ctx.properties["open_recursion"] = False
        return

    ctx.out("Open recursion: the server resolves arbitrary external names for this client.", "VULN", indent=4)
    with ctx.results_lock:
        ctx.properties["open_recursion"] = True
        ctx.deferred_vulns.append({
            "vuln_code": VULNS.OpenRecursion.value,
            "vuln_request": "RD=1 queries for external names (" + ", ".join(rc.EXTERNAL_NAMES[:3]) + ", …)",
            "vuln_response": "resolved: " + ", ".join(p.name for p in probes if p.answered),
        })
