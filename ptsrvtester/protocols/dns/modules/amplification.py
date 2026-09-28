"""AMPLIFICATION — out-of-zone recursion abusable for reflection/amplification.

Sends small RD=1 queries for out-of-zone names that yield large answers (TXT,
DNSKEY, ANY) and measures the response-to-query byte ratio. If the server
recurses for these (an open resolver) and the response is much larger than the
query, it can be abused as a DDoS reflector/amplifier (PTV-DNS-AMPLIFICATION):
an attacker spoofs a victim's source address and the big answers flood the
victim.
"""
from ptsrvtester.protocols.dns.utils import recursion_core as rc
from ptsrvtester.protocols.dns.utils.results import VULNS

__MODULELABEL__ = "Reflection / amplification potential"
__MODULECODE__ = "AMPLIFICATION"
__ORDER__ = 310

# Response must be at least this many times the query to call it amplification.
AMP_THRESHOLD = 4.0


def run(ctx):
    ip = getattr(ctx, "ip", None)
    if not ip:
        ctx.out("This test needs a target DNS server; pass -tg <server>.", "WARNING", indent=4)
        return
    port = getattr(ctx, "port", None) or 53

    results = rc.amplification(ip, port)
    if not results:
        ctx.out("No response to any amplification probe.", "OK", indent=4)
        return

    for r in results:
        if r.reflectable:
            state = "recursed"
        elif r.answered and r.authoritative:
            state = "authoritative in-zone"
        else:
            state = "not resolved"
        tc = ", truncated (TCP required)" if r.truncated else ""
        cat = "VULN" if (r.reflectable and r.factor >= AMP_THRESHOLD) else "TEXT"
        ctx.out(f"{r.name} {r.rtype:<6} {r.request_size}→{r.response_size} B  x{r.factor}  ({state}{tc})", cat, indent=4)

    best = rc.best_amplification(results)
    if best is None:
        ctx.out("Server does not resolve out-of-zone names — not usable as an amplifier.", "OK", indent=4)
        with ctx.results_lock:
            ctx.properties["amplification"] = "not out-of-zone recursive"
        return

    if best.factor < AMP_THRESHOLD:
        ctx.out(f"Resolves out-of-zone names but max amplification is low (x{best.factor}).", "WARNING", indent=4)
        with ctx.results_lock:
            ctx.properties["amplification"] = f"out-of-zone recursive, max x{best.factor}"
        return

    ctx.out(f"Usable as a reflector/amplifier: {best.name} {best.rtype} gives x{best.factor} "
            f"({best.request_size}→{best.response_size} B).", "VULN", indent=4)
    with ctx.results_lock:
        ctx.properties["amplification"] = f"x{best.factor} via {best.name}/{best.rtype}"
        ctx.deferred_vulns.append({
            "vuln_code": VULNS.Amplification.value,
            "vuln_request": f"RD=1 {best.name} {best.rtype} ({best.request_size} B)",
            "vuln_response": f"{best.response_size} B response, amplification factor x{best.factor}",
        })
