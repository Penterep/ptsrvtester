"""TRANSPORT — which DNS transports the server accepts.

Probes UDP/53, TCP/53, DoT/853, DoH/443 and DoQ/853 with a benign query.
Informational: encrypted transports (DoT/DoH/DoQ) are a privacy positive, not a
finding; the result maps out the server's exposed surface. DoQ needs the
optional ``aioquic`` package to be tested.
"""
from ptsrvtester.protocols.dns.utils import fingerprint_core as fp

__MODULELABEL__ = "Supported transports"
__MODULECODE__ = "TRANSPORT"
__ORDER__ = 30


def run(ctx):
    target = fp.server_target(ctx)
    if target is None:
        ctx.out("This test needs a target DNS server; pass -tg <server>.", "WARNING", indent=4)
        return
    ip, port = target
    host = getattr(ctx, "host", None)

    ctx.debug(f"Querying supported transports (UDP/53, TCP/53, DoT/853, DoH/443, DoQ/853) on {ip}")
    results = fp.transports(host, ip, port)

    order = ("UDP/53", "TCP/53", "DoT/853", "DoH/443", "DoQ/853")
    probed = [results[n] for n in order if results.get(n) is not None]
    # Seed the run-shared reachability cache from the plaintext probes so the
    # later per-module guards (version/nsid/edns/…) read it without re-probing.
    cache = getattr(ctx, "reach_cache", None)
    if cache is not None:
        cache[(ip, port)] = (results["UDP/53"].state is True) or (results["TCP/53"].state is True)
    # If not a single transport answered, the target is not a reachable DNS
    # server (every probe just errored out). Those five "not available" lines are
    # noise, so say the target is moot instead of listing them.
    if probed and not any(r.state is True for r in probed):
        ctx.out("")
        ctx.out(f"{ip} did not answer on any transport (UDP/TCP/DoT/DoH/DoQ) — not a reachable "
                "DNS server, so there is nothing meaningful to test here.", "WARNING", indent=4)
        return

    ctx.out("")
    ctx.out("Returned information:", "TEXT", indent=4)
    for name in order:
        res = results.get(name)
        if res is None:
            continue
        if res.state is True:
            ctx.out(f"{name:<10} supported", "OK", indent=4)
        elif res.state is False:
            ctx.out(f"{name:<10} not available ({res.detail})", "WARNING", indent=4)
        else:
            ctx.out(f"{name:<10} not tested ({res.detail})", "WARNING", indent=4)
