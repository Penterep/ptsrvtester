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

    ctx.out("")
    ctx.out("Returned information:", "TEXT", indent=4)
    for name in ("UDP/53", "TCP/53", "DoT/853", "DoH/443", "DoQ/853"):
        res = results.get(name)
        if res is None:
            continue
        if res.state is True:
            ctx.out(f"{name:<10} supported", "OK", indent=4)
        elif res.state is False:
            ctx.out(f"{name:<10} not available ({res.detail})", "WARNING", indent=4)
        else:
            ctx.out(f"{name:<10} not tested ({res.detail})", "WARNING", indent=4)
