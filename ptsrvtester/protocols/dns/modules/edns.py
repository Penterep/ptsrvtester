"""EDNS — EDNS(0) support, advertised UDP payload size and DNS cookies.

Sends an EDNS(0) query carrying a client cookie and reads the server's OPT
record back: whether EDNS is supported at all, the UDP payload size it
advertises (large sizes raise the amplification/fragmentation surface) and
whether it echoes a DNS cookie (RFC 7873, off-path spoofing hardening).
Informational.
"""
from ptsrvtester.protocols.dns.utils import fingerprint_core as fp

__MODULELABEL__ = "EDNS(0), UDP payload & DNS cookies"
__MODULECODE__ = "EDNS"
__ORDER__ = 40


def run(ctx):
    target = fp.server_target(ctx)
    if target is None:
        ctx.out("This test needs a target DNS server; pass -tg <server>.", "WARNING", indent=4)
        return
    ip, port = target

    info = fp.edns_probe(ip, port)
    if info.error:
        ctx.out(f"EDNS probe failed: {info.error}", "WARNING", indent=4)
        return
    if not info.supported:
        ctx.out("Server does not support EDNS(0).", "TITLE", indent=4)
        with ctx.results_lock:
            ctx.properties["edns"] = "unsupported"
        return

    ctx.out(f"{'EDNS version':<18} {info.version}", "OK", indent=4)
    ctx.out(f"{'UDP payload':<18} {info.udp_payload} bytes", "TITLE", indent=4)
    ctx.out(
        f"{'DNS cookies':<18} " + ("supported (server cookie echoed)" if info.cookie else "not observed"),
        "OK" if info.cookie else "TITLE",
        indent=4,
    )

    with ctx.results_lock:
        ctx.properties["edns"] = f"v{info.version}, payload {info.udp_payload}, cookies {'yes' if info.cookie else 'no'}"
