"""ROLE — authoritative vs recursive vs forwarder.

Sends a recursive (RD=1) query for an external name and reads the flags/answer.
Recursion offered to an arbitrary client (an open resolver) is a real finding:
it enables DNS amplification DDoS abuse. A full recursive resolver and a
forwarder look the same from the client side, so that distinction is reported
as "cannot be proven remotely".
"""
from ptsrvtester.protocols.dns.utils import fingerprint_core as fp
from ptsrvtester.protocols.dns.utils.results import VULNS

__MODULELABEL__ = "Server role (authoritative / recursive / forwarder)"
__MODULECODE__ = "ROLE"
__ORDER__ = 50


def run(ctx):
    target = fp.server_target(ctx)
    if target is None:
        ctx.out("This test needs a target DNS server; pass -tg <server>.", "WARNING", indent=4)
        return
    ip, port = target

    info = fp.role_probe(ip, port)
    if info.error:
        ctx.out(f"Role probe failed: {info.error}", "WARNING", indent=4)
        return

    ctx.out(f"{'Recursion available (RA)':<28} {'yes' if info.recursion_available else 'no'}", "TEXT", indent=4)
    ctx.out(f"{'Resolved external name':<28} {'yes' if info.recursion_answered else 'no'} (rcode {info.rcode})", "TEXT", indent=4)
    ctx.out(f"{'Authoritative answer (AA)':<28} {'yes' if info.authoritative else 'no'}", "TEXT", indent=4)

    open_resolver = bool(info.recursion_available and info.recursion_answered)
    if open_resolver:
        role = "Recursive resolver — open to this client"
        ctx.out("Open recursion: the server resolves arbitrary external names for us "
                "(open resolver → DNS amplification abuse).", "VULN", indent=4)
        ctx.out("Note: a full recursive resolver and a forwarder cannot be reliably "
                "distinguished remotely.", "TEXT", indent=4)
    elif info.recursion_available:
        role = "Recursion advertised but not resolving for us (possibly restricted by ACL)"
        ctx.out(role, "TEXT", indent=4)
    else:
        role = "Authoritative-only / recursion not available"
        ctx.out(role, "OK", indent=4)

    with ctx.results_lock:
        ctx.properties["role"] = role
        if open_resolver:
            ctx.deferred_vulns.append({
                "vuln_code": VULNS.OpenRecursion.value,
                "vuln_request": "RD=1 query for external name (example.com A)",
                "vuln_response": f"RA=1, answered=yes, rcode={info.rcode}",
            })
