"""ROLE — authoritative vs recursive vs forwarder.

Sends a recursive (RD=1) query for an external name and reads the flags/answer
to classify the server's role. This is informational recon: the open-recursion
*finding* (and its amplification/abuse angle) is owned by the RECURSION and
AMPLIFICATION tests in the "Recursion & resolver abuse" section, so it is not
re-reported here. A full recursive resolver and a forwarder look the same from
the client side, so that distinction is reported as "cannot be proven remotely".
"""
from ptsrvtester.protocols.dns.utils import fingerprint_core as fp
from ptsrvtester.protocols.dns.utils import recursion_core as rc

__MODULELABEL__ = "Server role (authoritative / recursive / forwarder)"
__MODULECODE__ = "ROLE"
__ORDER__ = 50


def run(ctx):
    target = fp.server_target(ctx)
    if target is None:
        ctx.out("This test needs a target DNS server; pass -tg <server>.", "WARNING", indent=4)
        return
    ip, port = target

    # Use the -d domain when given (so an internal DNS can resolve it); bail with
    # guidance if the target cannot resolve the probe name at all.
    probe = (rc.probe_domains(ctx) or ["example.com"])[0]
    rc.resolve_guard(ctx, ip, port, probe)

    info = fp.role_probe(ip, port, name=probe)
    if info.error:
        ctx.out(f"Role probe failed: {info.error}", "WARNING", indent=4)
        return

    ctx.out(f"{'Recursion available (RA)':<28} {'yes' if info.recursion_available else 'no'}", "TITLE", indent=4)
    ctx.out(f"{'Resolved external name':<28} {'yes' if info.recursion_answered else 'no'} (rcode {info.rcode})", "TITLE", indent=4)
    ctx.out(f"{'Authoritative answer (AA)':<28} {'yes' if info.authoritative else 'no'}", "TITLE", indent=4)

    open_resolver = bool(info.recursion_available and info.recursion_answered)
    if open_resolver:
        role = "Recursive resolver — open to this client"
        ctx.out("Recursive/open resolver (resolves external names for us); "
                "see the RECURSION and AMPLIFICATION tests for the abuse findings.",
                "TITLE", indent=4)
        ctx.out("Note: a full recursive resolver and a forwarder cannot be reliably "
                "distinguished remotely.", "ADDITIONS", colortext=True, indent=8)
    elif info.recursion_available:
        role = "Recursion advertised but not resolving for us (possibly restricted by ACL)"
        ctx.out(role, "TITLE", indent=4)
    else:
        role = "Authoritative-only / recursion not available"
        ctx.out(role, "OK", indent=4)

    with ctx.results_lock:
        ctx.properties["role"] = role
