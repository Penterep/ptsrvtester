"""VERSION — software/build disclosure via CHAOS-class TXT records.

Queries version.bind, hostname.bind, id.server and authors.bind (class CHAOS).
A server that answers leaks its software and often the exact build/OS, which
helps an attacker target known vulnerabilities — reported as a finding.
"""
from ptsrvtester.protocols.dns.utils import fingerprint_core as fp

__MODULELABEL__ = "Software version disclosure (CHAOS TXT)"
__MODULECODE__ = "VERSION"
__ORDER__ = 10


def run(ctx):
    target = fp.server_target(ctx)
    if target is None:
        ctx.out("This test needs a target DNS server; pass -tg <server>.", "WARNING", indent=4)
        return
    ip, port = target
    if fp.server_reachable(ctx) is False:
        ctx.out(fp.unreachable_message(ip, port), "WARNING", indent=4)
        return

    ctx.debug(f"Querying CHAOS-class TXT records ({', '.join(fp.CHAOS_NAMES)}) on {ip}:{port}")
    chaos = fp.collect_chaos(ip, port)
    disclosed = {name: vals for name, vals in chaos.items() if vals}

    ctx.out("")
    ctx.out("Returned information:", "TEXT", indent=4)
    for name in fp.CHAOS_NAMES:
        vals = chaos.get(name)
        if vals:
            ctx.out(f"{name:<15} {', '.join(vals)}", "VULN", indent=4)
        elif vals == []:
            ctx.out(f"{name:<15} refused / not set", "OK", indent=4)
        else:
            ctx.out(f"{name:<15} no response", "WARNING", indent=4)

    if not disclosed:
        ctx.out("No CHAOS TXT information disclosed.", "OK", indent=4)
        return

    ctx.out("Server discloses software/build information via CHAOS TXT.", "VULN", indent=4)

    with ctx.results_lock:
        ctx.deferred_vulns.append({"vuln_code": "PTV-SVC-DNS-CHAOS"})
