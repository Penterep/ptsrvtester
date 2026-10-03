"""NSID — server-instance identification via the EDNS NSID option (RFC 5001).

Sends an empty NSID option; a server that echoes one reveals which specific
instance answered (behind anycast/load balancing). Useful recon and a minor
information disclosure — reported as a finding.
"""
from ptsrvtester.protocols.dns.utils import fingerprint_core as fp
from ptsrvtester.protocols.dns.utils.results import VULNS

__MODULELABEL__ = "Server identity disclosure (NSID)"
__MODULECODE__ = "NSID"
__ORDER__ = 20


def run(ctx):
    target = fp.server_target(ctx)
    if target is None:
        ctx.out("This test needs a target DNS server; pass -tg <server>.", "WARNING", indent=4)
        return
    ip, port = target

    raw = fp.nsid(ip, port)
    if raw is None:
        ctx.out("Server does not return an NSID (no instance identity disclosed).", "OK", indent=4)
        return

    ascii_val, hex_val = fp.nsid_display(raw)
    ctx.out(f"{'NSID (text)':<15} {ascii_val}", "VULN", indent=4)
    ctx.out(f"{'NSID (hex)':<15} {hex_val}", "TITLE", indent=4)
    ctx.out("Server reveals its instance identity via NSID.", "VULN", indent=4)

    with ctx.results_lock:
        ctx.properties["nsid"] = ascii_val
        ctx.deferred_vulns.append({
            "vuln_code": VULNS.NsidDisclosure.value,
            "vuln_request": "EDNS OPT with NSID (option 3)",
            "vuln_response": f"{ascii_val} (hex {hex_val})",
        })
