"""AUDIT — ssh-audit CVE + insecure-crypto scan."""
from ptsrvtester.protocols.ssh.utils.ssh_helpers import is_reachable, run_ssh_audit
from ptsrvtester.protocols.ssh.utils.results import VULNS

__MODULELABEL__ = "ssh-audit scan results"
__MODULECODE__ = "AUDIT"
__ORDER__ = 40


def run(ctx):
    ip, port = ctx.target
    # Availability check first: in the full sweep this module runs even if BANNER
    # failed, so skip cleanly on an unreachable host instead of surfacing an
    # ssh-audit connection error.
    if not is_reachable(ip, port):
        ctx.out(f"Host {ip}:{port} is not reachable — skipping ssh-audit", "TEXT", indent=4)
        with ctx.results_lock:
            ctx.properties["sshauditStatus"] = "unreachable"
        return

    try:
        audit = run_ssh_audit(ip, port)
    except Exception as e:
        ctx.out(f"SSH-audit test failed: {e}", "VULN", indent=4)
        with ctx.results_lock:
            ctx.properties["sshauditError"] = str(e)
        return

    if audit.err is not None:
        ctx.out(f"ssh-audit failed with error: {audit.err}", "TEXT", indent=4)
        with ctx.results_lock:
            ctx.properties["sshauditStatus"] = audit.err
        return

    with ctx.results_lock:
        ctx.properties["sshauditStatus"] = "ok"
        cve_lines = [f"{c.name} ({c.severity}): {c.description}" for c in audit.cves]
        if cve_lines:
            ctx.deferred_vulns.append({
                "vuln_code": VULNS.CVE.value,
                "vuln_request": "ssh-audit scan",
                "vuln_response": "\n".join(cve_lines),
            })
        crypto_lines = [
            f"{f.level.upper()} {f.category}/{f.action}: {f.name}"
            + (f" ({f.notes})" if f.notes else "")
            for f in audit.cryptofindings
        ]
        if crypto_lines:
            ctx.deferred_vulns.append({
                "vuln_code": VULNS.InsecureCrypto.value,
                "vuln_request": "ssh-audit scan",
                "vuln_response": "\n".join(crypto_lines),
            })

    ctx.out(f"Identified {len(audit.cves)} CVEs", "TEXT", indent=4)
    for cve in audit.cves:
        ctx.out(f"{cve.name} ({cve.severity}): {cve.description}", "TEXT", indent=8)

    ctx.out(f"Identified {len(audit.cryptofindings)} insecure SSH configurations", "TEXT", indent=4)
    for find in audit.cryptofindings:
        level = find.level.upper()
        body = f"{find.category}/{find.action}: {find.name}" + (f" ({find.notes})" if find.notes else "")
        if level == "CRITICAL":
            ctx.out(body, "VULN", indent=8)
        elif level == "WARNING":
            ctx.out(body, "WARNING", indent=8)
        else:
            ctx.out(f"{level} {body}", "TEXT", indent=8)