"""FINGERPRINT — host-key fingerprints (from the shared ssh-audit scan).

Informational: lists the SHA256/MD5 fingerprint of each host key ssh-audit saw.
"""
from ptsrvtester.protocols.ssh.utils.ssh_helpers import service_reachable, unreachable_message

__MODULELABEL__ = "Host-key fingerprints"
__MODULECODE__ = "FINGERPRINT"
__ORDER__ = 44


def run(ctx):
    if service_reachable(ctx) is False:
        ip, port = ctx.target
        ctx.out(unreachable_message(ip, port), "WARNING", indent=4)
        return

    if ctx.ssh_audit.done:
        ctx.debug("Reading host-key fingerprints from the shared ssh-audit scan")
    else:
        ctx.debug(f"Running ssh-audit against {ctx.ip}:{ctx.port} (shared crypto scan)")
    run_result = ctx.ssh_audit.get()
    if not run_result.ok:
        ctx.out(f"ssh-audit did not run: {run_result.error}", "WARNING", indent=4)
        return

    fingerprints = (run_result.data or {}).get("fingerprints") or []
    if not fingerprints:
        ctx.out("ssh-audit reported no host-key fingerprints", "NOTVULN", indent=4)
        return

    ctx.debug(f"{len(fingerprints)} host-key fingerprint(s) reported")

    ctx.out("")
    ctx.out("Returned information:", "TEXT", indent=4)
    # Align the host-key and hash-label columns so the fingerprints line up.
    host_width = max(len(fp.get("hostkey", "?")) for fp in fingerprints)
    label_width = max(len(f"{fp.get('hash_alg', '?')}:") for fp in fingerprints) + 1
    for fp in fingerprints:
        hostkey = fp.get("hostkey", "?")
        hash_alg = fp.get("hash_alg", "?")
        value = fp.get("hash", "")
        # One line per fingerprint: "<hostkey> <HASH>: <value>", columns aligned.
        label = f"{hash_alg}:"
        ctx.out(f"{hostkey.ljust(host_width)} {label.ljust(label_width)}{value}", "TEXT", indent=4)