"""FINGERPRINT — host-key fingerprints (from the shared ssh-audit scan).

Informational: lists the SHA256/MD5 fingerprint of each host key ssh-audit saw.
"""
__MODULELABEL__ = "Host-key fingerprints"
__MODULECODE__ = "FINGERPRINT"
__ORDER__ = 44


def run(ctx):
    run_result = ctx.ssh_audit.get()
    if not run_result.ok:
        ctx.out(f"ssh-audit did not run: {run_result.error}", "WARNING", indent=4)
        return

    fingerprints = (run_result.data or {}).get("fingerprints") or []
    if not fingerprints:
        ctx.out("ssh-audit reported no host-key fingerprints", "NOTVULN", indent=4)
        return

    for fp in fingerprints:
        hostkey = fp.get("hostkey", "?")
        hash_alg = fp.get("hash_alg", "?")
        value = fp.get("hash", "")
        # Host key on one line; its fingerprint on the next, one indent level deeper.
        ctx.out(hostkey, "TEXT", indent=4)
        ctx.out(f"{hash_alg}:{value}", "TEXT", indent=8)

    with ctx.results_lock:
        ctx.properties["fingerprints"] = [
            f"{fp.get('hostkey', '?')} {fp.get('hash_alg', '?')}:{fp.get('hash', '')}"
            for fp in fingerprints
        ]