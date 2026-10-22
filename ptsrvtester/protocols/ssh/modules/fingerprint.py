"""FINGERPRINT — host-key fingerprints (from the shared ssh-audit scan).

Informational: lists the SHA256/MD5 fingerprint of each host key ssh-audit saw.
"""
__MODULELABEL__ = "Host-key fingerprints"
__MODULECODE__ = "FINGERPRINT"
__ORDER__ = 44


def run(ctx):
    if ctx.ssh_audit.done:
        ctx.debug("reading host-key fingerprints from the shared ssh-audit scan")
    else:
        ctx.debug(f"running ssh-audit against {ctx.ip}:{ctx.port} (shared crypto scan)")
    run_result = ctx.ssh_audit.get()
    if not run_result.ok:
        ctx.out(f"ssh-audit did not run: {run_result.error}", "WARNING", indent=4)
        return

    fingerprints = (run_result.data or {}).get("fingerprints") or []
    if not fingerprints:
        ctx.out("ssh-audit reported no host-key fingerprints", "NOTVULN", indent=4)
        return

    ctx.debug(f"{len(fingerprints)} host-key fingerprint(s) reported")

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