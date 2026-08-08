"""BADAUTHKEY — try known static (bad) user private keys against the server."""
from ptsrvtester.protocols.ssh.utils.ssh_helpers import check_bad_authkeys
from ptsrvtester.protocols.ssh.utils.results import VULNS

__MODULELABEL__ = "Known static (bad) auth keys"
__MODULECODE__ = "BADAUTHKEY"
__ORDER__ = 60
# Needs -A/--bad-authkeys, so it is skipped by the default / ALL sweep (SSH-only).
__RUN_IN_ALL__ = False


def run(ctx):
    path = getattr(ctx.args, "bad_authkeys", None)
    if not path:
        ctx.out("BADAUTHKEY requires -A/--bad-authkeys <directory>", "WARNING", indent=4)
        return

    ip, port = ctx.target
    try:
        keys = check_bad_authkeys(ip, port, path)
    except OSError as e:
        ctx.out(f"Cannot read --bad-authkeys directory '{path}': {e}", "VULN", indent=4)
        return

    if keys:
        ctx.out(f"Matched {len(keys)} key(s)", "VULN", indent=4)
        for k in keys:
            ctx.out(k, "TEXT", indent=8)
        with ctx.results_lock:
            ctx.deferred_vulns.append({
                "vuln_code": VULNS.BadAuthKeys.value,
                "vuln_request": f"matched keys from: {path}",
                "vuln_response": "\n".join(keys),
            })
    else:
        ctx.out("No match", "NOTVULN", indent=4)