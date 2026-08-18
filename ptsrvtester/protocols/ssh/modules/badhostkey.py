"""BADHOSTKEY — compare the server host key against known static (bad) keys."""
from ptsrvtester.protocols.ssh.utils.ssh_helpers import get_host_key, check_bad_pubkey
from ptsrvtester.protocols.ssh.utils.results import VULNS

__MODULELABEL__ = "Known static (bad) host key"
__MODULECODE__ = "BADHOSTKEY"
__ORDER__ = 50
__RUN_IN_ALL__ = False


def run(ctx):
    path = getattr(ctx.args, "bad_pubkeys", None)
    if not path:
        ctx.out("BADHOSTKEY requires -H/--bad-pubkeys <directory>", "WARNING", indent=4)
        return

    ip, port = ctx.target
    try:
        host_key = get_host_key(ip, port)
    except Exception as e:
        ctx.out(f"Failed to fetch host key from {ip}:{port}: {e}", "VULN", indent=4)
        return

    try:
        result = check_bad_pubkey(path, host_key)
    except OSError as e:
        ctx.out(f"Cannot read --bad-pubkeys directory '{path}': {e}", "VULN", indent=4)
        return

    if result.bad:
        ctx.out(f"Matched key path: {result.path}", "VULN", indent=4)
        with ctx.results_lock:
            ctx.deferred_vulns.append({
                "vuln_code": VULNS.BadHostKey.value,
                "vuln_request": f"matched key from: {path}",
                "vuln_response": result.path,
            })
    else:
        ctx.out("No match", "NOTVULN", indent=4)