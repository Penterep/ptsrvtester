"""BRUTE — SSH login bruteforce (password or private key)."""
import sys
from io import StringIO

from ptsrvtester.protocols.ssh.utils.helpers import threaded_bruteforce
from ptsrvtester.protocols.ssh.utils.ssh_helpers import (
    build_ssh_creds,
    cred_to_str,
    try_login,
)
from ptsrvtester.protocols.ssh.utils.results import VULNS

__MODULELABEL__ = "Login bruteforce"
__MODULECODE__ = "BRUTE"
__ORDER__ = 70
__RUN_IN_ALL__ = False


def run(ctx):
    a = ctx.args
    has_user = bool(a.user or a.users)
    has_secret = bool(a.password or a.passwords or getattr(a, "privkeys", None))
    if not (has_user and has_secret):
        ctx.out("BRUTE requires -u/-U and -p/-P (or --privkeys)", "WARNING", indent=4)
        return

    ip, port = ctx.target
    creds = build_ssh_creds(a)
    if not creds:
        ctx.out("No credentials to try (empty user/secret list)", "WARNING", indent=4)
        return

    err = StringIO("")
    old_write = sys.stderr.write
    sys.stderr.write = err.write
    try:
        found = threaded_bruteforce(creds, lambda c: try_login(ip, port, c), a.threads)
    finally:
        sys.stderr.write = old_write
    errors = len(err.getvalue()) > 0
    err.close()

    with ctx.results_lock:
        ctx.properties["bruteStatus"] = "errors" if errors else "ok"

    if errors:
        ctx.out(
            "WARNING: there were some errors during the bruteforce process."
            " Try reducing the --brute-threads parameter",
            "WARNING", indent=4,
        )

    if found:
        ctx.out(f"{len(found)} valid credentials", "INFO", colortext=True)
        for cred in found:
            ctx.out(cred_to_str(cred), "TEXT", indent=4)

        user_str = f"username: {a.user}" if a.user else f"usernames: {a.users}"
        if a.password:
            passw_str = f"password: {a.password}"
        elif getattr(a, "privkeys", None):
            passw_str = f"private keys: {a.privkeys}"
        else:
            passw_str = f"passwords: {a.passwords}"

        with ctx.results_lock:
            ctx.deferred_vulns.append({
                "vuln_code": VULNS.WeakCreds.value,
                "vuln_request": f"{user_str}\n{passw_str}",
                "vuln_response": "\n".join(cred_to_str(c) for c in found),
            })
    else:
        ctx.out("No valid credentials found", "NOTVULN", indent=4)