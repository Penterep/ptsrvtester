"""BRUTE — SSH login bruteforce (password or private key)."""
import sys
from io import StringIO

from ptsrvtester.protocols.ssh.utils.helpers import threaded_bruteforce
from ptsrvtester.protocols.ssh.utils.ssh_helpers import (
    build_ssh_creds,
    cred_to_str,
    try_login,
)

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

    ctx.debug(
        f"Trying {len(creds)} credential(s) against {ip}:{port} "
        f"with {a.threads} thread(s)"
    )
    err = StringIO("")
    old_write = sys.stderr.write
    sys.stderr.write = err.write
    try:
        found = threaded_bruteforce(creds, lambda c: try_login(ip, port, c), a.threads)
    finally:
        sys.stderr.write = old_write
    ctx.debug(f"Bruteforce finished: {len(found)} valid credential(s) found")
    errors = len(err.getvalue()) > 0
    err.close()

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
        ctx.vulns.hit(ctx.module_code)
    else:
        ctx.out("No valid credentials found", "NOTVULN", indent=4)