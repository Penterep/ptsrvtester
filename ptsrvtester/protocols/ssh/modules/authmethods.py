"""AUTHM — supported SSH authentication methods."""
from ptsrvtester.protocols.ssh.utils.ssh_helpers import get_auth_methods

__MODULELABEL__ = "Authentication methods"
__MODULECODE__ = "AUTHM"
__ORDER__ = 30


def run(ctx):
    ip, port = ctx.target
    try:
        methods = get_auth_methods(ip, port)
    except Exception as e:
        ctx.out(f"Failed to query authentication methods from {ip}:{port}: {e}", "VULN", indent=4)
        with ctx.results_lock:
            ctx.properties["authMethodsError"] = str(e)
        return

    if not methods:
        ctx.out("Server did not report authentication methods", "NOTVULN", indent=4)
        return

    with ctx.results_lock:
        ctx.properties["authMethods"] = methods

    has_kb_interactive = False
    for method in methods:
        if method.lower() == "keyboard-interactive":
            has_kb_interactive = True
        cat = "VULN" if method.lower() == "password" else "NOTVULN"
        ctx.out(method, cat, indent=4)

    if has_kb_interactive:
        ctx.out(
            "Server supports keyboard-interactive; password bruteforce may fail.",
            "WARNING", indent=4,
        )