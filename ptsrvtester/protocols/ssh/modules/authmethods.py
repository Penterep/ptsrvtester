"""AUTHM — supported SSH authentication methods."""
from ptsrvtester.protocols.ssh.utils.ssh_helpers import (
    get_auth_methods,
    service_reachable,
    unreachable_message,
)

__MODULELABEL__ = "Authentication methods"
__MODULECODE__ = "AUTHM"
__ORDER__ = 30



def run(ctx):
    ip, port = ctx.target
    if service_reachable(ctx) is False:
        ctx.out(unreachable_message(ip, port), "WARNING", indent=4)
        return

    ctx.debug(f"Querying the authentication methods offered by {ip}:{port}")
    try:
        methods = get_auth_methods(ip, port)
    except Exception as e:
        ctx.out(f"Failed to query authentication methods from {ip}:{port}: {e}", "VULN", indent=4)
        return

    if not methods:
        ctx.out("Server did not report authentication methods", "NOTVULN", indent=4)
        return

    ctx.debug(f"Server offers: {', '.join(methods)}")

    ctx.out("")
    ctx.out("Returned information:", "TEXT", indent=4)
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