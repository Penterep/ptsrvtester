"""HOSTKEY — remote SSH server host key."""
from ptsrvtester.protocols.ssh.utils.ssh_helpers import (
    get_host_key,
    service_reachable,
    unreachable_message,
)

__MODULELABEL__ = "Host key"
__MODULECODE__ = "HOSTKEY"
__ORDER__ = 20


def run(ctx):
    ip, port = ctx.target
    if service_reachable(ctx) is False:
        ctx.out(unreachable_message(ip, port), "WARNING", indent=4)
        return

    ctx.debug(f"Opening an SSH transport to {ip}:{port} to read the server host key")
    try:
        host_key = get_host_key(ip, port)
    except Exception as e:
        msg = f"Failed to establish SSH connection with server {ip}:{port}: {e}"
        ctx.out(msg, "VULN", indent=4)
        return

    ctx.debug("Host key received")
    ctx.out("")
    ctx.out("Returned information:", "TEXT", indent=4)
    ctx.out(host_key, "TEXT", indent=4)