"""HOSTKEY — remote SSH server host key."""
from ptsrvtester.protocols.ssh.utils.ssh_helpers import get_host_key

__MODULELABEL__ = "Host key"
__MODULECODE__ = "HOSTKEY"
__ORDER__ = 20


def run(ctx):
    ip, port = ctx.target
    try:
        host_key = get_host_key(ip, port)
    except Exception as e:
        msg = f"Failed to establish SSH connection with server {ip}:{port}: {e}"
        ctx.out(msg, "VULN", indent=4)
        with ctx.results_lock:
            ctx.properties["hostKeyError"] = msg
        return

    with ctx.results_lock:
        ctx.properties["hostKey"] = host_key
    ctx.out(host_key, "TEXT", indent=4)