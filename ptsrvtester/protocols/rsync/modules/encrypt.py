import socket
from ptsrvtester.protocols.ssh.modules.authmethods import get_auth_methods

__MODULELABEL__ = "Rsync SSH detection"
__MODULECODE__ = "encrypt"
__ORDER__ = 100


def _rsync_try_ssh(ctx):
    try:
        with socket.create_connection((ctx.ip, 22), timeout=ctx.timeout) as s:
            ctx.out(f"The host supports SSH", "INFO", indent=4)

            try:
                auth_m = get_auth_methods(ctx.ip, 22)
                if auth_m:
                    ctx.out(f"Supported authentication methods: {', '.join(auth_m)}", "INFO", indent=4)
                else:
                    ctx.out(f"No authentication methods found", "INFO", indent=4)
            except Exception as e:
                ctx.out(f"Error occurred while fetching authentication methods: {e}", "ERROR", indent=4)
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        ctx.out(f"The host does not support SSH: {e}", "INFO", indent=4)

def run(ctx):
    _rsync_try_ssh(ctx)