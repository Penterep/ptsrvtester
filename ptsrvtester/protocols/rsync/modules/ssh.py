import socket


__MODULELABEL__ = "Rsync SSH detection"
__MODULECODE__ = "ssh"
__ORDER__ = 100


def _rsync_try_ssh(ctx):
    try:
        with socket.create_connection((ctx.ip, 22), timeout=ctx.timeout) as s:
            ctx.out(f"The host supports SSH", "INFO", indent=4)
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        ctx.out(f"The host does not support SSH: {e}", "INFO", indent=4)

def run(ctx):
    _rsync_try_ssh(ctx)