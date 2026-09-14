import socket


__MODULELABEL__ = "Rsync version detection module"
__MODULECODE__ = "banner"
__ORDER__ = 100


def _rsync_grab_banner(ctx):
    try:
        with socket.create_connection((ctx.ip, ctx.port), timeout=ctx.timeout) as sock:
            banner = sock.recv(1024).decode(errors="replace").strip()

        if banner is not None:
            ctx.out(f"Grabbed Rsync server banner: {banner}", "VULN", indent=4)
        else:
            ctx.out(f"Could not grab banner", "OK", indent=4)

    except Exception as e:
        ctx.out(f"Error grabbing banner: {e}", "ERROR", condition=not ctx.json, indent=4)


def run(ctx):
    _rsync_grab_banner(ctx)