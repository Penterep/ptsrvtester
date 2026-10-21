import socket
from ptsrvtester.protocols.ssh.modules.authmethods import get_auth_methods
from ptsrvtester.protocols.rsync.modules.banner import get_supported_digests

__MODULELABEL__ = "Rsync SSH and authentication method detection"
__MODULECODE__ = "encrypt"
__ORDER__ = 80

DIGEST_SECURITY_MAPPING = {
    "md4": "VULN",
    "md5": "VULN",
    "sha1": "WARNING",
    "sha256": "OK",
    "sha512": "OK",
}

def _rsync_try_ssh(ctx):
    try:
        ctx.debug(f"Sent: TCP connection to SSH service at {ctx.ip}:22", indent=4)
        with socket.create_connection((ctx.ip, 22), timeout=ctx.timeout) as s:
            ctx.debug("Received: SSH service accepted the TCP connection", indent=8)
            ctx.out(f"The host supports SSH", "INFO", indent=4)

            try:
                auth_m = get_auth_methods(ctx.ip, 22)
                ctx.debug(
                    f"Received SSH authentication methods: {', '.join(auth_m) if auth_m else '<none>'}",
                    indent=8,
                )
                if auth_m:
                    ctx.out(f"Supported authentication methods: {', '.join(auth_m)}", "INFO", indent=8)
                else:
                    ctx.out(f"No authentication methods found", "INFO", indent=8)
            except Exception as e:
                ctx.out(f"Error occurred while fetching authentication methods: {e}", "ERROR", indent=4)
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        ctx.out(f"The host does not support SSH: {e}", "INFO", indent=4)

def run(ctx):
    supported_digests = list(ctx.supported_digests)
    if not supported_digests:
        try:
            supported_digests = get_supported_digests(ctx)
        except OSError as e:
            ctx.out(
                f"Error fetching supported hash digest algorithms: {e}",
                "ERROR",
                indent=4,
            )

    ctx.debug(
        f"Received supported rsync digest algorithms: "
        f"{', '.join(supported_digests) if supported_digests else '<none>'}",
        indent=4,
    )
    ctx.out(f"Supported hash digest algorithms:", "INFO", indent=4)
    for hd in supported_digests:
        ctx.out(f"{hd}", DIGEST_SECURITY_MAPPING.get(hd, "INFO"), indent=8)
    _rsync_try_ssh(ctx)
