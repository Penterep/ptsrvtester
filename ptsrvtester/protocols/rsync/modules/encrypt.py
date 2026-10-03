import socket
from ptsrvtester.protocols.ssh.modules.authmethods import get_auth_methods

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
        with socket.create_connection((ctx.ip, 22), timeout=ctx.timeout) as s:
            ctx.out(f"The host supports SSH", "INFO", indent=4)

            try:
                auth_m = get_auth_methods(ctx.ip, 22)
                if auth_m:
                    ctx.out(f"Supported authentication methods: {', '.join(auth_m)}", "INFO", indent=8)
                else:
                    ctx.out(f"No authentication methods found", "INFO", indent=8)
            except Exception as e:
                ctx.out(f"Error occurred while fetching authentication methods: {e}", "ERROR", indent=4)
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        ctx.out(f"The host does not support SSH: {e}", "INFO", indent=4)

def run(ctx):
    ctx.out(f"Supported hash digest algorithms:", "INFO", indent=4)
    for hd in ctx.supported_digests:
        ctx.out(f"{hd}", DIGEST_SECURITY_MAPPING.get(hd, "INFO"), indent=8)
    _rsync_try_ssh(ctx)