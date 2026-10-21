import socket
from ptsrvtester.protocols.rsync.modules.banner import get_supported_digests
from ptsrvtester.protocols.rsync.utils.registry import rsync_debug

__MODULELABEL__ = "Rsync daemon and digest detection"
__MODULECODE__ = "encrypt"
__ORDER__ = 80

DIGEST_SECURITY_MAPPING = {
    "md4": "VULN",
    "md5": "VULN",
    "sha1": "WARNING",
    "sha256": "OK",
    "sha512": "OK",
}

def _rsync_try_daemon(ctx):
    try:
        rsync_debug(ctx, f"Sent: TCP connection to rsync daemon at {ctx.ip}:{ctx.port}", indent=4)
        with socket.create_connection((ctx.ip, ctx.port), timeout=ctx.timeout) as sock:
            with sock.makefile("rb") as reader:
                greeting = reader.readline().decode(errors="replace").strip()
        rsync_debug(ctx, f"Received: {greeting or '<empty response>'}", indent=8)
        if greeting.startswith("@RSYNCD:"):
            ctx.out("The host supports the rsync daemon", "INFO", indent=4)
            ctx.ptjsonlib.add_vulnerability("PTV-SVC-RSYNC-RUNTYPE", 
                                            poc=f"Succesfully connected to {ctx.ip}:{ctx.port} and received greeting {greeting}")
        else:
            ctx.out("The host does not support the rsync daemon", "INFO", indent=4)
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        ctx.out(f"The host does not support the rsync daemon: {e}", "INFO", indent=4)

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

    rsync_debug(ctx,
        f"Received supported rsync digest algorithms: "
        f"{', '.join(supported_digests) if supported_digests else '<none>'}",
        indent=4,
    )
    ctx.out(f"Supported hash digest algorithms:", "INFO", indent=4)
    vuln_digests = []
    for hd in supported_digests:
        ctx.out(f"{hd}", DIGEST_SECURITY_MAPPING.get(hd, "INFO"), indent=8)
        if DIGEST_SECURITY_MAPPING.get(hd) in ["VULN", "WARN"]:
            vuln_digests.append(hd)
    if vuln_digests:
        ctx.ptjsonlib.add_vulnerability("PTV-SVC-RSYNC-AUTH", poc={"vulnerable_digests": vuln_digests})
    _rsync_try_daemon(ctx)
