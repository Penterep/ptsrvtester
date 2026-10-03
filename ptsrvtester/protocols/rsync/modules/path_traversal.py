import os
import subprocess
import tempfile
import uuid
from ptsrvtester.protocols.rsync.utils.registry import rsync_env, rsync_url


__MODULELABEL__ = "Rsync path traversal detection"
__MODULECODE__ = "path_traversal"
__ORDER__ = 80


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
    

def _try_path_traversal_write(ctx):
    traversal_dir = "../../../../../../tmp"
    marker_name = f"ptsrvtester_traversal_{uuid.uuid4().hex}.txt"

    with tempfile.TemporaryDirectory() as tmpdir:
        local_path = os.path.join(tmpdir, marker_name)
        with open(local_path, "w", encoding="utf-8") as marker:
            marker.write("Temporary rsync path traversal probe.\n")

        try:
            upload = subprocess.run(
                [
                    "rsync",
                    "--no-motd",
                    "--ignore-existing",
                    local_path,
                    rsync_url(ctx, f"{traversal_dir}/{marker_name}"),
                ],
                capture_output=True,
                text=True,
                input="",
                env=rsync_env(ctx),
                timeout=ctx.timeout,
            )
        except subprocess.TimeoutExpired:
            ctx.out("Write-based path traversal timed out", "OK", indent=4)
            return
        except FileNotFoundError:
            ctx.out("rsync client binary not found on this machine", "ERROR", indent=4)
            return

        if upload.returncode != 0:
            error = upload.stderr.strip().splitlines()
            detail = error[0] if error else f"rsync exited with status {upload.returncode}"
            ctx.out(f"Write-based path traversal was unsuccessful: {detail}", "OK", indent=4)
            return

        ctx.out("Write-based path traversal successful", "VULN", indent=4)

        empty_dir = os.path.join(tmpdir, "empty")
        os.makedirs(empty_dir)
        try:
            cleanup = subprocess.run(
                [
                    "rsync",
                    "-r",
                    "--no-motd",
                    "--delete",
                    "--include",
                    marker_name,
                    "--exclude",
                    "*",
                    f"{empty_dir}/",
                    rsync_url(ctx, f"{traversal_dir}/"),
                ],
                capture_output=True,
                text=True,
                input="",
                env=rsync_env(ctx),
                timeout=ctx.timeout,
            )
        except subprocess.TimeoutExpired:
            ctx.out("Could not confirm removal of the traversal marker (cleanup timed out)", "WARN", indent=4)
            return

        if cleanup.returncode != 0:
            ctx.out("Could not remove the temporary traversal marker", "WARN", indent=4)
            ctx.debug(f"Path traversal marker cleanup failed: {cleanup.stderr.strip()}")


def run(ctx):
    _try_path_traversal(ctx)
    _try_path_traversal_write(ctx)