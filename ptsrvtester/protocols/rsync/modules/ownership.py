import os
import re
import subprocess
import tempfile
import uuid

from ptsrvtester.protocols.rsync.utils.registry import rsync_env, rsync_url


__MODULELABEL__ = "Rsync daemon UID/GID probe"
__MODULECODE__ = "ownership"
__ORDER__ = 90

_ID_PATTERN = re.compile(r"(\d+|DEFAULT)\|(\d+|DEFAULT)\|(.+)")

def _cleanup_probe(ctx, module, probe_name, empty_dir, env):
    try:
        cleanup = subprocess.run(
            [
                "rsync",
                "-r",
                "--no-motd",
                "--contimeout=5",
                "--delete",
                "--include",
                probe_name,
                "--exclude",
                "*",
                f"{empty_dir}/",
                rsync_url(ctx, f"{module}/"),
            ],
            capture_output=True,
            text=True,
            input="",
            env=env,
            timeout=ctx.timeout,
        )
    except subprocess.TimeoutExpired:
        ctx.out(f"Could not confirm removal of the ownership probe from module {module} (timed out)", "WARN", indent=4)
    except FileNotFoundError:
        ctx.out("rsync client binary not found on this machine", "ERROR", indent=4)
    else:
        if cleanup.returncode != 0:
            ctx.out(f"Could not remove the ownership probe from module {module}", "WARN", indent=4)
            ctx.debug(f"Ownership probe cleanup failed: {cleanup.stderr.strip()}")


def _probe_module(ctx, module):
    probe_name = f"ptsrvtester_owner_{uuid.uuid4().hex}"
    env = rsync_env(ctx)

    with tempfile.TemporaryDirectory() as tmpdir:
        probe_path = os.path.join(tmpdir, probe_name)
        download_path = os.path.join(tmpdir, "download")
        empty_dir = os.path.join(tmpdir, "empty")
        os.makedirs(empty_dir)
        with open(probe_path, "w", encoding="utf-8") as probe:
            probe.write("Temporary rsync ownership probe.\n")

        try:
            upload = subprocess.run(
                [
                    "rsync",
                    "--no-motd",
                    "--contimeout=5",
                    "--no-o",
                    "--no-g",
                    probe_path,
                    rsync_url(ctx, f"{module}/{probe_name}"),
                ],
                capture_output=True,
                text=True,
                input="",
                env=env,
                timeout=ctx.timeout,
            )
        except subprocess.TimeoutExpired:
            ctx.out(f"Ownership probe upload to module {module} timed out", "WARN", indent=4)
            _cleanup_probe(ctx, module, probe_name, empty_dir, env)
            return False
        except FileNotFoundError:
            ctx.out("rsync client binary not found on this machine", "ERROR", indent=4)
            return False

        if upload.returncode != 0:
            error = upload.stderr.strip().splitlines()
            detail = error[0] if error else f"rsync exited with status {upload.returncode}"
            ctx.out(f"Module {module} is not writable: {detail}", "OK", indent=4)
            _cleanup_probe(ctx, module, probe_name, empty_dir, env)
            return False

        found_ids = False
        try:
            try:
                query = subprocess.run(
                    [
                        "rsync",
                        "--dry-run",
                        "--archive",
                        "--numeric-ids",
                        "--no-motd",
                        "--contimeout=5",
                        f"--out-format=%U|%G|%n",
                        rsync_url(ctx, f"{module}/{probe_name}"),
                        download_path,
                    ],
                    capture_output=True,
                    text=True,
                    input="",
                    env=env,
                    timeout=ctx.timeout,
                )
            except subprocess.TimeoutExpired:
                ctx.out(f"Timed out reading UID/GID from module {module}", "WARN", indent=4)
                return False
            except FileNotFoundError:
                ctx.out("rsync client binary not found on this machine", "ERROR", indent=4)
                return False

            match = _ID_PATTERN.search(query.stdout)

            if query.returncode != 0:
                error = query.stderr.strip().splitlines()
                detail = error[0] if error else f"rsync exited with status {query.returncode}"
                ctx.out(f"Could not read file ownership from module {module}: {detail}", "WARN", indent=4)
            elif match is None:
                ctx.out(f"Could not parse UID/GID from module {module} dry-run output", "WARN", indent=4)
                ctx.debug(f"Ownership probe dry-run output: {query.stdout.strip()}")
            else:
                uid, gid, file_name = match.groups()
                if uid == "0" and gid == "DEFAULT":
                    ctx.out(f"Module {module} returned default UID/GID (0/DEFAULT) for the uploaded file. "
                            f"Try running the test as root", "OK", indent=4)
                else:
                    ctx.out(f"Rsync daemon file UID: {uid}, GID: {gid} (module {module})", "VULN", indent=4)
                found_ids = True
        finally:
            _cleanup_probe(ctx, module, probe_name, empty_dir, env)

        return found_ids


def run(ctx):
    if not ctx.modules:
        ctx.out("No modules available to test for rsync ownership", "OK", indent=4)
        return

    for module in ctx.modules:
        if _probe_module(ctx, module):
            return

    ctx.out("Could not obtain rsync daemon UID/GID from any module", "OK", indent=4)