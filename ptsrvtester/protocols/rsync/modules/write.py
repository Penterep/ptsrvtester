import socket, tempfile, subprocess, os, re
from datetime import datetime, timezone
from ptthreads.ptthreads import ptthreads
from ptsrvtester.protocols.rsync.utils.registry import rsync_env, rsync_url


__MODULELABEL__ = "Rsync write probe"
__MODULECODE__ = "write"
__ORDER__ = 100


def check_write_access(module_dict: dict):
    ctx = module_dict.get("ctx")
    module = module_dict.get("module")
    cleanup = True
    
    marker_name = f"pentest_write_check_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}.txt"
    marker_content = (
        "Authorized rsync write-access test marker. Safe to delete.\n"
        f"Created {datetime.now(timezone.utc).isoformat()}\n"
    )
 
    result = {"module": module, "write_allowed": False}
    env = rsync_env(ctx)
 
    with tempfile.TemporaryDirectory() as tmpdir:
        local_path = os.path.join(tmpdir, marker_name)
        with open(local_path, "w") as f:
            f.write(marker_content)

        ctx.debug(f"Created temporary write probe at {local_path}", indent=4)
        
        upload_url = rsync_url(ctx, f"{module}/{marker_name}")
        try:
            command = ["rsync", "--contimeout=5", local_path, upload_url]
            ctx.debug(f"Uploading write probe with command: \"{command}\"", indent=4)
            
            upload = subprocess.run(
                command,
                capture_output=True, text=True, input="", env=env, timeout=ctx.timeout,
            )
            
            ctx.debug(f"Received stdout: {upload.stdout.rstrip}", indent=4)
            ctx.debug(f"Received stderr: {upload.stderr.rstrip}", indent=4)
            
            result["upload_returncode"] = upload.returncode
            result["upload_stderr"] = upload.stderr[:1000]

            if re.search(
                r"password\s*:|@RSYNCD:\s*AUTHREQD|auth(?:entication)?\s+(?:is\s+)?(?:required|failed)",
                upload.stderr + upload.stdout,
                re.IGNORECASE,
            ):
                result["auth_required"] = True
                result["error"] = "rsync requires a password for this module"
                return result
 
            if upload.returncode == 0:
                result["write_allowed"] = True

                verify = subprocess.run(
                    ["rsync", "--list-only", "--contimeout=5",
                     rsync_url(ctx, f"{module}/{marker_name}")],
                    capture_output=True, text=True, input="", env=env, timeout=ctx.timeout,
                )
                result["verified_present"] = verify.returncode == 0

                if cleanup:
                    empty_dir = os.path.join(tmpdir, "empty")
                    os.makedirs(empty_dir, exist_ok=True)
                    delete_cmd = [
                        "rsync", "-r", "--contimeout=5", "--delete",
                        "--include", marker_name, "--exclude", "*",
                        f"{empty_dir}/",
                        rsync_url(ctx, f"{module}/"),
                    ]
                    
                    ctx.debug(f"Executing cleanup: \"{' '.join(delete_cmd)}\"", indent=4)
                    
                    delcheck = subprocess.run(
                        delete_cmd,
                        capture_output=True,
                        text=True,
                        input="",
                        env=env,
                        timeout=ctx.timeout,
                    )
                    result["cleanup_returncode"] = delcheck.returncode
                    result["cleanup_stderr"] = delcheck.stderr[:1000]
        except subprocess.TimeoutExpired:
            result["error"] = "timeout"
        except FileNotFoundError:
            result["error"] = "rsync client binary not found on this machine"

    return result


def run(ctx):
    threads = ptthreads()

    if not ctx.modules:
        ctx.out(f"No modules available to probe for write access", "OK", indent=4)
        return

    modules = [{"module": m, "ctx": ctx} for m in ctx.modules or []]

    res = threads.threads(modules, check_write_access, 10)

    for r in res:
        if r["write_allowed"]:
            ctx.out(f"The module {r.get("module")} is writable", "VULN", indent=4)
            ctx.ptjsonlib.add_vulnerability()
        else:
            cleanup_stderr = r.get("cleanup_stderr", r.get("upload_stderr", "")).strip()
            ctx.out(f"The module {r.get("module")} is not writable", "OK", indent=4)
            ctx.debug(f"{cleanup_stderr}")
