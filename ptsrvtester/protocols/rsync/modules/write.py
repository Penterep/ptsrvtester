import socket, tempfile, subprocess, os, re
from datetime import datetime, timezone


__MODULELABEL__ = "Rsync write probe"
__MODULECODE__ = "write"
__ORDER__ = 100


def check_write_access(ctx, module, cleanup=True):
    marker_name = f"pentest_write_check_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}.txt"
    marker_content = (
        "Authorized rsync write-access test marker. Safe to delete.\n"
        f"Created {datetime.now(timezone.utc).isoformat()}\n"
    )
 
    result = {"module": module, "write_allowed": False}
    env = os.environ.copy()
    env["RSYNC_PASSWORD"] = "ptsrvtester-auth-probe-invalid"
 
    with tempfile.TemporaryDirectory() as tmpdir:
        local_path = os.path.join(tmpdir, marker_name)
        with open(local_path, "w") as f:
            f.write(marker_content)
 
        upload_url = f"rsync://{ctx.ip}:{ctx.port}/{module}/{marker_name}"
        try:
            upload = subprocess.run(
                ["rsync", "--contimeout=5", local_path, upload_url],
                capture_output=True, text=True, input="", env=env, timeout=ctx.timeout,
            )
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
                     f"rsync://{ctx.ip}:{ctx.port}/{module}/{marker_name}"],
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
                        f"rsync://{ctx.ip}:{ctx.port}/{module}/",
                    ]
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
    for module in ctx.modules:
        res = check_write_access(ctx, module)
        if res["write_allowed"]:
            ctx.out(f"The module {module} is writable", "VULN", indent=4)
        else:
            cleanup_stderr = res.get("cleanup_stderr", res.get("upload_stderr", "")).strip()
            ctx.out(f"The module {module} is not writable", "OK", indent=4)
            ctx.debug(f"{cleanup_stderr}")
