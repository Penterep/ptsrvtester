import shutil
import subprocess

def check_rsync_path() -> str:
    path = shutil.which("rsync")

    return path    

def split_module_list(modules: str) -> list:
    return modules.split(",")

def rsync_grab_modules(ctx, printer=True, include_motd=False):
    rsync_path = check_rsync_path()
    if rsync_path is None:
        return []

    timeout = getattr(ctx, "timeout", None) or 10
    port = getattr(ctx, "port", 873)
    command = [
        rsync_path,
        "--list-only",
        "--no-motd",
        f"--contimeout={timeout}",
        f"--timeout={timeout}",
        f"rsync://{ctx.ip}:{port}/",
    ]

    if include_motd:
        command.remove("--no-motd")

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            input="",
            timeout=timeout + 2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []

    if result.returncode != 0:
        return []    
    
    return [line.strip().split()[0] for line in result.stdout.splitlines() if line.strip()]