import shutil
import subprocess

def check_rsync_path() -> str:
    path = shutil.which("rsync")

    return path    

def split_module_list(modules: str) -> list:
    return modules.split(",")


def _modules_from_motd(output):
    modules = []
    table_started = False
    saw_content = False
    blank_after_content = False

    for line in output.splitlines():
        if not line.strip():
            if saw_content:
                blank_after_content = True
            continue

        module_name, separator, _ = line.partition("\t")
        module_name = module_name.strip()
        is_module = bool(
            separator and module_name and not any(c.isspace() for c in module_name)
        )

        if not table_started:
            if is_module and (not saw_content or blank_after_content):
                table_started = True
                modules.append(module_name)
                continue
            saw_content = True
            blank_after_content = False
            continue

        if not is_module:
            break
        modules.append(module_name)

    return modules


def rsync_grab_modules(ctx, printer=True, include_motd=False):
    rsync_path = check_rsync_path()
    if rsync_path is None:
        return []

    timeout = getattr(ctx, "timeout", None) or 3
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