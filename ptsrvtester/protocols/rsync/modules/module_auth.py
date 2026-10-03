import re
import subprocess
from ptthreads.ptthreads import ptthreads
from ptsrvtester.protocols.rsync.modules.grab_modules import rsync_grab_modules
from ptsrvtester.protocols.rsync.utils.registry import rsync_env, rsync_url

__MODULELABEL__ = "Rsync module authentication enumeration"
__MODULECODE__ = "module_auth"
__ORDER__ = 100


def _check_module(module):
    ctx = module["ctx"]
    module_name = module["module"]
    timeout = ctx.timeout or 10
    command = [
        ctx.rsync_path,
        "--list-only",
        "--no-motd",
        f"--contimeout={timeout}",
        f"--timeout={timeout}",
        rsync_url(ctx, f"{module_name}/"),
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            input="",
            env=rsync_env(ctx),
            timeout=timeout + 2,
        )
    except subprocess.TimeoutExpired:
        ctx.out(f"Timed out checking authentication for '{module_name}'", "ERROR", indent=4)
        return
    except OSError as e:
        ctx.out(f"Error checking authentication for '{module_name}': {e}", "ERROR", indent=4)
        return

    output = f"{result.stdout}\n{result.stderr}"
    if re.search(
        r"@RSYNCD:\s*AUTHREQD|auth(?:entication)?\s+(?:is\s+)?(?:required|failed)|password\s*:",
        output,
        re.IGNORECASE,
    ):
        ctx.out(f"The '{module_name}' module requires authentication", "OK", indent=4)
    elif result.returncode == 0:
        if getattr(ctx, "user", None) or getattr(ctx, "password", None):
            ctx.out(f"The '{module_name}' module is accessible with the supplied credentials", "INFO", indent=4)
        else:
            ctx.out(f"The '{module_name}' module does not require authentication", "VULN", indent=4)
    else:
        detail = result.stderr.strip() or result.stdout.strip() or f"rsync exited with status {result.returncode}"
        ctx.out(f"Error checking '{module_name}' authentication: {detail}", "ERROR", indent=4)


def _rsync_check_modules_for_auth(ctx):
    threads = ptthreads()
    module_names = getattr(ctx, "modules", None)
    if module_names is None:
        module_names = rsync_grab_modules(ctx, print=False)
    modules = [{"module": m, "ctx": ctx} for m in module_names or []]

    if not modules:
        ctx.out(f"No modules available for authentication detection", "INFO", indent=4)
        return

    if ctx.rsync_path is None:
        ctx.out("The rsync client is required for module authentication detection", "ERROR", indent=4)
        return
    
    threads.threads(modules, _check_module, 10)


def run(ctx):
    _rsync_check_modules_for_auth(ctx)