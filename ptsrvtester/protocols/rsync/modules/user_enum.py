import secrets
import subprocess
import sys

from ptlibs.ptprinthelper import ptprint
from ptsrvtester.protocols.rsync.utils.registry import rsync_env, rsync_url


__MODULELABEL__ = "Rsync username enumeration"
__MODULECODE__ = "USER_ENUM"
__ORDER__ = 95

_INVALID_PASSWORD = "ptsrvtester-user-enum-invalid"


def _probe_user(ctx, module: str, username: str):
    timeout = ctx.timeout or 5
    command = [
        ctx.rsync_path,
        "--list-only",
        "--no-motd",
        f"--contimeout={timeout}",
        f"--timeout={timeout}",
        rsync_url(ctx, f"{module}/", username=username),
    ]
    env = rsync_env(ctx)
    env["RSYNC_PASSWORD"] = _INVALID_PASSWORD

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        input="",
        env=env,
        timeout=timeout + 2,
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def run(ctx):
    modules = getattr(ctx.args, "modules", None) or []
    modules = [module.strip() for module in modules if module.strip()]
    if len(modules) != 1:
        ctx.out("USER_ENUM requires exactly one module via -m/--modules", "ERROR", indent=4)
        return

    username_file = getattr(ctx.args, "users", None)
    if username_file:
        try:
            with open(username_file, encoding="utf-8") as usernames:
                username_list = list(dict.fromkeys(
                    line.strip() for line in usernames if line.strip()
                ))
        except OSError as e:
            ctx.out(f"Could not read username file '{username_file}': {e}", "ERROR", indent=4)
            return
    else:
        username = getattr(ctx.args, "user", None)
        username_list = [username] if username else []

    if not username_list:
        ctx.out("USER_ENUM requires a username via -u/--user or -U/--users", "ERROR", indent=4)
        return
    if not ctx.rsync_path:
        ctx.out("The rsync client is required for username enumeration", "ERROR", indent=4)
        return

    module = modules[0]
    try:
        baseline_user = f"ptenum_{secrets.token_hex(8)}"
        baseline = _probe_user(ctx, module, baseline_user)
        ctx.debug(
            f"Baseline response for random username '{baseline_user}': "
            f"returncode={baseline[0]}, stdout={baseline[1]!r}, stderr={baseline[2]!r}"
        )
    except subprocess.TimeoutExpired:
        ctx.out(f"Timed out checking authentication for module '{module}'", "ERROR", indent=4)
        return
    except OSError as e:
        ctx.out(f"Error checking rsync authentication: {e}", "ERROR", indent=4)
        return

    show_progress = not ctx.json and sys.stdout.isatty()
    progress_line = None
    try:
        for index, username in enumerate(username_list, start=1):
            progress_line = (
                f"Trying username {index}/{len(username_list)}: '{username}' "
                f"for module '{module}'"
            )
            if show_progress:
                ptprint(
                    progress_line,
                    "INFO",
                    condition=True,
                    end="\r",
                    flush=True,
                    clear_to_eol=True,
                    indent=4,
                )

            try:
                response = _probe_user(ctx, module, username)
            except subprocess.TimeoutExpired:
                ctx.out(
                    f"Timed out checking username '{username}' for module '{module}'",
                    "ERROR",
                    indent=4,
                )
                return
            except OSError as e:
                ctx.out(f"Error checking rsync credentials: {e}", "ERROR", indent=4)
                return

            ctx.debug(
                f"Response for username '{username}': returncode={response[0]}, "
                f"stdout={response[1]!r}, stderr={response[2]!r}"
            )
            if response != baseline:
                ctx.out(f"Possible username found: {username}", "VULN", indent=4)
    finally:
        if show_progress and progress_line is not None:
            ptprint(
                progress_line,
                "INFO",
                condition=True,
                end="\n",
                flush=True,
                clear_to_eol=True,
                indent=4,
            )