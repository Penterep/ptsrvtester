import subprocess
import sys

from ptsrvtester.protocols.rsync.utils.registry import rsync_env, rsync_url
from ptlibs.ptprinthelper import ptprint


__MODULELABEL__ = "Rsync module password bruteforce"
__MODULECODE__ = "PASS_BRUTE"
__ORDER__ = 90


def _try_password(ctx, module: str, username: str, password: str) -> bool:
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
    env["RSYNC_PASSWORD"] = password

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        input="",
        env=env,
        timeout=timeout + 2,
    )
    return result.returncode == 0 

def run(ctx):
    modules = getattr(ctx.args, "modules", None) or []
    modules = [module.strip() for module in modules if module.strip()]
    if len(modules) != 1:
        ctx.out("PASS_BRUTE requires exactly one module via -m/--modules", "ERROR", indent=4)
        return
    username = ctx.user
    username_file = getattr(ctx.args, "users", None)
    try:
        if not username and username_file:
            with open(username_file, encoding="utf-8") as usernames:
                username_list = list(dict.fromkeys(
                    name.strip() for name in usernames if name.strip()
                ))
        else:
            username_list = [username] if username else []
    except OSError as e:
        ctx.out(f"Could not read username file '{username_file}': {e}", "ERROR", indent=4)
        return
    if not username_list:
        ctx.out(
            "PASS_BRUTE requires a username via -u/--user or -U/--users",
            "ERROR",
            indent=4,
        )
        return
    if not ctx.args.passwords:
        ctx.out("PASS_BRUTE requires a password list via -P/--passwords", "ERROR", indent=4)
        return
    if not ctx.rsync_path:
        ctx.out("The rsync client is required for password bruteforce", "ERROR", indent=4)
        return

    attempts = 0
    show_progress = not ctx.json and sys.stdout.isatty()
    progress_line = None
    try:
        with open(ctx.args.passwords, encoding="utf-8") as passwords:
            try:
                for username in username_list:
                    passwords.seek(0)
                    for line in passwords:
                        password = line.rstrip("\r\n")
                        if not password:
                            continue
                        attempts += 1
                        progress_line = (
                            f"Trying user '{username}' and password '{password}' "
                            f"for module '{modules[0]}' (attempt {attempts})"
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
                            matched = _try_password(ctx, modules[0], username, password)
                        except subprocess.TimeoutExpired:
                            ctx.out(
                                f"Timed out checking credentials for module '{modules[0]}'",
                                "ERROR",
                                indent=4,
                            )
                            return
                        except OSError as e:
                            ctx.out(f"Error checking rsync credentials: {e}", "ERROR", indent=4)
                            return
                        if matched:
                            if ctx.json:
                                node = ctx.ptjsonlib.create_node_object(
                                    "rsync_module_credentials",
                                    properties={
                                        "module": modules[0],
                                        "user": username,
                                        "password": password,
                                    },
                                )
                                ctx.ptjsonlib.add_node(node)
                            ctx.out(
                                f"Valid credentials for module '{modules[0]}': "
                                f"user '{username}', password '{password}'",
                                "VULN",
                                indent=4,
                            )
                            return
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
    except OSError as e:
        ctx.out(f"Could not read password list '{ctx.args.passwords}': {e}", "ERROR", indent=4)
        return

    ctx.out(
        f"No valid password found for module '{modules[0]}' after {attempts} attempts",
        "OK",
        indent=4,
    )