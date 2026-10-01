import os
import subprocess
import re
from dataclasses import dataclass
from ptsrvtester.protocols.rsync.utils.registry import rsync_grab_modules

__MODULELABEL__ = "Rsync module enumeration"
__MODULECODE__ = "grab_modules"
__ORDER__ = 100

@dataclass
class RsyncEntry:
    permissions: str
    size: int
    mtime: str
    name: str
    symlink_target: str | None = None
    
@dataclass
class Module:
    name: str
    entries: list[RsyncEntry]


class RsyncPasswordRequired(RuntimeError):
    pass


# Matches lines like:
# drwxr-xr-x          4,096 2024/01/15 10:30:00 somedir
# -rw-r--r--      1,234,567 2024/01/15 10:30:12 somefile.txt
# lrwxrwxrwx             11 2024/01/15 10:30:12 alink -> target
_LINE_RE = re.compile(
    r'^([bcdlpsD-][rwxstST-]{9})\s+'   # permissions
    r'([\d,]+)\s+'                     # size (comma-grouped)
    r'(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\s+'  # mtime
    r'(.+)$'                           # name (possibly "name -> target")
)


def _print_modules(modules: list[Module], ctx) -> None:
    ctx.out("Grabbed available modules", "VULN", indent=4, condition=modules)
    for module in modules:
        ctx.out(f"{module.name}", "INFO", indent=8)
        for entry in module.entries:
            sym = f" -> {entry.symlink_target}" if entry.symlink_target else ""
            ctx.out(f"{entry.permissions} {entry.size:>12} {entry.mtime} {entry.name} {sym}", "TEXT", indent=12, colortext=True)


def list_module_contents(host, module, recursive=False, timeout=15):
    url = f"rsync://{host}/{module}/"
    cmd = ["rsync", "--list-only", "--no-motd"]
    if recursive:
        cmd.append("-r")
    cmd.append(url)

    env = os.environ.copy()
    env["RSYNC_PASSWORD"] = "ptsrvtester-auth-probe-invalid"
    result = subprocess.run(
        cmd, capture_output=True, text=True, input="", env=env, timeout=timeout
    )
    output = f"{result.stdout}\n{result.stderr}"
    if re.search(
        r"password\s*:|@RSYNCD:\s*AUTHREQD|auth(?:entication)?\s+(?:is\s+)?(?:required|failed)",
        output,
        re.IGNORECASE,
    ):
        return []
    if result.returncode != 0:
        return []

    entries = []
    for line in result.stdout.splitlines():
        m = _LINE_RE.match(line)
        if not m:
            continue  # skip stray MOTD/blank lines
        perms, size_str, mtime, name = m.groups()
        target = None
        if perms.startswith('l') and ' -> ' in name:
            name, target = name.split(' -> ', 1)
        entries.append(RsyncEntry(
            permissions=perms,
            size=int(size_str.replace(',', '')),
            mtime=mtime,
            name=name,
            symlink_target=target,
        ))
    return entries 


def probe_module_names(ctx, module_names, modules):
    for module_name in module_names:
                if ctx.rsync_path is None:
                    entries = []
                else:
                    try:
                        entries = list_module_contents(
                            ctx.ip, module_name, timeout=ctx.timeout or 15
                        )
                    except subprocess.TimeoutExpired:
                        ctx.out(f"Timed out listing the '{module_name}' module", "ERROR", indent=8)
                        entries = []
                    except RsyncPasswordRequired as e:
                        ctx.out(str(e), "OK", indent=8)
                        entries = []
                modules.append(Module(name=module_name, entries=entries))   


def run(ctx):
    module_names = getattr(ctx, "modules", None)
    if module_names is None:
        module_names = rsync_grab_modules(ctx) or rsync_grab_modules(ctx, include_motd=True)
    modules: list[Module] = []

    if module_names:
        probe_module_names(ctx, module_names, modules)
    else:
        ctx.out("Could not list modules or server doesn't have any", "OK", indent=4,
            condition=not ctx.json and print)
    
    _print_modules(modules=modules, ctx=ctx)
