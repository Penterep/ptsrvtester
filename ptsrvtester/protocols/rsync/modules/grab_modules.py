import socket, subprocess, re
from dataclasses import dataclass

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


def _sanitize_rsync_data(data: list):
    if '\n' in data:
        data.remove('\n')

    for e in data:
        if "@RSYNCD" in e:
            data.pop(data.index(e))

    return list(filter(None, data))

def _print_modules(modules: list[Module], ctx) -> None:
    ctx.out("Grabbed available modules", "VULN", indent=4)
    for module in modules:
        ctx.out(f"{module.name}", "INFO", indent=8)
        for entry in module.entries:
            sym = f" -> {entry.symlink_target}" if entry.symlink_target else ""
            ctx.out(f"{entry.permissions} {entry.size:>12} {entry.mtime} {entry.name} {sym}", "TEXT", indent=12, colortext=True)


def receive(sock: socket.socket) -> bytes:
    data = b""

    while True:
        try:
            chunk = sock.recv(8192)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk

        if b"@RSYNCD: EXIT" in data:
            break
        if b"@ERROR" in data:
            break

    return data


def list_module_contents(host, module, recursive=False, timeout=15):
    url = f"rsync://{host}/{module}/"
    cmd = ["rsync", "--list-only", "--no-motd"]
    if recursive:
        cmd.append("-r")
    cmd.append(url)

    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout
    )
    if result.returncode != 0:
        raise RuntimeError(f"rsync failed ({result.returncodewd}): {result.stderr.strip()}")

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


def rsync_grab_modules(ctx, print=True):
    try:
        with socket.create_connection((ctx.ip, ctx.port), timeout=ctx.timeout) as sock:
            sock.settimeout(ctx.timeout)

            data = receive(sock)
            banner = data.decode(errors="replace")

            if not banner:
                return

            sock.sendall(b"@RSYNCD: 31.0\n")
            sock.sendall(b"\n")

            data = receive(sock)

            modules = data.decode(errors="replace")

            modules = _sanitize_rsync_data(modules.split('\n'))
            return [module.split('\t')[0].strip() for module in modules]

    except Exception as e:
        ctx.out(f"Error grabbing modules: {e}", "ERROR", condition=not ctx.json and print, indent=4)

def run(ctx):
    module_names = rsync_grab_modules(ctx)
    modules: list[Module] = []

    if module_names:
        for module_name in module_names:
            if ctx.rsync_path is None:
                entries = []
            else:
                entries = list_module_contents(ctx.ip, module_name)
            modules.append(Module(name=module_name, entries=entries))        
    else:
        ctx.out("Could not list modules or server doesn't have any", "OK", indent=4,
                condition=not ctx.json and print)
    
    _print_modules(modules=modules, ctx=ctx)
