import socket


__MODULELABEL__ = "Rsync module enumeration"
__MODULECODE__ = "grab_modules"
__ORDER__ = 100


def _sanitize_rsync_data(data: list):
    if '\n' in data:
        data.remove('\n')

    for e in data:
        if "@RSYNCD" in e:
            data.pop(data.index(e))

    return list(filter(None, data))

def _print_modules(modules, ctx) -> None:
    modules = _sanitize_rsync_data(modules.split('\n'))
    for module in modules:
        ctx.out(f"{module}", "INFO", indent=8)


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


def _rsync_grab_modules(ctx):
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
            if modules:
                ctx.out(f"Grabbed available modules", "VULN", indent=4)
                _print_modules(modules, ctx)
            else:
                ctx.out("Could not list modules or server doesn't have any", "OK", indent=4)

    except Exception as e:
        ctx.out(f"Error grabbing modules: {e}", "ERROR", condition=not ctx.json, indent=4)


def run(ctx):
    _rsync_grab_modules(ctx)