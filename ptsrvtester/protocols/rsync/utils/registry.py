import socket, shutil, argparse


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

def check_rsync_path() -> str:
    path = shutil.which("rsync")

    return path    

def split_module_list(modules: str) -> list:
    return modules.split(",")

def _sanitize_rsync_data(data: list):
    if '\n' in data:
        data.remove('\n')

    for e in data:
        if "@RSYNCD" in e:
            data.pop(data.index(e))

    return list(filter(None, data))

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
        return [e]