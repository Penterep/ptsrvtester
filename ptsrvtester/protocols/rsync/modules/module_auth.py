import socket
from ptsrvtester.protocols.rsync.utils.registry import receive
from io import BufferedReader
from ptthreads.ptthreads import ptthreads
from ptsrvtester.protocols.rsync.modules.grab_modules import rsync_grab_modules

__MODULELABEL__ = "Rsync module authentication enumeration"
__MODULECODE__ = "module_auth"
__ORDER__ = 100


def _check_module_for_auth(sock: socket.socket, f: BufferedReader , module, ctx) -> str:
    try:
        motd = ""
        sock.sendall(f"{module}\n".encode())
        while True:
            line = f.readline()

            if not line:
                return ""

            text: str = line.decode(errors="replace").rstrip("\n")

            if text.startswith("@RSYNCD: OK"):
                ctx.out(f"The '{module}' module does not require authentication",
                        "VULN", indent=4)
                return motd
            elif text.startswith("@ERROR"):
                ctx.out(f"Received an error while probing the '{module}' authentication: {text}", "ERROR", indent=4)
                return motd
            elif text.startswith("@RSYNCD: AUTHREQD"):
                reqd_auth = text[len('@RSYNCD: AUTHREQD '):].strip()
                ctx.out(f"The '{module}' module requires authentication: {reqd_auth}",
                        "OK", indent=4)
                return reqd_auth
            elif text.startswith("@RSYNCD: END"):
                ctx.out(f"The server terminated the connection", "OK", indent=4)
                return ""
            else:
                ctx.out(f"Received unknown response from server: {text}", "ERROR", indent=4)
                motd += text

    except Exception as e:
        ctx.out(f"Error checking module for authentication: {e}", "ERROR", indent=4)


def _check_module(module):
    try:
        with socket.create_connection((module.get("ctx").ip, module.get("ctx").port), timeout=module.get("ctx").timeout) as sock:
            sock.settimeout(module.get("ctx").timeout)
            f = sock.makefile("rb")

            data = receive(sock)
            banner = data.decode(errors="replace").rstrip('\n')
            banner_header = banner.split("\n")[0]
            if not banner:
                return

            sock.sendall(f"{banner_header}\n".encode())

            r = _check_module_for_auth(sock, f, module.get("module"), module.get("ctx"))

    except Exception as e:
        module.get("ctx").out(f"Error enumerating modules: {e}", "ERROR", condition=not module.get("ctx").json, indent=4)


def _rsync_check_modules_for_auth(ctx):
    threads = ptthreads()
    if ctx.modules:
        modules = [{"module": m, "ctx": ctx} for m in ctx.modules]
    else:
        modules = [{"module": m, "ctx": ctx} for m in rsync_grab_modules(ctx, print=False)]

    threads.threads(modules, _check_module, 10)


def run(ctx):
    _rsync_check_modules_for_auth(ctx)