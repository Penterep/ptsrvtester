"""TEMPLATE — copy to modules/<name>.py (files starting with ``_`` are not loaded).

    __MODULELABEL__  section header printed by BaseMain
    __MODULECODE__   -ts code (default: FILENAME.upper())
    __ORDER__        run/print order (default: 100)

    def run(ctx): ...

ctx core: args, target, ptjsonlib, out()/debug(), json/verbose
ctx POP3: host, ip, port, tls, starttls, connect(), server_info, report

Use ctx.report for structured findings (assembled into one software node in
POP3.output()). Prefer ctx.server_info.get()/require_server_info() over a
fresh connect when you only need banner/CAPA.
"""

__MODULELABEL__ = "Template (never runs)"
__MODULECODE__ = "TEMPLATE"
__ORDER__ = 100


def run(ctx):
    ip, port = ctx.target
    ctx.out(f"Would check {ip}:{port} here.", "TEXT")
