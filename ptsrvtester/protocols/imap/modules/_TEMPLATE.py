"""TEMPLATE — copy to modules/<name>.py (files starting with ``_`` are not loaded).

    __MODULELABEL__  section header printed by BaseMain
    __MODULECODE__   -ts code (default: FILENAME.upper())
    __ORDER__        run/print order (default: 100)

    def run(ctx): ...

ctx IMAP extras: engine, report, host, ip, port, tls, starttls
"""

__MODULELABEL__ = "Template (never runs)"
__MODULECODE__ = "TEMPLATE"
__ORDER__ = 100


def run(ctx):
    ip, port = ctx.target
    ctx.out(f"Would check {ip}:{port} here.", "TEXT")
