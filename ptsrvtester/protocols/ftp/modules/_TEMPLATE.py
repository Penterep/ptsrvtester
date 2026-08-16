"""TEMPLATE — copy to modules/<name>.py (_ prefix = not loaded)."""
__MODULELABEL__ = "Template (never runs)"
__MODULECODE__ = "TEMPLATE"
__ORDER__ = 100

def run(ctx):
    ip, port = ctx.target
    ctx.out(f'Would check {ip}:{port} here.', 'TEXT')
