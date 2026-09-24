"""INTERACT — interactive SMTP CLI."""
from ._common import ensure_info

__MODULELABEL__ = ""
__MODULECODE__ = "INTERACT"
__ORDER__ = 300


def run(ctx):
    e = ensure_info(ctx, get_commands=False)
    if getattr(e.results, "info_error", None) or e.use_json:
        return
    e.start_interactive_mode(e.smtp)
