"""BANNER — greeting + service identification."""
from ..utils.connection import require_server_info
from ..utils.render import emit_banner

__MODULELABEL__ = "Banner"
__MODULECODE__ = "BANNER"
__ORDER__ = 10


def run(ctx):
    info = require_server_info(ctx)
    if info is None:
        return
    emit_banner(ctx, info)
