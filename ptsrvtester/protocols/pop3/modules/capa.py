"""CAPA — capability listing."""
from ..utils.connection import require_server_info
from ..utils.render import emit_capa

__MODULELABEL__ = ""  # section titles come from emit_capa (CAPA command PLAIN/STLS/…)
__MODULECODE__ = "CAPA"
__ORDER__ = 20


def run(ctx):
    info = require_server_info(ctx)
    if info is None:
        return
    emit_capa(ctx, info)
