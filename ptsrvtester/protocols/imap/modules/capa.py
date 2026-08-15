"""CAPA — ID + CAPABILITY listing."""
from ._common import ensure_info

__MODULELABEL__ = "CAPABILITY"
__MODULECODE__ = "CAPA"
__ORDER__ = 20


def run(ctx):
    e = ensure_info(ctx, get_commands=True)
    if getattr(e.results, "info_error", None):
        return
    e._stream_capa_result()
