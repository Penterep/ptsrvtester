"""BANNER — greeting + service identification."""
from ._common import ensure_info

__MODULELABEL__ = "Banner"
__MODULECODE__ = "BANNER"
__ORDER__ = 10


def run(ctx):
    e = ensure_info(ctx, get_commands=True)
    if getattr(e.results, "info_error", None):
        return
    e._stream_banner_result()
