"""BANNER — Banner."""
__MODULELABEL__ = "Banner"
__MODULECODE__ = "BANNER"
__ORDER__ = 10

from ._common import ensure_info
def run(ctx):
    e = ensure_info(ctx, get_commands=True)
    if getattr(e.results, "info_error", None):
        return
    e._stream_banner_result()

