"""CMD — HELP / SYST / STAT."""
__MODULELABEL__ = "HELP / SYST / STAT"
__MODULECODE__ = "CMD"
__ORDER__ = 20

from ._common import ensure_info
def run(ctx):
    e = ensure_info(ctx, get_commands=True)
    if getattr(e.results, "info_error", None):
        return
    e._stream_commands_result()

