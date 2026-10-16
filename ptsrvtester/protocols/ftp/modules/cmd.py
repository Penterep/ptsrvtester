"""CMD — HELP / SYST / STAT."""
__MODULELABEL__ = ""  # section title is printed with the command list
__MODULECODE__ = "CMD"
__ORDER__ = 20

from ._common import eng, ensure_info
def run(ctx):
    e = eng(ctx)
    e.results.commands_requested = True
    e = ensure_info(ctx, get_commands=True)
    if getattr(e.results, "info_error", None):
        return
    e._stream_commands_result()

