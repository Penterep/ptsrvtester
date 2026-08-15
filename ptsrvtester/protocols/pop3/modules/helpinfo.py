"""HELPINFO — HELP command + IMPLEMENTATION from CAPA."""
from ..utils.connection import fetch_help_info, require_server_info
from ..utils.render import emit_helpinfo

__MODULELABEL__ = "Help/Implementation info"
__MODULECODE__ = "HELPINFO"
__ORDER__ = 50


def run(ctx):
    info = require_server_info(ctx)
    if info is None:
        return

    # CAPA comes from the shared probe; HELP needs its own short-lived connection.
    capa = info.capability_stls or info.capability
    try:
        pop3 = ctx.connect(debug=ctx.debug)
        try:
            hi = fetch_help_info(pop3, capa, debug=ctx.debug)
        finally:
            pop3.close()
    except Exception as e:
        ctx.out(f"HELP probe failed: {e}", "ERROR", indent=4)
        return

    emit_helpinfo(ctx, hi.help_response, hi.implementation)
