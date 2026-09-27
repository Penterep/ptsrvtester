"""AUTHLIST — EHLO AUTH mechanisms (auth-focused JSON)."""
from ._common import ensure_info
from .ehlo import _stream_ehlo_result


__MODULELABEL__ = ""
__MODULECODE__ = "AUTHLIST"
__ORDER__ = 26


def run(ctx):
    e = ensure_info(ctx, get_commands=True)
    e.results.authentications_requested = True
    already_streamed = bool(e.results.commands_requested)
    e.results.commands_requested = True
    if getattr(e.results, "info_error", None):
        return
    if not already_streamed:
        _stream_ehlo_result(e)
