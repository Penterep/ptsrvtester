"""RESLOAD — APPEND + SEARCH resource-load stress."""
from ._common import eng

__MODULELABEL__ = "Resource load"
__MODULECODE__ = "RESLOAD"
__ORDER__ = 130


def run(ctx):
    e = eng(ctx)
    e.args.imap_resource_load = True
    try:
        e.results.imap_resource_load = e.test_imap_resource_load()
    except Exception as ex:
        e.results.imap_resource_load_error = str(ex)
        ctx.out(f"RESLOAD failed: {ex}", "ERROR", indent=4)
        return
    e._stream_imap_resource_load_result()
