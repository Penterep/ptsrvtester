"""EICAR — APPEND antivirus probe."""
from ._common import eng

__MODULELABEL__ = "EICAR APPEND"
__MODULECODE__ = "EICAR"
__ORDER__ = 110


def run(ctx):
    e = eng(ctx)
    e.args.eicar = True
    try:
        e.results.eicar = e.test_eicar_append()
    except Exception as ex:
        e.results.eicar_error = str(ex)
        ctx.out(f"EICAR probe failed: {ex}", "ERROR", indent=4)
        return
    e._stream_eicar_result()
