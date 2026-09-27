"""ANON — Anonymous authentication."""
__MODULELABEL__ = "Anonymous authentication"
__MODULECODE__ = "ANON"
__ORDER__ = 40

from ._common import eng
def run(ctx):
    e = eng(ctx)
    try:
        if e.ftp is None:
            e.ftp = e.connect(trace=True)
        e.results.anonymous = e.anonymous()
    except Exception as ex:
        e.results.anonymous_error = str(ex)
        ctx.out(f"Anonymous probe failed: {ex}", "ERROR", indent=4)
        return
    e._stream_anonymous_result()

