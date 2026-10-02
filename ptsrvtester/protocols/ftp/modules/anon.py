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
        low = str(ex).lower()
        if "timed out" in low or "timeout" in low:
            ctx.out("USER anonymous timed out (not confirmed)", "WARNING", indent=4)
        else:
            ctx.out(f"Anonymous probe failed: {ex}", "ERROR", indent=4)
        return
    e._stream_anonymous_result()

