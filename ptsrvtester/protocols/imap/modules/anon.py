"""ANON — SASL ANONYMOUS + weak LOGIN probes."""
from ._common import eng

__MODULELABEL__ = "Anonymous authentication"
__MODULECODE__ = "ANON"
__ORDER__ = 50


def run(ctx):
    e = eng(ctx)
    try:
        e.results.anonymous = e.test_anonymous_access()
    except Exception as ex:
        e.results.anonymous_error = str(ex)
        ctx.out(f"Anonymous probe failed: {ex}", "ERROR", indent=4)
        return
    e._stream_anonymous_result()
