"""USRENUM — Username enumeration."""
__MODULELABEL__ = "Username enumeration"
__MODULECODE__ = "USRENUM"
__ORDER__ = 70

from ._common import eng
def run(ctx):
    e = eng(ctx)
    e.args.user_enum = True
    try:
        e.results.user_enum = e.test_user_enumeration()
    except Exception as ex:
        e.results.user_enum_error = str(ex)
        ctx.out(f"USRENUM failed: {ex}", "ERROR", indent=4)
        return
    e._stream_user_enum_result()

