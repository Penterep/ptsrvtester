"""USRENUMPLAIN — AUTHENTICATE PLAIN user enumeration."""
from ._common import eng

__MODULELABEL__ = "AUTHENTICATE PLAIN user enumeration"
__MODULECODE__ = "USRENUMPLAIN"
__ORDER__ = 90


def run(ctx):
    e = eng(ctx)
    e.args.imap_usrenum_plain = True
    try:
        e.results.imap_usrenum_plain = e.test_imap_authenticate_plain_user_enumeration()
    except Exception as ex:
        e.results.imap_usrenum_plain_error = str(ex)
        ctx.out(f"USRENUMPLAIN failed: {ex}", "ERROR", indent=4)
        return
    e._stream_imap_usrenum_plain_result()
