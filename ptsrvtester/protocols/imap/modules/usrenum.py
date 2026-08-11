"""USRENUM — LOGIN user enumeration."""
from ._common import eng

__MODULELABEL__ = "LOGIN user enumeration"
__MODULECODE__ = "USRENUM"
__ORDER__ = 80


def run(ctx):
    e = eng(ctx)
    # Engine methods still read legacy bool dests in some paths — set for this run.
    e.args.imap_usrenum = True
    try:
        e.results.imap_usrenum = e.test_imap_login_user_enumeration()
    except Exception as ex:
        e.results.imap_usrenum_error = str(ex)
        ctx.out(f"USRENUM failed: {ex}", "ERROR", indent=4)
        return
    e._stream_imap_usrenum_login_result()
