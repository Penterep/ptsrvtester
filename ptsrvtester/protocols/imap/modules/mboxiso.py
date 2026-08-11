"""MBOXISO — mailbox isolation / ACL."""
from ._common import eng

__MODULELABEL__ = "Mailbox isolation"
__MODULECODE__ = "MBOXISO"
__ORDER__ = 140


def run(ctx):
    e = eng(ctx)
    e.args.imap_mailbox_iso = True
    try:
        e.results.imap_mailbox_iso = e.test_imap_mailbox_iso()
    except Exception as ex:
        e.results.imap_mailbox_iso_error = str(ex)
        ctx.out(f"MBOXISO failed: {ex}", "ERROR", indent=4)
        return
    e._stream_imap_mailbox_iso_result()
