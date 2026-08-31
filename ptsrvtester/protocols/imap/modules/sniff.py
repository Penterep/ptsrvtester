"""SNIFF — cleartext LOGIN + SELECT INBOX (mailbox traffic without TLS)."""
from ._common import eng

__MODULELABEL__ = "Cleartext sniffable"
__MODULECODE__ = "SNIFF"
__ORDER__ = 60


def run(ctx):
    e = eng(ctx)
    try:
        e.results.sniffable = e.test_sniffable_plain_imap()
    except Exception as ex:
        e.results.sniffable_error = str(ex)
        ctx.out(f"Sniffable probe failed: {ex}", "ERROR", indent=4)
        return
    e._stream_sniffable_result()
