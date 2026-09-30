"""AUTHLIST — AUTH= mechanisms on cleartext, STARTTLS and implicit TLS."""
from ._common import eng

__MODULELABEL__ = "AUTH mechanisms"
__MODULECODE__ = "AUTHLIST"
__ORDER__ = 35


def run(ctx):
    e = eng(ctx)
    try:
        e.results.imap_authlist = e.test_imap_authlist()
    except Exception as ex:
        e.results.imap_authlist_error = str(ex)
        ctx.out(f"AUTHLIST failed: {ex}", "ERROR", indent=4)
        return
    e._stream_imap_authlist_result()
