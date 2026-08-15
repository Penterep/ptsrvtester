"""INVCMD — invalid / malformed IMAP commands."""
from ._common import eng

__MODULELABEL__ = "Invalid commands"
__MODULECODE__ = "INVCMD"
__ORDER__ = 70


def run(ctx):
    e = eng(ctx)
    try:
        e.results.inv_comm = e.test_invalid_commands_imap()
    except Exception as ex:
        e.results.inv_comm_error = str(ex)
        ctx.out(f"Invalid-command probe failed: {ex}", "ERROR", indent=4)
        return
    e._stream_inv_comm_result()
