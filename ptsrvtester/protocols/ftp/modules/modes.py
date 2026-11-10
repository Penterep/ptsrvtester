"""MODES — Data modes."""
__MODULELABEL__ = "Data modes"
__MODULECODE__ = "MODES"
__ORDER__ = 90

from ..utils.helpers import check_if_brute
from ._common import eng, ensure_creds


def run(ctx):
    e = eng(ctx)
    e.args.modes = True

    def resolve_login():
        if not (getattr(ctx.args, "anonymous", False) or check_if_brute(ctx.args)):
            return None, None
        creds = ensure_creds(ctx)
        if creds is None:
            return None, e._missing_login_line()
        return creds, None

    try:
        e.results.modes = e.test_modes(resolve_login=resolve_login)
    except Exception as ex:
        e.results.modes_error = str(ex)
        ctx.out(f"MODES failed: {ex}", "ERROR", indent=4)
        return
    e._stream_modes_result()
