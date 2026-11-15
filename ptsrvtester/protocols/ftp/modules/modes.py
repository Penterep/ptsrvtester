"""MODES — Transfer modes."""
__MODULELABEL__ = "Transfer modes"
__MODULECODE__ = "MODES"
__ORDER__ = 90

from ..utils.helpers import Creds, check_if_brute
from ._common import eng, ensure_creds


def run(ctx):
    e = eng(ctx)
    e.args.modes = True

    def resolve_login():
        want_anon = bool(getattr(ctx.args, "anonymous", False))
        want_user = check_if_brute(ctx.args)
        if not want_anon and not want_user:
            return None, None
        # -A alone is tried in the After login section. A login here would be a second one.
        if want_anon and not want_user and e.results.anonymous is None:
            return Creds("anonymous", "anonymous@"), None
        creds = ensure_creds(ctx)
        if creds is None:
            return None, e._missing_login_line()
        if creds.user.lower() == "anonymous" and creds.passw == "":
            return Creds("anonymous", "anonymous@"), None
        return creds, None

    try:
        e.results.modes = e.test_modes(resolve_login=resolve_login)
    except Exception as ex:
        e.results.modes_error = str(ex)
        ctx.out(f"MODES failed: {ex}", "ERROR", indent=4)
        return
    e._stream_modes_result()
