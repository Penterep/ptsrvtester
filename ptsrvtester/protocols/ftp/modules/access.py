"""ACCESS — Access check."""
__MODULELABEL__ = "Access check"
__MODULECODE__ = "ACCESS"
__ORDER__ = 50

from ..utils.helpers import Creds, brute_passwords, check_if_brute, one_cli_user
from ._common import eng, ensure_creds


def _direct_account(ctx) -> Creds | None:
    """One -u and one -p. The access session itself performs the login."""
    if getattr(ctx.args, "users", None) or getattr(ctx.args, "passwords", None):
        return None
    user = one_cli_user(getattr(ctx.args, "user", None))
    if not user:
        return None
    passwords = brute_passwords(getattr(ctx.args, "password", None), None)
    if len(passwords) != 1:
        return None
    return Creds(user, passwords[0])


def run(ctx):
    e = eng(ctx)
    e.args.access = True
    want_anon = bool(getattr(ctx.args, "anonymous", False))
    want_user = check_if_brute(ctx.args)
    direct = _direct_account(ctx) if want_user and not e.results.creds else None
    if direct is not None:
        e._access_direct = (direct,)
    elif not (want_anon and not want_user and e.results.anonymous is None):
        ensure_creds(ctx)
    if not (want_anon or e.results.anonymous or e.results.creds or getattr(e, "_access_direct", None)):
        ctx.out(
            e._missing_login_line(),
            "WARNING",
            indent=4,
        )
        return
    try:
        e.results.access = e.access_check()
    except Exception as ex:
        e.results.access_error = str(ex)
        ctx.out(f"ACCESS failed: {ex}", "ERROR", indent=4)
        return
    if getattr(e.args, "bounce", None):
        try:
            e.results.bounce = e.bounce()
        except Exception as ex:
            ctx.out(f"Bounce failed: {ex}", "ERROR", indent=4)
    e._stream_access_check_terminal()
    if getattr(e.args, "access_list", False):
        e._stream_directory_listing_result()
    if getattr(e.results, "bounce", None) is not None:
        e._stream_bounce_result()
