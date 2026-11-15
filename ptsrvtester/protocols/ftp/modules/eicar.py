"""EICAR — EICAR antivirus."""
__MODULELABEL__ = "EICAR antivirus"
__MODULECODE__ = "EICAR"
__ORDER__ = 190

from ..utils.helpers import Creds, brute_passwords, check_if_brute, one_cli_user
from ._common import eng, ensure_creds


def _direct_account(ctx) -> Creds | None:
    """One -u and one -p. The EICAR session itself performs the login."""
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
    e.args.eicar_probe = True
    want_anon = bool(getattr(ctx.args, "anonymous", False))
    want_user = check_if_brute(ctx.args)
    direct = _direct_account(ctx) if want_user and not e.results.creds else None
    if direct is not None:
        e._eicar_direct = (direct,)
    elif not (want_anon and not want_user and e.results.anonymous is None):
        ensure_creds(ctx)
    try:
        e.results.eicar_audit = e.test_eicar_antivirus_probe()
    except Exception as ex:
        e.results.eicar_audit_error = str(ex)
        ctx.out(f"EICAR failed: {ex}", "ERROR", indent=4)
        return
    e._stream_eicar_audit_result()
