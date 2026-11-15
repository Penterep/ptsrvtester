"""PASVPORT — PASV port range."""
__MODULELABEL__ = "PASV port range"
__MODULECODE__ = "PASVPORT"
__ORDER__ = 100

from ..utils.helpers import Creds, check_if_brute
from ._common import eng, ensure_creds


def _sample_count(args) -> int:
    raw = getattr(args, "conn_limit_count", None)
    if raw is None:
        raw = getattr(args, "pasv_port_audit_samples", None)
    if raw is None:
        return 20
    return int(raw)


def run(ctx):
    e = eng(ctx)
    e.args.pasv_port_audit = True

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
        e.results.pasv_port_range = e.test_pasv_port_range_audit(
            _sample_count(ctx.args), resolve_login=resolve_login
        )
    except Exception as ex:
        e.results.pasv_port_range_error = str(ex)
        ctx.out(f"Passive port range test failed: {ex}", "ERROR", indent=4)
        return
    e._stream_pasv_port_range_result()
