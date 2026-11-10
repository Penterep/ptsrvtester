"""PASVPORT — PASV port range."""
__MODULELABEL__ = "PASV port range"
__MODULECODE__ = "PASVPORT"
__ORDER__ = 100

from ..utils.helpers import check_if_brute
from ._common import eng, ensure_creds


def run(ctx):
    e = eng(ctx)
    e.args.pasv_port_audit = True

    def resolve_login():
        if not (getattr(ctx.args, "anonymous", False) or check_if_brute(ctx.args)):
            return None, None
        creds = ensure_creds(ctx)
        if creds is None:
            return None, e._missing_login_line()
        return creds, None

    try:
        n = max(4, int(getattr(ctx.args, "pasv_port_audit_samples", 8) or 8))
        mxsp = max(256, int(getattr(ctx.args, "pasv_port_audit_max_span", 8192) or 8192))
        e.results.pasv_port_range = e.test_pasv_port_range_audit(n, mxsp, resolve_login=resolve_login)
    except Exception as ex:
        e.results.pasv_port_range_error = str(ex)
        ctx.out(f"Passive port range test failed: {ex}", "ERROR", indent=4)
        return
    e._stream_pasv_port_range_result()
