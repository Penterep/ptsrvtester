"""PASVPORT — PASV port range."""
__MODULELABEL__ = "PASV port range"
__MODULECODE__ = "PASVPORT"
__ORDER__ = 100

from ._common import eng, ensure_creds


def run(ctx):
    e = eng(ctx)
    e.args.pasv_port_audit = True
    creds = ensure_creds(ctx)
    if creds is None:
        e.results.pasv_port_range_error = (
            "No credentials for passive port audit (use -A/--anonymous or -u/-p)"
        )
        e._stream_pasv_port_range_result()
        return
    try:
        n = max(4, int(getattr(ctx.args, "pasv_port_audit_samples", 8) or 8))
        mxsp = max(256, int(getattr(ctx.args, "pasv_port_audit_max_span", 8192) or 8192))
        e.results.pasv_port_range = e.test_pasv_port_range_audit(creds, n, mxsp)
    except Exception as ex:
        e.results.pasv_port_range_error = str(ex)
        ctx.out(f"PASVPORT failed: {ex}", "ERROR", indent=4)
        return
    e._stream_pasv_port_range_result()
