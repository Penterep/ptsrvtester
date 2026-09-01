"""CONNLIM — Connection limits."""
__MODULELABEL__ = "Connection limits"
__MODULECODE__ = "CONNLIM"
__ORDER__ = 160

from ._common import eng, ensure_creds


def run(ctx):
    e = eng(ctx)
    e.args.conn_limits_audit = True
    creds_post = ensure_creds(ctx)
    try:
        e.results.conn_limits = e.test_connection_limits_audit(creds_post)
    except Exception as ex:
        e.results.conn_limits_error = str(ex)
        ctx.out(f"CONNLIM failed: {ex}", "ERROR", indent=4)
        return
    e._stream_conn_limits_result()
