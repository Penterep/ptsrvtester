"""CONNLIM — connection limits / rate / idle probes."""
from ._common import eng

__MODULELABEL__ = "Connection limits"
__MODULECODE__ = "CONNLIM"
__ORDER__ = 120


def run(ctx):
    e = eng(ctx)
    e.args.conn_limits_probe = True
    try:
        e.results.conn_limits = e.test_connection_limits_imap()
    except Exception as ex:
        e.results.conn_limits_error = str(ex)
        ctx.out(f"CONNLIM failed: {ex}", "ERROR", indent=4)
        return
    e._stream_conn_limits_result()
