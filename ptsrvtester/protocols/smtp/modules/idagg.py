"""IDAGG — aggressive fingerprinting (VRFY, unknown commands)."""
from ._common import eng
from .identify import test_server_identify, _stream_identify_result


__MODULELABEL__ = "Service Fingerprinting"
__MODULECODE__ = "IDAGG"
__ORDER__ = 13


def run(ctx):
    e = eng(ctx)
    e.args.identify = True
    e.args.id_aggressive = True
    try:
        e.results.identify = test_server_identify(e)
    except Exception as ex:
        e.results.identify_error = str(ex)
        ctx.out(f"Identify probe failed: {ex}", "ERROR", indent=4)
        return
    _stream_identify_result(e)
