"""NTLM — AUTHENTICATE NTLM information disclosure."""
from ._common import eng

__MODULELABEL__ = "NTLM information"
__MODULECODE__ = "NTLM"
__ORDER__ = 40


def run(ctx):
    e = eng(ctx)
    try:
        e.results.ntlm = e.auth_ntlm()
    except Exception as ex:
        e.results.ntlm_error = str(ex)
        ctx.out(f"NTLM probe failed: {ex}", "ERROR", indent=4)
        return
    e._stream_ntlm_result()
