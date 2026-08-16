"""MODES — Data modes."""
__MODULELABEL__ = "Data modes"
__MODULECODE__ = "MODES"
__ORDER__ = 90

from ._common import eng, ensure_creds


def run(ctx):
    e = eng(ctx)
    e.args.modes = True
    creds = ensure_creds(ctx)
    if creds is None:
        e.results.modes_error = "No credentials for mode test (use -A/--anonymous or -u/-p)"
        e._stream_modes_result()
        return
    try:
        e.results.modes = e.test_modes(creds)
    except Exception as ex:
        e.results.modes_error = str(ex)
        ctx.out(f"MODES failed: {ex}", "ERROR", indent=4)
        return
    e._stream_modes_result()
