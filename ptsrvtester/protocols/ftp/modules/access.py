"""ACCESS — Access check."""
__MODULELABEL__ = "Access check"
__MODULECODE__ = "ACCESS"
__ORDER__ = 50

from ._common import eng, ensure_creds


def run(ctx):
    e = eng(ctx)
    e.args.access = True
    creds = ensure_creds(ctx)
    if creds is None and not e.results.anonymous and not e.results.creds:
        ctx.out(
            "ACCESS needs -A/--anonymous (working anon) or credentials (-u/-p), or -ts ANON first",
            "ERROR",
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
