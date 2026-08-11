"""Shared helpers for IMAP modules."""


def eng(ctx):
    """Bind the shared engine to this module's print lock / report."""
    return ctx.engine.bind_ctx(ctx)


def ensure_info(ctx, *, get_commands: bool = True):
    """Populate eng.results.info once (shared by BANNER/CAPA)."""
    e = eng(ctx)
    if e.results.info is not None or getattr(e.results, "info_error", None):
        return e
    try:
        e.imap = e.connect()
        e.results.info = e.info(get_commands=get_commands)
    except Exception as ex:
        msg = str(ex)
        e.results.info_error = msg
        ctx.report.set_connect_error(msg)
        ctx.out(msg, "ERROR", indent=4)
    return e
