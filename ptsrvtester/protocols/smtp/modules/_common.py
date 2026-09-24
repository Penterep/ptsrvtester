"""Shared helpers for SMTP modules."""
from __future__ import annotations


def eng(ctx):
    """Bind the shared engine to this module's print lock / report."""
    return ctx.engine.bind_ctx(ctx)


def ensure_info(ctx, *, get_commands: bool = True):
    """Populate ``results.info`` and ``engine.smtp`` once (BANNER / EHLO / ROLE / NTLM)."""
    e = eng(ctx)
    if getattr(e.results, "info_error", None):
        return e
    if e.results.info is not None:
        return e
    try:
        smtp, info = e.initial_info(get_commands=get_commands)
        e.smtp = smtp
        e.results.info = info
        e.results.resolved_domain = e._get_domain_from_banner_or_ptr(info)
    except Exception as ex:
        msg = str(ex)
        e.results.info_error = msg
        report = getattr(ctx, "report", None) or e.report
        if report is not None:
            report.set_connect_error(msg)
        ctx.out(msg, "ERROR", indent=4)
        e._info_error_emitted = True
    return e
