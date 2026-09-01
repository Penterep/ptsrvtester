"""ACTIVEFULL — Active mode (full)."""
__MODULELABEL__ = "Active mode (full)"
__MODULECODE__ = "ACTIVEFULL"
__ORDER__ = 120

from ._common import eng, ensure_creds


def run(ctx):
    e = eng(ctx)
    e.args.active_audit_full = True
    creds = ensure_creds(ctx)
    try:
        low_s = getattr(ctx.args, "active_audit_low_ports", None) or "80,443,21"
        e.results.active_audit = e.test_active_audit_full(creds, low_s)
    except Exception as ex:
        e.results.active_audit_error = str(ex)
        ctx.out(f"ACTIVEFULL failed: {ex}", "ERROR", indent=4)
        return
    e._stream_active_audit_result()
