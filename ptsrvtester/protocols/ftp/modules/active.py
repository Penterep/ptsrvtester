"""ACTIVE — Active mode (quick)."""
__MODULELABEL__ = "Active mode (quick)"
__MODULECODE__ = "ACTIVE"
__ORDER__ = 110

from ._common import eng, ensure_creds


def run(ctx):
    e = eng(ctx)
    e.args.active_audit = True
    creds = ensure_creds(ctx)
    try:
        e.results.active_audit = e.test_active_audit_quick(creds)
    except Exception as ex:
        e.results.active_audit_error = str(ex)
        ctx.out(f"ACTIVE failed: {ex}", "ERROR", indent=4)
        return
    e._stream_active_audit_result()
