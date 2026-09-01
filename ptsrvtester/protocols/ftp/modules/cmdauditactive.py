"""CMDAUDITACTIVE — Command surface (active)."""
__MODULELABEL__ = "Command surface (active)"
__MODULECODE__ = "CMDAUDITACTIVE"
__ORDER__ = 140

from ._common import eng, ensure_creds


def run(ctx):
    e = eng(ctx)
    e.args.cmd_audit_active = True
    creds = ensure_creds(ctx)
    if creds is None:
        e.results.cmd_audit_active_error = (
            "Active command probes require credentials (-A/--anonymous or -u/-p)"
        )
        e._stream_cmd_audit_active_result()
        return
    # Passive cmd audit is a prerequisite when not already run.
    if e.results.cmd_audit is None and not e.results.cmd_audit_error:
        try:
            e.results.cmd_audit = e.test_command_audit(creds)
        except Exception as ex:
            e.results.cmd_audit_error = str(ex)
    if e.results.cmd_audit_error:
        e.results.cmd_audit_active_error = (
            f"Skipped: passive cmd audit failed: {e.results.cmd_audit_error}"
        )
        e._stream_cmd_audit_active_result()
        return
    try:
        e.results.cmd_audit_active = e.test_command_audit_active(creds, e.results.cmd_audit)
    except Exception as ex:
        e.results.cmd_audit_active_error = str(ex)
        ctx.out(f"CMDAUDITACTIVE failed: {ex}", "ERROR", indent=4)
        return
    e._stream_cmd_audit_active_result()
