"""CMDAUDIT — Command surface."""
__MODULELABEL__ = "Command surface"
__MODULECODE__ = "CMDAUDIT"
__ORDER__ = 130

from ._common import eng, ensure_creds


def run(ctx):
    e = eng(ctx)
    e.args.cmd_audit = True
    creds = ensure_creds(ctx)
    try:
        e.results.cmd_audit = e.test_command_audit(creds)
    except Exception as ex:
        e.results.cmd_audit_error = str(ex)
        ctx.out(f"CMDAUDIT failed: {ex}", "ERROR", indent=4)
        return
    e._stream_cmd_audit_result()
