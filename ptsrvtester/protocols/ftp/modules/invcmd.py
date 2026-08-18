"""INVCMD — Invalid commands."""
__MODULELABEL__ = "Invalid commands"
__MODULECODE__ = "INVCMD"
__ORDER__ = 150

from ._common import eng, ensure_creds


def run(ctx):
    e = eng(ctx)
    e.args.invalid_cmd_audit = True
    creds = ensure_creds(ctx)
    try:
        e.results.invalid_cmd_audit = e.test_invalid_command_audit(creds)
    except Exception as ex:
        e.results.invalid_cmd_audit_error = str(ex)
        ctx.out(f"INVCMD failed: {ex}", "ERROR", indent=4)
        return
    e._stream_invalid_cmd_audit_result()
