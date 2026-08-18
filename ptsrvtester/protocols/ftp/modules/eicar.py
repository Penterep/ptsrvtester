"""EICAR — EICAR antivirus."""
__MODULELABEL__ = "EICAR antivirus"
__MODULECODE__ = "EICAR"
__ORDER__ = 190

from ._common import eng, ensure_creds


def run(ctx):
    e = eng(ctx)
    e.args.eicar_probe = True
    ensure_creds(ctx)
    try:
        e.results.eicar_audit = e.test_eicar_antivirus_probe()
    except Exception as ex:
        e.results.eicar_audit_error = str(ex)
        ctx.out(f"EICAR failed: {ex}", "ERROR", indent=4)
        return
    e._stream_eicar_audit_result()
