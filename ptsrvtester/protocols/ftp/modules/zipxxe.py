"""ZIPXXE — XML and zip-bomb upload probes."""
__MODULELABEL__ = "ZIPXXE"
__MODULECODE__ = "ZIPXXE"
__ORDER__ = 170

from ._common import eng, ensure_creds


def run(ctx):
    e = eng(ctx)
    e.args.ftp_dos_probes = True
    if ensure_creds(ctx) is None:
        e.results.dos_audit_error = (
            e._missing_login_line()
        )
    try:
        e.results.dos_audit = e.test_ftp_processing_resilience_probes()
    except Exception as ex:
        e.results.dos_audit_error = str(ex)
        ctx.out(f"ZIPXXE failed: {ex}", "ERROR", indent=4)
        return
    e._stream_dos_audit_result()
