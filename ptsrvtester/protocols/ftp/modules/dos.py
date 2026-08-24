"""DOS — Processing DoS probes."""
__MODULELABEL__ = "Processing DoS probes"
__MODULECODE__ = "DOS"
__ORDER__ = 170

from ._common import eng, ensure_creds


def run(ctx):
    e = eng(ctx)
    e.args.ftp_dos_probes = True
    if ensure_creds(ctx) is None:
        e.results.dos_audit_error = (
            "No credentials for processing probes (-A/--anonymous or -u/-p required)"
        )
        # still call engine which returns structured empty result when no creds
    try:
        e.results.dos_audit = e.test_ftp_processing_resilience_probes()
    except Exception as ex:
        e.results.dos_audit_error = str(ex)
        ctx.out(f"DOS failed: {ex}", "ERROR", indent=4)
        return
    e._stream_dos_audit_result()
