"""TLSAUDIT — strict TLS handshake + certificate audit."""
from ._common import eng

__MODULELABEL__ = "TLS and Certificate Audit"
__MODULECODE__ = "TLSAUDIT"
__ORDER__ = 150


def run(ctx):
    e = eng(ctx)
    e.args.imap_tls_audit = True
    try:
        e.results.imap_tls_audit = e.test_imap_tls_audit()
    except Exception as ex:
        e.results.imap_tls_audit_error = str(ex)
        ctx.out(f"TLSAUDIT failed: {ex}", "ERROR", indent=4)
        return
    e._stream_imap_tls_audit_result()
