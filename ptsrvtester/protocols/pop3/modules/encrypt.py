"""ENCRYPT — plaintext / STLS / implicit TLS probes."""
from ..utils.connection import test_encryption

__MODULELABEL__ = "Encryption"
__MODULECODE__ = "ENCRYPT"
__ORDER__ = 30


def run(ctx):
    try:
        enc = test_encryption(ctx.args, debug=ctx.debug)
    except Exception as e:
        ctx.report.update_properties(encryptionError=str(e))
        ctx.out(f"Encryption test failed: {e}", "VULN", indent=4)
        return

    ctx.report.update_properties(
        encryption={"plaintext": enc.plaintext_ok, "stls": enc.stls_ok, "tls": enc.tls_ok}
    )
    plaintext_only = enc.plaintext_ok and not enc.stls_ok and not enc.tls_ok
    any_ok = enc.plaintext_ok or enc.stls_ok or enc.tls_ok
    if plaintext_only:
        ctx.out("Plaintext only", "VULN", indent=4)
    elif any_ok:
        if enc.plaintext_ok:
            bullet = "WARNING" if (enc.stls_ok or enc.tls_ok) else "NOTVULN"
            ctx.out("Plaintext", bullet, indent=4)
        if enc.stls_ok:
            ctx.out("STLS", "NOTVULN", indent=4)
        if enc.tls_ok:
            ctx.out("TLS", "NOTVULN", indent=4)
    else:
        ctx.out(
            "No connection mode available (plaintext, STLS, TLS failed)",
            "VULN",
            indent=4,
        )
