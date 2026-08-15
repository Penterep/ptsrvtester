"""CHROOT — Chroot / isolation."""
__MODULELABEL__ = "Chroot / isolation"
__MODULECODE__ = "CHROOT"
__ORDER__ = 180

from ._common import eng, ensure_creds


def run(ctx):
    e = eng(ctx)
    e.args.chroot_audit = True
    creds = ensure_creds(ctx)
    if creds is None:
        e.results.chroot_audit_error = (
            "No credentials for chroot audit (use -A/--anonymous or -u/-p)"
        )
        e._stream_chroot_audit_result()
        return
    try:
        e.results.chroot_audit = e.test_chroot_audit(creds)
    except Exception as ex:
        e.results.chroot_audit_error = str(ex)
        ctx.out(f"CHROOT failed: {ex}", "ERROR", indent=4)
        return
    e._stream_chroot_audit_result()
