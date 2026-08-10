"""RDP security protocol and encryption enumeration adapter."""

__MODULELABEL__ = "RDP security and encryption enumeration"
__MODULECODE__ = "RDPENC"
__ORDER__ = 40


def run(ctx) -> None:
    ctx.rdp_engine.run_module(__MODULECODE__, ctx)
