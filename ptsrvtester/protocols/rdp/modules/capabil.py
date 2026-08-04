"""RDP capability negotiation adapter."""

__MODULELABEL__ = "RDP capabilities"
__MODULECODE__ = "CAPABIL"
__ORDER__ = 50


def run(ctx) -> None:
    ctx.rdp_engine.run_module(__MODULECODE__, ctx)
