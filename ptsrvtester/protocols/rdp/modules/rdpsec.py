"""Legacy Standard RDP Security negotiation adapter."""

__MODULELABEL__ = "RDP Security test"
__MODULECODE__ = "RDPSEC"
__ORDER__ = 20


def run(ctx) -> None:
    ctx.rdp_engine.run_module(__MODULECODE__, ctx)
