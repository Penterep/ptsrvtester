"""RDP protocol version adapter."""

__MODULELABEL__ = "RDP protocol version"
__MODULECODE__ = "VERSION"
__ORDER__ = 60


def run(ctx) -> None:
    ctx.rdp_engine.run_module(__MODULECODE__, ctx)
