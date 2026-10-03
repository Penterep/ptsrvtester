"""RDP OS detection adapter."""

__MODULELABEL__ = "OS detection"
__MODULECODE__ = "OSDETECT"
__ORDER__ = 65


def run(ctx) -> None:
    ctx.rdp_engine.run_module(__MODULECODE__, ctx)
