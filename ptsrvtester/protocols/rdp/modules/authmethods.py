"""Password authentication through explicitly selected RDP mechanisms."""

__MODULELABEL__ = "RDP authentication methods"
__MODULECODE__ = "AUTHMETHODS"
__ORDER__ = 100


def run(ctx) -> None:
    ctx.rdp_engine.run_module(__MODULECODE__, ctx)
