"""CredSSP support adapter."""

__MODULELABEL__ = "CredSSP test"
__MODULECODE__ = "CREDSSP"
__ORDER__ = 30


def run(ctx) -> None:
    ctx.rdp_engine.run_module(__MODULECODE__, ctx)
