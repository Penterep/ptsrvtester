"""Explicit RDP account-enumeration adapter."""

__MODULELABEL__ = "RDP user enumeration"
__MODULECODE__ = "USERENUM"
__ORDER__ = 110


def run(ctx) -> None:
    ctx.rdp_engine.run_module(__MODULECODE__, ctx)
