"""Explicit password-guessing protection adapter."""

__MODULELABEL__ = "RDP password-guessing protections"
__MODULECODE__ = "BRUTEPROT"
__ORDER__ = 120


def run(ctx) -> None:
    ctx.rdp_engine.run_module(__MODULECODE__, ctx)
