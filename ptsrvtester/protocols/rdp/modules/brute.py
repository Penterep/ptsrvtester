"""Explicit, bounded RDP credential-guessing adapter."""

__MODULELABEL__ = "RDP credential guessing"
__MODULECODE__ = "BRUTE"
__ORDER__ = 115


def run(ctx) -> None:
    ctx.rdp_engine.run_module(__MODULECODE__, ctx)
