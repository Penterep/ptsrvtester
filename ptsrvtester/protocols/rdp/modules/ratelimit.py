"""Explicit RDP connection-limiting adapter."""

__MODULELABEL__ = "RDP connection rate limiting"
__MODULECODE__ = "RATELIMIT"
__ORDER__ = 130


def run(ctx) -> None:
    ctx.rdp_engine.run_module(__MODULECODE__, ctx)
