"""RDP TLS configuration adapter."""

__MODULELABEL__ = "TLS / SSL configuration test"
__MODULECODE__ = "SSL"
__ORDER__ = 70


def run(ctx) -> None:
    ctx.rdp_engine.run_module(__MODULECODE__, ctx)
