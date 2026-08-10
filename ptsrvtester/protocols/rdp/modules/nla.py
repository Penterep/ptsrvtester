"""Network Level Authentication requirement adapter."""

__MODULELABEL__ = "Network Level Authentication (NLA) test"
__MODULECODE__ = "NLA"
__ORDER__ = 10


def run(ctx) -> None:
    ctx.rdp_engine.run_module(__MODULECODE__, ctx)
