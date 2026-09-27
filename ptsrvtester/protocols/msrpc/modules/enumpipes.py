"""ENUMPIPES — Enumerate named pipes."""
__MODULELABEL__ = "Enumerate named pipes"
__MODULECODE__ = "ENUMPIPES"
__ORDER__ = 30

from ._common import run_probe


def run(ctx):
    run_probe(ctx, __MODULECODE__, "Pipes", "enumerate_pipes")
