"""ENUMPIPES — Enumerate named pipes."""
__MODULELABEL__ = "Enumerate named pipes"
__MODULECODE__ = "ENUMPIPES"
__ORDER__ = 30

from ._common import eng


def run(ctx):
    e = eng(ctx)
    e.results.Pipes = e.enumerate_pipes()
