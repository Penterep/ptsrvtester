"""REVERSE — Reverse DNS lookup."""
__MODULELABEL__ = "Reverse DNS lookup"
__MODULECODE__ = "REVERSE"
__ORDER__ = 20

from ._common import eng


def run(ctx):
    e = eng(ctx)
    e.results.ReverseDomain = e.reverseDNS()
