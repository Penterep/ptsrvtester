"""ENUMEPM — Enumerate EPM endpoints."""
__MODULELABEL__ = "Enumerate EPM endpoints"
__MODULECODE__ = "ENUMEPM"
__ORDER__ = 10

from ._common import eng


def run(ctx):
    e = eng(ctx)
    e.results.EpmapEndpoints = e.enumerate_epm()
