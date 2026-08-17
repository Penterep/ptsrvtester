"""ENUMEPM — Enumerate EPM endpoints."""
__MODULELABEL__ = "Enumerate EPM endpoints"
__MODULECODE__ = "ENUMEPM"
__ORDER__ = 10

from ._common import run_probe


def run(ctx):
    run_probe(ctx, __MODULECODE__, "EpmapEndpoints", "enumerate_epm")
