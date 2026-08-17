"""ENUMMGMT — Enumerate MGMT UUIDs."""
__MODULELABEL__ = "Enumerate MGMT UUIDs"
__MODULECODE__ = "ENUMMGMT"
__ORDER__ = 20

from ._common import run_probe


def run(ctx):
    run_probe(ctx, __MODULECODE__, "MgmtEndpoints", "enumerate_mgmt")
