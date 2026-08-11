"""ENUMMGMT — Enumerate MGMT UUIDs."""
__MODULELABEL__ = "Enumerate MGMT UUIDs"
__MODULECODE__ = "ENUMMGMT"
__ORDER__ = 20

from ._common import eng


def run(ctx):
    e = eng(ctx)
    e.results.MgmtEndpoints = e.enumerate_mgmt()
