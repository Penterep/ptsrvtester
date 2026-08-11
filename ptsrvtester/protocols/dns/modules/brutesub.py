"""BRUTESUB — Subdomain bruteforce."""
__MODULELABEL__ = "Subdomain bruteforce"
__MODULECODE__ = "BRUTESUB"
__ORDER__ = 60

from ._common import eng


def run(ctx):
    e = eng(ctx)
    e.results.Subdomains = e.brute_force_subdomains()
