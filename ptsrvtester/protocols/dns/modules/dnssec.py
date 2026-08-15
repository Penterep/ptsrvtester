"""DNSSEC — DNSSEC check."""
__MODULELABEL__ = "DNSSEC check"
__MODULECODE__ = "DNSSEC"
__ORDER__ = 70

from ._common import eng


def run(ctx):
    e = eng(ctx)
    e.results.DNSSEC = e.check_dns()
