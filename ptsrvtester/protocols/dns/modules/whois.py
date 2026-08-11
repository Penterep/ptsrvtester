"""WHOIS — WHOIS lookup."""
__MODULELABEL__ = "WHOIS lookup"
__MODULECODE__ = "WHOIS"
__ORDER__ = 50

from ._common import eng


def run(ctx):
    e = eng(ctx)
    e.results.Whois = e.lookup_whois()
