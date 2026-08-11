"""BRUTEHTTP — Brute RPC over HTTP."""
__MODULELABEL__ = "Brute RPC over HTTP"
__MODULECODE__ = "BRUTEHTTP"
__ORDER__ = 80

from ._common import eng


def run(ctx):
    e = eng(ctx)
    e.results.HTTP_Brute = e.http_brute()
