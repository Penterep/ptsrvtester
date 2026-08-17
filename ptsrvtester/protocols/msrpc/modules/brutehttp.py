"""BRUTEHTTP — Brute RPC over HTTP."""
__MODULELABEL__ = "Brute RPC over HTTP"
__MODULECODE__ = "BRUTEHTTP"
__ORDER__ = 80

from ._common import run_probe


def run(ctx):
    run_probe(ctx, __MODULECODE__, "HTTP_Brute", "http_brute")
