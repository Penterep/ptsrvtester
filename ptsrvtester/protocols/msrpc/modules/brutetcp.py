"""BRUTETCP — Brute RPC over TCP."""
__MODULELABEL__ = "Brute RPC over TCP"
__MODULECODE__ = "BRUTETCP"
__ORDER__ = 70

from ._common import eng


def run(ctx):
    e = eng(ctx)
    e.results.TCP_Brute = e.tcp_brute()
