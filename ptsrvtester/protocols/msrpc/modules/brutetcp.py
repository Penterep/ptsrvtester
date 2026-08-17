"""BRUTETCP — Brute RPC over TCP."""
__MODULELABEL__ = "Brute RPC over TCP"
__MODULECODE__ = "BRUTETCP"
__ORDER__ = 70

from ._common import run_probe


def run(ctx):
    run_probe(ctx, __MODULECODE__, "TCP_Brute", "tcp_brute")
