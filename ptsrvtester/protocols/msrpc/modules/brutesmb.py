"""BRUTESMB — Brute SMB credentials."""
__MODULELABEL__ = "Brute SMB credentials"
__MODULECODE__ = "BRUTESMB"
__ORDER__ = 60

from ._common import run_probe


def run(ctx):
    run_probe(ctx, __MODULECODE__, "SMB_Brute", "smb_brute")
