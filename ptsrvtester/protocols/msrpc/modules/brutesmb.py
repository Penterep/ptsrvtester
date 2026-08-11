"""BRUTESMB — Brute SMB credentials."""
__MODULELABEL__ = "Brute SMB credentials"
__MODULECODE__ = "BRUTESMB"
__ORDER__ = 60

from ._common import eng


def run(ctx):
    e = eng(ctx)
    e.results.SMB_Brute = e.smb_brute()
