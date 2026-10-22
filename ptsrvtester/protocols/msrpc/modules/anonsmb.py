"""ANONSMB — Anonymous SMB access."""
__MODULELABEL__ = "SMB null session"
__MODULECODE__ = "ANONSMB"
__ORDER__ = 40

from ._common import run_probe


def run(ctx):
    run_probe(ctx, __MODULECODE__, "Anonymous", "Anonymous_smb")
