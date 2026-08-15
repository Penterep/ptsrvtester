"""ANONSMB — Anonymous SMB access."""
__MODULELABEL__ = "Anonymous SMB access"
__MODULECODE__ = "ANONSMB"
__ORDER__ = 40

from ._common import eng


def run(ctx):
    e = eng(ctx)
    e.results.Anonymous = e.Anonymous_smb()
