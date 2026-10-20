__MODULELABEL__ = "Anonymous SMB share enumeration"
__MODULECODE__ = "SHARES"
__ORDER__ = 41

from ._common import run_probe


def run(ctx):
    run_probe(ctx, __MODULECODE__, "AnonymousSharesAccess", "Anonymous_shares")
