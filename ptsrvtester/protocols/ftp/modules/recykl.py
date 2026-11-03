"""RECYKL — same probe as WEAK, vuln code PTV-SVC-AUTH-RECYKL."""
from ._authguess import run_auth_guess

__MODULELABEL__ = "Recycled credentials"
__MODULECODE__ = "RECYKL"
__ORDER__ = 62


def run(ctx):
    run_auth_guess(ctx, "RECYKL")
