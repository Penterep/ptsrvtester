"""WEAK — valid login from the default wordlist (PTV-SVC-AUTH-WEAK)."""
from ._authguess import run_auth_guess

__MODULELABEL__ = "Weak credentials"
__MODULECODE__ = "WEAK"
__ORDER__ = 96


def run(ctx):
    run_auth_guess(ctx, "WEAK")
