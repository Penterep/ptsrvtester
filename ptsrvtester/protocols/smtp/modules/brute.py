"""BRUTE — server does not stop a guessing attack (PTV-SVC-AUTH-BRUTE)."""
from ._authguess import run_auth_guess

__MODULELABEL__ = "Blocking guessing attack"
__MODULECODE__ = "BRUTE"
__ORDER__ = 95


def run(ctx):
    run_auth_guess(ctx, "BRUTE")
