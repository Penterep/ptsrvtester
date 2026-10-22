__MODULELABEL__ = "RPC/TCP guessing protection"
__MODULECODE__ = "NTLMGUESS"
__ORDER__ = 75

from ._common import run_probe


def run(ctx):
    run_probe(ctx, __MODULECODE__, "NtlmGuess", "ntlm_guess_protection")
