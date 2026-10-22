__MODULELABEL__ = "RPC Proxy guessing protection"
__MODULECODE__ = "CHGUESS"
__ORDER__ = 85

from ._common import run_probe


def run(ctx):
    run_probe(ctx, __MODULECODE__, "ChannelGuess", "channel_guess_protection")
