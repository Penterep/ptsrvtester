"""BRUTEPIPE — Brute named pipe creds."""
__MODULELABEL__ = "Brute named pipe creds"
__MODULECODE__ = "BRUTEPIPE"
__ORDER__ = 50

from ._common import run_probe


def run(ctx):
    run_probe(ctx, __MODULECODE__, "PipesCreds", "pipe_dictionary_attack")
