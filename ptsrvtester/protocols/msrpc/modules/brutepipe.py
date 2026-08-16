"""BRUTEPIPE — Brute named pipe creds."""
__MODULELABEL__ = "Brute named pipe creds"
__MODULECODE__ = "BRUTEPIPE"
__ORDER__ = 50

from ._common import eng


def run(ctx):
    e = eng(ctx)
    e.results.PipesCreds = e.pipe_dictionary_attack()
