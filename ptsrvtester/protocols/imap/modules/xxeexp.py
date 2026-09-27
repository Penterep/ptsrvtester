"""XXEEXP — XML Entity Expansion (Billion of Lolz) via authenticated APPEND."""
from ._common import eng

__MODULELABEL__ = "XML Entity Expansion"
__MODULECODE__ = "XXEEXP"
__ORDER__ = 116
__RUN_IN_ALL__ = False


def run(ctx):
    e = eng(ctx)
    try:
        e.results.xxeexp = e.test_imap_xxeexp()
    except Exception as ex:
        e.results.xxeexp_error = str(ex)
    e._stream_imap_xxeexp_result()
