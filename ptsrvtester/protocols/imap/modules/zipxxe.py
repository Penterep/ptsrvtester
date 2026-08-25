"""ZIPXXE — Zip bomb, Billion Laughs, XXE via authenticated APPEND."""
from ._common import eng

__MODULELABEL__ = "ZIPXXE – Zip Bomb, Billion Laughs, XXE"
__MODULECODE__ = "ZIPXXE"
__ORDER__ = 115


def run(ctx):
    e = eng(ctx)
    try:
        e.results.zipxxe = e.test_imap_zipxxe()
    except Exception as ex:
        e.results.zipxxe_error = str(ex)
    e._stream_imap_zipxxe_result()
