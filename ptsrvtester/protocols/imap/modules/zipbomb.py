"""ZIPBOMB — Zip bomb (DoS) via authenticated APPEND."""
from ._common import eng

__MODULELABEL__ = "Zip bomb"
__MODULECODE__ = "ZIPBOMB"
__ORDER__ = 117
__RUN_IN_ALL__ = False


def run(ctx):
    e = eng(ctx)
    try:
        e.results.zipbomb = e.test_imap_zipbomb()
    except Exception as ex:
        e.results.zipbomb_error = str(ex)
    e._stream_imap_zipbomb_result()
