"""XXESSRF — SSRF through XXE via authenticated APPEND."""
from ._common import eng

__MODULELABEL__ = "SSRF through XXE"
__MODULECODE__ = "XXESSRF"
__ORDER__ = 115
__RUN_IN_ALL__ = False


def run(ctx):
    e = eng(ctx)
    try:
        e.results.xxessrf = e.test_imap_xxessrf()
    except Exception as ex:
        e.results.xxessrf_error = str(ex)
    e._stream_imap_xxessrf_result()
