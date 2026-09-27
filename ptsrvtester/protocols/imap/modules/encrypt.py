"""ENCRYPT — cleartext / STARTTLS / implicit TLS probes."""
from ._common import eng

__MODULELABEL__ = "Encryption"
__MODULECODE__ = "ENCRYPT"
__ORDER__ = 30


def run(ctx):
    e = eng(ctx)
    try:
        e.results.encryption = e.test_encryption()
    except Exception as ex:
        e.results.encryption_error = str(ex)
    e._stream_encryption_result()
