"""AV / SSRF message payloads generated in code (IMAP-style; no on-disk payload tree)."""
from __future__ import annotations

import zipfile
from base64 import b64encode
from io import BytesIO

from .decompression_payloads import build_full_zip_bomb

# Same EICAR line as IMAP (https://www.eicar.org/).
EICAR_LINE = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_BYTES = (EICAR_LINE + "\n").encode("ascii")
EICAR_BYTES_NO_NL = EICAR_LINE.encode("ascii")

_XXE_SIMPLE_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<document>
  <title>Test</title>
  <content>&xxe;</content>
</document>
"""

_MALFORMED_EML = """\
From: {FROM}
To: {TO}
Subject: {SUBJECT}
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BND1"

--BND1
Content-Type: text/plain

Malformed MIME - nested part uses wrong boundary to confuse parser.
--BND1
Content-Type: multipart/alternative; boundary="BND2"

--BND_WRONG
Content-Type: application/octet-stream; name="eicar.com"
Content-Transfer-Encoding: base64

WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=
--BND1--
"""

SSRF_VARIANTS: dict[str, dict] = {
    "plain": {
        "subject": "SSRF test - plain URL (PTL-SVC-SMTP-SSRF)",
        "body": "Test SSRF – prosím zkontrolujte odkaz: {{CANARY_URL}}",
        "bodyHtml": None,
    },
    "html_link": {
        "subject": "SSRF test - HTML link (PTL-SVC-SMTP-SSRF)",
        "body": "Odkaz v těle.",
        "bodyHtml": '<html><body><p>Klikněte zde:</p><a href="{{CANARY_URL}}">{{CANARY_URL}}</a></body></html>',
    },
    "html_img": {
        "subject": "SSRF test - HTML image (PTL-SVC-SMTP-SSRF)",
        "body": "Obrázek v těle.",
        "bodyHtml": '<html><body><img src="{{CANARY_URL}}" alt="tracking" /></body></html>',
    },
    "html_iframe": {
        "subject": "SSRF test - HTML iframe (PTL-SVC-SMTP-SSRF)",
        "body": "Iframe v těle.",
        "bodyHtml": '<html><body><iframe src="{{CANARY_URL}}" width="1" height="1"></iframe></body></html>',
    },
    "multipart": {
        "subject": "SSRF test - multipart (PTL-SVC-SMTP-SSRF)",
        "body": "Test SSRF – odkaz v plain části: {{CANARY_URL}}",
        "bodyHtml": '<html><body><p>Odkaz v HTML:</p><a href="{{CANARY_URL}}">link</a></body></html>',
    },
    "ssrf_malformed": {"subject": "SSRF test - Malformed MIME"},
    "ssrf_nested": {"subject": "SSRF test - Deeply Nested"},
}


def _zip_bytes(inner_name: str, payload: bytes) -> bytes:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(inner_name, payload)
    return buf.getvalue()


def _nested_eicar_zip() -> bytes:
    """ZIP with 5 nesting levels; innermost file is EICAR (eicar.com)."""
    data = EICAR_BYTES_NO_NL
    name = "eicar.com"
    for wrap in ("level5.zip", "level4.zip", "level3.zip", "level2.zip"):
        data = _zip_bytes(name, data)
        name = wrap
    return _zip_bytes(name, data)


def antivirus_catalog() -> dict[str, list[tuple[str, dict, dict[str, bytes]]]]:
    """category → [(source name, message def, attachment bytes by filename)]."""
    eicar_zip = _zip_bytes("eicar.com", EICAR_BYTES)
    eicar_double = _zip_bytes("eicar.zip", eicar_zip)
    eicar_b64 = b64encode(EICAR_BYTES_NO_NL).decode("ascii")
    bat = f"rem EICAR test\n{EICAR_LINE}\n".encode("ascii")
    return {
        "eicar": [
            (
                "msg_001.json",
                {
                    "subject": "EICAR antivirus test - eicar.com attachment (PTL-SVC-SMTP-ANTIVIRUS)",
                    "body": "EICAR standard test file as attachment (eicar.org variant 1). Harmless but should be detected by antivirus.",
                    "attachments": ["eicar.com"],
                },
                {"eicar.com": EICAR_BYTES},
            ),
            (
                "msg_002.json",
                {
                    "subject": "EICAR antivirus test - alternate filename (PTL-SVC-SMTP-ANTIVIRUS)",
                    "body": "EICAR standard test file with .txt extension (eicar.org variant 2). Harmless but should be detected by antivirus.",
                    "attachments": ["eicar.com.txt"],
                },
                {"eicar.com.txt": EICAR_BYTES},
            ),
            (
                "msg_003.json",
                {
                    "subject": "EICAR antivirus test - single ZIP (PTL-SVC-SMTP-ANTIVIRUS)",
                    "body": "EICAR test file inside a single ZIP archive (eicar.org variant 3). Scanner should unpack and detect eicar.com.",
                    "attachments": ["eicar.zip"],
                },
                {"eicar.zip": eicar_zip},
            ),
            (
                "msg_004.json",
                {
                    "subject": "EICAR antivirus test - double ZIP (PTL-SVC-SMTP-ANTIVIRUS)",
                    "body": "EICAR test file inside a ZIP within a ZIP (eicar.org variant 4). Scanner should recurse at least two archive levels.",
                    "attachments": ["eicar_double.zip"],
                },
                {"eicar_double.zip": eicar_double},
            ),
            (
                "msg_005.json",
                {
                    "subject": "EICAR antivirus test - plain body (PTL-SVC-SMTP-ANTIVIRUS)",
                    "bodyPlainEicar": True,
                    "body": "EICAR standard string at the beginning of the plain message body (Kaspersky SMTP traffic protection guidance).",
                },
                {},
            ),
        ],
        "double_ext": [
            (
                "msg_001.json",
                {
                    "subject": "Invoice document - double extension test",
                    "body": "Please find the invoice attached.",
                    "attachments": ["invoice.pdf.exe"],
                },
                {"invoice.pdf.exe": EICAR_BYTES},
            ),
            (
                "msg_002.json",
                {
                    "subject": "Image scan - double extension test",
                    "body": "Please review the scan.",
                    "attachments": ["scan.jpg.js"],
                },
                {"scan.jpg.js": EICAR_BYTES},
            ),
            (
                "msg_003.json",
                {
                    "subject": "Document - double extension test",
                    "body": "Please open the document.",
                    "attachments": ["document.docx.lnk"],
                },
                {"document.docx.lnk": EICAR_BYTES},
            ),
        ],
        "executable": [
            (
                "msg_001.json",
                {
                    "subject": "Executable attachment test - PTL-SVC-SMTP-ANTIVIRUS",
                    "body": "Test message with executable attachment.",
                    "attachments": ["test.exe"],
                },
                {"test.exe": EICAR_BYTES},
            ),
            (
                "msg_002.json",
                {
                    "subject": "Executable attachment test - PTL-SVC-SMTP-ANTIVIRUS",
                    "body": "Test message with executable attachment.",
                    "attachments": ["test.bat"],
                },
                {"test.bat": bat},
            ),
        ],
        "nested_archive": [
            (
                "msg_001.json",
                {
                    "subject": "Nested archive test - PTL-SVC-SMTP-ANTIVIRUS (recursive decompression)",
                    "body": "This message contains a ZIP archive with 5 nesting levels. EICAR test file is in the innermost layer. Modern AV engines often limit decompression depth (e.g. 3-4 levels); if server accepts (250 OK), inspection may stop before detecting the payload.",
                    "attachments": ["nested.zip"],
                },
                {"nested.zip": _nested_eicar_zip()},
            ),
        ],
        "encoded_content": [
            (
                "msg_001.json",
                {
                    "subject": "Encoded content test - Base64 (PTL-SVC-SMTP-ANTIVIRUS)",
                    "body": "This message contains EICAR in base64-encoded body. Server should decode before AV scan.",
                    "bodyBase64": eicar_b64,
                },
                {},
            ),
            (
                "msg_002.json",
                {
                    "subject": "Encoded content test - Quoted-Printable (PTL-SVC-SMTP-ANTIVIRUS)",
                    "body": "This message contains EICAR in quoted-printable encoded body.",
                    "bodyQuotedPrintable": EICAR_LINE,
                },
                {},
            ),
        ],
        "html_sanitization": [
            (
                "msg_001.json",
                {
                    "subject": "HTML sanitization test - XSS (PTL-SVC-SMTP-ANTIVIRUS)",
                    "body": "This message contains HTML with JavaScript and iframe. Webmail should sanitize.",
                    "bodyHtml": (
                        "<html><body><p>Test</p><script>alert('XSS')</script>"
                        '<iframe src="javascript:alert(1)"></iframe>'
                        "<img src=x onerror=alert(1)>"
                        "<a href=\"javascript:alert('phishing')\">Click here</a></body></html>"
                    ),
                },
                {},
            ),
        ],
        "xxe": [
            (
                "msg_001.json",
                {
                    "subject": "XXE test - XML Entity Expansion (PTL-SVC-SMTP-ANTIVIRUS)",
                    "body": "This message contains XML attachment with external entity declaration. Server should block XXE.",
                    "attachments": ["xxe_simple.xml"],
                },
                {"xxe_simple.xml": _XXE_SIMPLE_XML.encode("utf-8")},
            ),
        ],
        "mime_malformed": [
            (
                "msg_001.json",
                {
                    "subject": "MIME malformed test - parser evasion (PTL-SVC-SMTP-ANTIVIRUS)",
                    "rawEml": _MALFORMED_EML,
                },
                {},
            ),
        ],
        "zip_bomb": [
            (
                "msg_001.json",
                {
                    "subject": "Zip bomb test - resource exhaustion (PTL-SVC-SMTP-ANTIVIRUS)",
                    "body": "This message contains a zip bomb (~100KB compressed, ~100MB expanded). Use with caution. Monitor server performance.",
                    "attachments": ["zipbomb.zip"],
                },
                {"zipbomb.zip": build_full_zip_bomb()},
            ),
        ],
    }
