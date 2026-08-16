"""
SSH service identification from the server banner.
Maps banner content to product name, version (if numeric) and CPE 2.3 (NVD-style).
Only numeric app versions (e.g. 7.4p1, 2020.81) are used as version and in CPE.

This is the SSH-only slice of the shared identifier: it recognises the SSH server
products (OpenSSH, libssh, Dropbear, PuTTY, Cisco IOS) — other protocols keep their
own tables.

CPE 2.3 (NIST/NVD) has exactly 11 components after the "cpe:2.3:" prefix:
  part, vendor, product, version, update, edition, language, sw_edition, target_sw, target_hw, other.
Unknown/NA components are represented as *.
"""
import re
from dataclasses import dataclass
from typing import Final

_CPE_VERSION_RE = re.compile(r"^\d+[.\d]*(?:p\d+)?[\w.-]*$", re.I)

_CPE_23_NUM_COMPONENTS = 11


def _cpe_23_normalize(cpe: str) -> str:
    """Return CPE 2.3 string with all 11 components; pad with * if shorter."""
    if not cpe or not cpe.startswith("cpe:2.3:"):
        return cpe
    parts = cpe.split(":")
    if len(parts) < 3:
        return cpe
    components = parts[2:]
    while len(components) < _CPE_23_NUM_COMPONENTS:
        components.append("*")
    return ":".join([parts[0], parts[1]] + components[: _CPE_23_NUM_COMPONENTS])


# (pattern re, product display name, CPE base with wildcard version)
# Order: more specific first. Version is the first capture group if present.
# CPE vendor/product from NVD where available.
_BANNER_PATTERNS: Final[list[tuple[re.Pattern[str], str, str]]] = [
    (re.compile(r"SSH-2\.0-OpenSSH_([\d\.]+(?:p\d+)?)", re.I), "OpenSSH", "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"),
    (re.compile(r"OpenSSH_([\d\.]+(?:p\d+)?)", re.I), "OpenSSH", "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"),
    (re.compile(r"SSH-2\.0-libssh_([\d\.]+)", re.I), "libssh", "cpe:2.3:a:libssh:libssh:*:*:*:*:*:*:*:*"),
    (re.compile(r"libssh[_ ]([\d\.]+)", re.I), "libssh", "cpe:2.3:a:libssh:libssh:*:*:*:*:*:*:*:*"),
    (re.compile(r"SSH-2\.0-dropbear_(\d{4}\.\d+)", re.I), "Dropbear SSH", "cpe:2.3:a:dropbear_ssh_project:dropbear_ssh:*:*:*:*:*:*:*:*"),
    (re.compile(r"dropbear[_ ](\d{4}\.\d+)", re.I), "Dropbear SSH", "cpe:2.3:a:dropbear_ssh_project:dropbear_ssh:*:*:*:*:*:*:*:*"),
    (re.compile(r"SSH-2\.0-dropbear", re.I), "Dropbear SSH", "cpe:2.3:a:dropbear_ssh_project:dropbear_ssh:*:*:*:*:*:*:*:*"),
    (re.compile(r"SSH-2\.0-PuTTY(?:_Release_)?([\d\.]+)?", re.I), "PuTTY", "cpe:2.3:a:simon_tatham:putty:*:*:*:*:*:*:*:*"),
    (re.compile(r"\bPuTTY\b", re.I), "PuTTY", "cpe:2.3:a:simon_tatham:putty:*:*:*:*:*:*:*:*"),
    (re.compile(r"SSH-2\.0-Cisco-\d+\.\d+(?:\.\d+)?", re.I), "Cisco IOS SSH", "cpe:2.3:o:cisco:ios:*:*:*:*:*:*:*:*"),
    (re.compile(r"SSH-2\.0-Cisco", re.I), "Cisco IOS SSH", "cpe:2.3:o:cisco:ios:*:*:*:*:*:*:*:*"),
]


# Generic SSH software token: everything after the "SSH-<proto>-" prefix, up to the
# first space (the optional free-text comments start after a space).
_SSH_SOFTWARE_RE = re.compile(r"^SSH-\d+(?:\.\d+)?-(\S+)", re.I)
# A dotted version number inside that token (allow a leading "_"/"-" separator, but not
# a digit/dot, so we don't split a longer number). Matches 8.0.9648, 1.1, 3.2.1p2, ...
_GENERIC_VERSION_RE = re.compile(r"(?<![\d.])\d+(?:\.\d+)+(?:p\d+)?")


@dataclass(frozen=True)
class ServiceIdentification:
    """Result of banner-based service identification."""
    product: str
    version: str | None
    cpe: str
    os: str | None = None


def _generic_version_disclosure(first_line: str) -> ServiceIdentification | None:
    """Fallback for SSH servers not in the pattern table.

    A banner like ``SSH-2.0-RebexSSH_8.0.9648`` discloses a concrete product and
    version even though we can't map it to a CPE. Return that product+version (with
    an empty CPE) so the banner test still flags the version disclosure; return None
    when the banner exposes no version at all (e.g. ``SSH-2.0-mysshd``).
    """
    m = _SSH_SOFTWARE_RE.match(first_line)
    if not m:
        return None
    software = m.group(1)
    mver = _GENERIC_VERSION_RE.search(software)
    if not mver:
        return None
    version = mver.group(0)
    product = software[: mver.start()].rstrip("_-/. ") or software
    return ServiceIdentification(product=product, version=version, cpe="", os=None)


def identify_service(banner: str | None) -> ServiceIdentification | None:
    """
    Identify product and optional version from an SSH server banner.
    Returns ServiceIdentification(product, version, cpe, os) or None if no match.
    Version is set only for numeric app versions; non-numeric captures go to os.
    CPE uses * for version when not found (full 11-attribute CPE 2.3 string).
    """
    if not banner or not banner.strip():
        return None
    text = banner.replace("\r", " ").strip()
    if not text:
        return None
    first_line = text.split("\n")[0].strip() if "\n" in text else text
    for pattern, product, cpe_base in _BANNER_PATTERNS:
        m = pattern.search(first_line)
        if m:
            raw = m.group(1).strip() if m.lastindex and m.lastindex >= 1 else None
            if raw and _CPE_VERSION_RE.match(raw):
                version, os_str = raw, None
            elif raw:
                version, os_str = None, raw
            else:
                version, os_str = None, None
            cpe_parts = cpe_base.split(":")
            use_in_cpe = (
                bool(version)
                and cpe_base.startswith("cpe:2.3:")
                and len(cpe_parts) >= 6
                and cpe_parts[5] == "*"
            )
            if use_in_cpe:
                injected = list(cpe_parts)
                injected[5] = version
                cpe = ":".join(injected)
            else:
                cpe = cpe_base
            cpe = _cpe_23_normalize(cpe)
            return ServiceIdentification(product=product, version=version, cpe=cpe, os=os_str)
    return _generic_version_disclosure(first_line)