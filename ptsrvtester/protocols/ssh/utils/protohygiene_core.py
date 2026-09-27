"""Protocol-agnostic core for the SSH "protocol & config hygiene" tests.

Two pre-auth checks, no credentials and no paramiko needed — the module reads the
raw handshake (identification banner + KEXINIT name-lists) and hands the parsed
values here so the verdicts are unit-testable:

  * **Terrapin (CVE-2023-48795)** — a prefix-truncation attack on the SSH
    transport. A connection is exploitable when a *vulnerable* cipher mode is used
    (``chacha20-poly1305@openssh.com``, or a CBC cipher paired with an
    Encrypt-then-MAC ``*-etm@openssh.com`` MAC) *and* the "strict kex"
    countermeasure is not in effect. A server is reported vulnerable when it
    offers such a mode but does **not** advertise ``kex-strict-s-v00@openssh.com``
    in its KEX list (the same criterion ssh-audit / the Terrapin scanner use).

  * **SSHv1** — SSH protocol version 1 is cryptographically broken (CRC-32 attack,
    trivial MITM). The identification string's protocol version reveals support:
    ``2.0`` is SSH-2 only (OK), ``1.99`` means the server also speaks SSH-1
    (fallback available), and ``1.x`` means SSH-1 only. Any SSH-1 support is a
    finding.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

CHACHA20 = "chacha20-poly1305@openssh.com"
STRICT_KEX_SERVER = "kex-strict-s-v00@openssh.com"
ETM_SUFFIX = "-etm@openssh.com"


@dataclass
class TerrapinResult:
    readable: bool
    strict_kex: Optional[bool] = None
    chacha_present: bool = False
    cbc_etm_present: bool = False
    vulnerable: Optional[bool] = None
    vulnerable_modes: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def is_finding(self) -> bool:
        return self.vulnerable is True


def _dir_cbc_etm(enc: list[str], mac: list[str]) -> bool:
    cbc = any(e.endswith("-cbc") for e in enc)
    etm = any(m.endswith(ETM_SUFFIX) for m in mac)
    return cbc and etm


def assess_terrapin(kexinit: Optional[dict]) -> TerrapinResult:
    """Classify Terrapin exploitability from a parsed KEXINIT (see module docstring)."""
    if not kexinit or not kexinit.get("kex"):
        return TerrapinResult(
            readable=False,
            notes=["could not read the server's KEXINIT (SSH-2 transport not available)"],
        )

    kex = kexinit.get("kex", [])
    enc_c2s = kexinit.get("enc_c2s", [])
    enc_s2c = kexinit.get("enc_s2c", [])
    mac_c2s = kexinit.get("mac_c2s", [])
    mac_s2c = kexinit.get("mac_s2c", [])
    enc_all = set(enc_c2s) | set(enc_s2c)

    strict = STRICT_KEX_SERVER in kex
    chacha = CHACHA20 in enc_all
    cbc_etm = _dir_cbc_etm(enc_c2s, mac_c2s) or _dir_cbc_etm(enc_s2c, mac_s2c)

    modes: list[str] = []
    if chacha:
        modes.append(CHACHA20)
    if cbc_etm:
        modes.append("CBC cipher + Encrypt-then-MAC (*-etm@openssh.com)")

    vulnerable = (not strict) and bool(modes)

    notes: list[str] = []
    if strict:
        notes.append("the server advertises kex-strict-s-v00@openssh.com — the strict-kex "
                     "countermeasure neutralises Terrapin")
    elif not modes:
        notes.append("no Terrapin-affected cipher mode is offered (no ChaCha20-Poly1305 and no "
                     "CBC+EtM) — not exploitable even without strict kex")
    else:
        notes.append("the server does not advertise strict kex and offers a Terrapin-affected "
                     "cipher mode — the handshake can be prefix-truncated")

    return TerrapinResult(
        readable=True, strict_kex=strict, chacha_present=chacha, cbc_etm_present=cbc_etm,
        vulnerable=vulnerable, vulnerable_modes=modes, notes=notes,
    )


@dataclass
class SSHv1Result:
    banner: Optional[str]
    protoversion: Optional[str]
    supports_v1: bool
    only_v1: bool
    supports_v2: bool

    @property
    def is_finding(self) -> bool:
        return self.supports_v1


def parse_protoversion(banner: Optional[str]) -> Optional[str]:
    """Extract the protocol version field from ``SSH-<proto>-<software>``."""
    if not banner or not banner.startswith("SSH-"):
        return None
    parts = banner.split("-", 2)
    return parts[1] if len(parts) >= 2 else None


def assess_sshv1(banner: Optional[str]) -> SSHv1Result:
    """Decide SSH-1 support from the identification banner."""
    pv = parse_protoversion(banner)
    if pv is None:
        return SSHv1Result(banner=banner, protoversion=None, supports_v1=False,
                           only_v1=False, supports_v2=False)
    supports_v1 = pv.startswith("1.")
    only_v1 = supports_v1 and pv != "1.99"
    supports_v2 = pv == "2.0" or pv == "1.99"
    return SSHv1Result(banner=banner, protoversion=pv, supports_v1=supports_v1,
                       only_v1=only_v1, supports_v2=supports_v2)


__all__ = [
    "CHACHA20", "STRICT_KEX_SERVER", "TerrapinResult", "assess_terrapin",
    "SSHv1Result", "parse_protoversion", "assess_sshv1",
]
