"""POP3 result types and vulnerability codes."""
from __future__ import annotations

from enum import Enum
from typing import NamedTuple

from .helpers import Creds
from .ptntlmauth.ptntlmauth import NTLMInfo


class NTLMResult(NamedTuple):
    success: bool
    ntlm: NTLMInfo | None


class InfoResult(NamedTuple):
    banner: str | None
    capability: dict[str, list[str]] | None
    capability_stls: dict[str, list[str]] | None = None


class HelpInfoResult(NamedTuple):
    """HELP (non-standard) + IMPLEMENTATION from CAPA (RFC 2449)."""
    help_response: str | None
    implementation: str | None


class EncryptionResult(NamedTuple):
    plaintext_ok: bool
    stls_ok: bool
    tls_ok: bool


CatchAllResult = str  # "not_configured" | "indeterminate"


class VULNS(Enum):
    Anonymous = "PTV-GENERAL-ANONYMOUS"
    NTLM = "PTV-GENERAL-NTLMINFO"
    WeakCreds = "PTV-GENERAL-WEAKCREDENTIALS"
    Banner = "PTV-SVC-BANNER"
