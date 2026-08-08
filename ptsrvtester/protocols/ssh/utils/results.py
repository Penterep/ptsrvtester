"""Result types shared by the SSH modules.

These are the same dataclasses / named tuples the old flat ``protocols/ssh.py``
used; they are collected here so every ``modules/*.py`` can import them from one
place (absolute import — the modules are loaded dynamically by BaseMain and have
no package parent, so relative imports would fail).
"""
from dataclasses import dataclass
from enum import Enum
from typing import NamedTuple

from ptsrvtester.protocols.ssh.utils.helpers import Creds


class PrivKeyDetails(NamedTuple):
    keypath: str
    passphrase: str | None


@dataclass(frozen=True)
class SSHCreds(Creds):
    privkey: PrivKeyDetails | None


class BruteResult(NamedTuple):
    creds: set[SSHCreds]
    errors: bool


class BadPubkeyResult(NamedTuple):
    bad: bool
    path: str


class CVE(NamedTuple):
    name: str
    description: str
    severity: float


class CryptoFinding(NamedTuple):
    level: str
    action: str
    category: str
    name: str
    notes: str


class SSHAuditResult(NamedTuple):
    err: str | int | None  # sys._ExitCode
    cryptofindings: list[CryptoFinding]
    cves: list[CVE]


class InfoResult(NamedTuple):
    banner: str | None
    host_key: str | None
    auth_methods: list[str] | None


class VULNS(Enum):
    CVE = "PTV-GENERAL-VULNERABLEVERSION"
    InsecureCrypto = "PTV-GENERAL-INSECURECRYPTO"
    BadHostKey = "PTV-SSH-BADHOSTKEY"
    BadAuthKeys = "PTV-SSH-BADAUTHKEYS"
    WeakCreds = "PTV-GENERAL-WEAKCREDENTIALS"
    Banner = "PTV-SVC-BANNER"