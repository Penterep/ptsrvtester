"""Protocol-agnostic core for the SSH "SFTP content scanning & resource limits" test.

Companion to the SFTP confinement test. Where SFTP asks *where can the account
go*, this asks *what happens to what it uploads* and *are there limits*:

  * **Antivirus** — is an uploaded EICAR test file detected / rejected /
    quarantined, or does it persist intact (no on-upload scanning)?
  * **Content-processing DoS** — does the server decompress / parse uploaded
    content (a bounded, highly-compressible "archive" and an XXE probe)? If it
    spends measurably more time on the compressible payload than on an
    incompressible baseline of the same on-wire size, it processes uploads — a
    ZIP-bomb / XXE denial-of-service surface.
  * **Quota / disk-fill** — is any size or file-count limit enforced? Bounded
    probes write up to a small default and create up to a small number of files;
    if neither limit is hit, filling the disk (DoS) is likely possible.

No paramiko / socket code: the module drives the (bounded, cleaned-up) uploads
and hands the observations here, so the verdicts are unit-testable. Every default
is deliberately small; the module clamps the operator's flags to safe caps.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# Safe defaults + hard caps (the module clamps CLI values to the caps).
DEFAULT_MAX_MB = 10
CAP_MAX_MB = 200
DEFAULT_MAX_FILES = 100
CAP_MAX_FILES = 2000
DEFAULT_BOMB_MB = 10
CAP_BOMB_MB = 200

#: Timing amplification needed to suspect the server processed (decompressed) an upload.
PROCESSING_RATIO = 3.0
PROCESSING_ABS_SECONDS = 1.0


@dataclass
class SftpDataObservations:
    authenticated: bool = False
    sftp_available: bool = False

    # antivirus (EICAR)
    eicar_attempted: bool = False
    eicar_write_rejected: bool = False
    eicar_persisted_intact: Optional[bool] = None
    eicar_note: str = ""

    # content-processing DoS (bomb / xxe)
    processing_tested: bool = False
    baseline_seconds: Optional[float] = None
    bomb_seconds: Optional[float] = None
    bomb_rejected: bool = False
    xxe_uploaded: Optional[bool] = None

    # quota / disk-fill
    quota_tested: bool = False
    mb_written: float = 0.0
    size_limit_hit: bool = False
    size_limit_at_mb: Optional[float] = None
    files_created: int = 0
    count_limit_hit: bool = False
    count_limit_at: Optional[int] = None

    notes: list[str] = field(default_factory=list)


@dataclass
class SftpDataResult:
    account: str
    obs: SftpDataObservations
    notes: list[str] = field(default_factory=list)

    @property
    def processing_suspected(self) -> bool:
        o = self.obs
        if not o.processing_tested:
            return False
        if o.bomb_seconds is not None and o.baseline_seconds is not None:
            if (o.bomb_seconds >= max(o.baseline_seconds * PROCESSING_RATIO,
                                      o.baseline_seconds + PROCESSING_ABS_SECONDS)):
                return True
        return False

    # -- finding predicates ----------------------------------------------------
    @property
    def no_antivirus_finding(self) -> bool:
        o = self.obs
        return o.eicar_attempted and o.eicar_persisted_intact is True and not o.eicar_write_rejected

    @property
    def processing_dos_finding(self) -> bool:
        return self.processing_suspected

    @property
    def no_quota_finding(self) -> bool:
        o = self.obs
        return o.quota_tested and not o.size_limit_hit and not o.count_limit_hit

    @property
    def any_finding(self) -> bool:
        return self.no_antivirus_finding or self.processing_dos_finding or self.no_quota_finding


def assess_sftpdata(*, account: str, obs: SftpDataObservations) -> SftpDataResult:
    """Wrap observations into a :class:`SftpDataResult` with explanatory notes."""
    notes: list[str] = list(obs.notes)

    if not obs.authenticated:
        notes.append("could not authenticate with the supplied credentials — content/limit "
                     "checks cannot run (verify -u and the password/key)")
        return SftpDataResult(account=account, obs=obs, notes=notes)
    if not obs.sftp_available:
        notes.append("the SFTP subsystem is not available for this account — nothing to upload")
        return SftpDataResult(account=account, obs=obs, notes=notes)

    result = SftpDataResult(account=account, obs=obs, notes=notes)

    if obs.eicar_attempted:
        if obs.eicar_write_rejected:
            notes.append("the EICAR upload was rejected outright (an AV/DLP layer blocked the write)")
        elif obs.eicar_persisted_intact is True:
            notes.append("the EICAR test file was stored intact — no antivirus scanning on upload "
                         "(note: on-access scanning by another process is not observable here)")
        elif obs.eicar_persisted_intact is False:
            notes.append("the EICAR test file was removed/altered after upload — antivirus appears active")

    if obs.processing_tested:
        if result.processing_suspected:
            notes.append(f"the compressible upload took {obs.bomb_seconds:.2f}s vs a "
                         f"{obs.baseline_seconds:.2f}s baseline — the server appears to "
                         "decompress/process uploads (ZIP-bomb / XXE DoS surface)")
        elif obs.bomb_rejected:
            notes.append("the server rejected the compressible archive quickly — it inspects "
                         "uploads but bounded the work (not a clear DoS)")
        else:
            notes.append("no timing amplification observed — no evidence the server decompresses "
                         "uploads on receipt")

    if obs.quota_tested:
        if obs.size_limit_hit:
            notes.append(f"a size limit was hit at ~{obs.size_limit_at_mb:.1f} MB (quota enforced)")
        if obs.count_limit_hit:
            notes.append(f"a file-count limit was hit at {obs.count_limit_at} files (quota enforced)")
        if not obs.size_limit_hit and not obs.count_limit_hit:
            notes.append(f"no size or count limit within the tested bounds "
                         f"(~{obs.mb_written:.0f} MB, {obs.files_created} files) — filling the disk "
                         "(DoS) is likely possible; a full quota test was not run to avoid harm")

    return result


__all__ = [
    "DEFAULT_MAX_MB", "CAP_MAX_MB", "DEFAULT_MAX_FILES", "CAP_MAX_FILES",
    "DEFAULT_BOMB_MB", "CAP_BOMB_MB", "PROCESSING_RATIO", "PROCESSING_ABS_SECONDS",
    "SftpDataObservations", "SftpDataResult", "assess_sftpdata",
]
