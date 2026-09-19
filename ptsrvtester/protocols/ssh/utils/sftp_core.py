"""Protocol-agnostic core for the SSH "SFTP access control & confinement" test.

Contains no paramiko / socket code: the module (:mod:`..modules.sftp`) drives the
SFTP session and reduces each probe to plain observations collected in
:class:`SftpObservations`; this module turns those into findings, so the verdict
logic is unit-testable without a live server.

The questions answered (all post-authentication, over one SFTP session):

  * **SFTP/SCP available** — did ``open_sftp()`` succeed; is command execution
    (which SCP rides on) also available?
  * **Chroot confinement** — is the account confined to a sub-tree
    (``ChrootDirectory``), or can it browse the real filesystem? Inferred from
    whether canonical system paths (``/etc/passwd``, ``/bin``…) are reachable and
    what the visible root looks like.
  * **Read/write outside the tree** — can it read system files or *write* to
    system locations (``/``, ``/tmp``, a parent of the login dir)? Bounded write
    probes only, always cleaned up by the module.
  * **Symlink escape** — can it create a symlink that resolves outside the
    confinement (e.g. to ``/etc/passwd``) and read through it? (Hardlinks are not
    exposed by the SFTP client, so only noted.)
  * **Unexpected SSH capabilities** — an account meant for SFTP only should not
    also get a shell, command execution or port forwarding; if it does, it is not
    properly restricted.
  * **ADS write** — on an NTFS/Windows server, can it write an NTFS Alternate
    Data Stream (``file:stream``) to hide data / bypass scanning?

Findings raised (see :class:`SftpResult`): no chroot confinement, write outside
the tree, symlink escape, an unrestricted "SFTP" account, and ADS write.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SftpObservations:
    authenticated: bool = False
    sftp_available: bool = False
    home: Optional[str] = None
    confined: Optional[bool] = None
    system_readable: list[str] = field(default_factory=list)
    system_writable: list[str] = field(default_factory=list)
    symlink_supported: Optional[bool] = None
    symlink_escape: bool = False
    symlink_detail: str = ""
    exec_ok: Optional[bool] = None
    shell_ok: Optional[bool] = None
    forward_ok: Optional[bool] = None
    scp_available: Optional[bool] = None
    ads_supported: Optional[bool] = None
    notes: list[str] = field(default_factory=list)


@dataclass
class SftpResult:
    account: str
    obs: SftpObservations
    notes: list[str] = field(default_factory=list)

    @property
    def extra_capabilities(self) -> list[str]:
        caps: list[str] = []
        if self.obs.exec_ok:
            caps.append("command execution")
        if self.obs.shell_ok:
            caps.append("interactive shell")
        if self.obs.forward_ok:
            caps.append("port forwarding")
        return caps

    @property
    def no_chroot_finding(self) -> bool:
        return self.obs.sftp_available and self.obs.confined is False

    @property
    def write_outside_finding(self) -> bool:
        return bool(self.obs.system_writable)

    @property
    def read_outside_finding(self) -> bool:
        return bool(self.obs.system_readable)

    @property
    def symlink_finding(self) -> bool:
        return self.obs.symlink_escape

    @property
    def unrestricted_finding(self) -> bool:
        return self.obs.sftp_available and bool(self.extra_capabilities)

    @property
    def ads_finding(self) -> bool:
        return self.obs.ads_supported is True

    @property
    def any_finding(self) -> bool:
        return (self.no_chroot_finding or self.write_outside_finding
                or self.symlink_finding or self.unrestricted_finding or self.ads_finding)


def assess_sftp(*, account: str, obs: SftpObservations) -> SftpResult:
    """Wrap observations into a :class:`SftpResult` and add explanatory notes."""
    notes: list[str] = list(obs.notes)

    if not obs.authenticated:
        notes.append("could not authenticate with the supplied credentials — SFTP access "
                     "control cannot be tested (verify -u and the password/key)")
        return SftpResult(account=account, obs=obs, notes=notes)

    if not obs.sftp_available:
        notes.append("the SFTP subsystem is not available for this account (open_sftp failed) — "
                     "the server may be shell-only, or the account is otherwise restricted")
        return SftpResult(account=account, obs=obs, notes=notes)

    if obs.confined is False:
        notes.append("the account can browse the real filesystem (no ChrootDirectory) — if this "
                     "account is meant for file transfer only, it should be chrooted")
    elif obs.confined is True:
        notes.append("the account appears confined to a sub-tree (chroot / internal-sftp)")

    if obs.system_writable:
        notes.append("writable location(s) outside the intended tree: "
                     + ", ".join(obs.system_writable))

    if obs.symlink_escape:
        notes.append("symlink escape: " + (obs.symlink_detail or "a symlink resolved outside the tree"))
    elif obs.symlink_supported is False:
        notes.append("the server refused symlink creation (good — blocks a common escape)")

    result = SftpResult(account=account, obs=obs, notes=notes)

    if result.unrestricted_finding:
        extra = ", ".join(result.extra_capabilities)
        confinement = "chrooted " if obs.confined else ""
        notes.append(f"the {confinement}SFTP account also has: {extra} — it is not restricted "
                     "to file transfer (expected: ForceCommand internal-sftp with no shell/exec)")

    return result


__all__ = ["SftpObservations", "SftpResult", "assess_sftp"]
