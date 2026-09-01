"""Protocol-agnostic core for the SSH "is shell access permitted?" test.

Contains no paramiko / socket code: the verdict logic is fed the results of two
post-authentication probes — command execution (``exec_command``) and an
interactive shell (PTY + ``invoke_shell``) — so it can be unit-tested without a
live server. The module (:mod:`..modules.shellaccess`) authenticates with the
supplied credentials, runs the two probes, and hands their outcomes here.

Shell access can only be tested *after* a successful login, so this test needs
valid credentials. Each probe runs a command that proves **execution** (an
arithmetic marker the shell must evaluate, so a bare terminal echo of the typed
command does not count as success). The verdicts:

  * ``shell``      — an interactive shell was obtained (strongest). A finding.
  * ``exec``       — command execution works but no interactive shell. A finding.
  * ``restricted`` — authenticated, but neither a shell nor command execution
                     (nologin / ``/bin/false`` / SFTP-only / ForceCommand).
  * ``no-auth``    — could not authenticate, so shell access was not tested.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

#: Substrings that hint the account is deliberately shell-less (for a nicer note).
_RESTRICTED_HINTS = (
    "not available",
    "nologin",
    "no shell",
    "shell is not",
    "this service allows sftp connections only",
    "permission denied",
)


@dataclass
class ProbeOutcome:
    """Result of one post-auth probe (command exec or interactive shell)."""

    ok: bool                        # the execution marker came back
    output: str = ""                # captured channel output (trimmed)
    note: Optional[str] = None      # error/explanation, if any
    exit_status: Optional[int] = None


@dataclass
class ShellAccessResult:
    account: str
    authenticated: bool
    exec_result: Optional[ProbeOutcome]
    shell_result: Optional[ProbeOutcome]
    verdict: str                    # shell | exec | restricted | no-auth
    banner: Optional[str]           # captured text when restricted (e.g. nologin msg)
    notes: list[str] = field(default_factory=list)

    @property
    def is_finding(self) -> bool:
        """Shell access is reportable when a shell or command execution was obtained."""
        return self.verdict in ("shell", "exec")


def _restricted_hint(*outputs: Optional[str]) -> Optional[str]:
    for text in outputs:
        if not text:
            continue
        low = text.lower()
        for hint in _RESTRICTED_HINTS:
            if hint in low:
                return text.strip()
    return None


def assess_shell_access(
    *,
    account: str,
    authenticated: bool,
    exec_result: Optional[ProbeOutcome] = None,
    shell_result: Optional[ProbeOutcome] = None,
    auth_note: Optional[str] = None,
) -> ShellAccessResult:
    """Turn the two probe outcomes into a verdict (see module docstring)."""
    notes: list[str] = []

    if not authenticated:
        if auth_note:
            notes.append(auth_note)
        else:
            notes.append("could not authenticate with the supplied credentials — shell access "
                         "cannot be tested (verify -u and the password/key)")
        return ShellAccessResult(
            account=account, authenticated=False, exec_result=exec_result,
            shell_result=shell_result, verdict="no-auth", banner=None, notes=notes,
        )

    shell_ok = bool(shell_result and shell_result.ok)
    exec_ok = bool(exec_result and exec_result.ok)

    if shell_ok:
        verdict = "shell"
        banner = None
    elif exec_ok:
        verdict = "exec"
        banner = None
        notes.append("command execution works, but an interactive shell was not obtained")
    else:
        verdict = "restricted"
        banner = _restricted_hint(
            shell_result.output if shell_result else None,
            exec_result.output if exec_result else None,
        )
        notes.append("authenticated, but neither an interactive shell nor command execution "
                     "succeeded — the account looks shell-restricted (nologin / SFTP-only / "
                     "forced command)")

    # Surface probe-level errors for the operator (verbose-friendly).
    for label, res in (("exec", exec_result), ("shell", shell_result)):
        if res and res.note:
            notes.append(f"{label}: {res.note}")

    return ShellAccessResult(
        account=account, authenticated=True, exec_result=exec_result,
        shell_result=shell_result, verdict=verdict, banner=banner, notes=notes,
    )


__all__ = ["ProbeOutcome", "ShellAccessResult", "assess_shell_access"]
