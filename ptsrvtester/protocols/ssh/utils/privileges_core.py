"""Protocol-agnostic core for the SSH "post-auth privileges & access" test.

Companion to the SHELL test: once an account can log in (and ideally run a
command), this decides *what that account can reach*. It contains no paramiko /
socket code — the module (:mod:`..modules.privileges`) authenticates, runs a
single enumeration script over the session, and hands the raw output here, so the
whole verdict logic is unit-testable without a live server.

Four things are assessed (exactly the operator's questions):

  * **Groups** — which user groups the account is in, and whether any of them are
    privilege-granting (``sudo``/``wheel``/``admin``…) or *root-equivalent*
    (``docker``/``lxd``/``disk``/``shadow`` — membership alone is effectively root).
  * **Filesystem** — read/write/execute rights on a fixed list of sensitive paths
    (tested with the shell's ``test`` builtin, so it reflects the account's real
    effective permissions and never reads a file's contents), plus any writable
    directory on ``$PATH`` (a PATH-hijack path to privilege escalation).
  * **Administrative commands** — which dangerous/admin binaries the account can
    invoke (``systemctl``, ``mount``, ``docker``, ``useradd``…). Informational:
    mere availability is not a vulnerability, but it frames what is reachable.
  * **Sudo** — the result of ``sudo -n -l``: passwordless sudo (especially to
    ``ALL``) is the classic instant-root finding; sudo that needs a password is a
    finding too when a login password was supplied (the same secret likely works).

Findings raised (see :class:`PrivilegesResult` properties):

  * ``group_is_finding``  — member of a privileged / root-equivalent group.
  * ``files_is_finding``  — writable sensitive file/dir, readable ``/etc/shadow``,
                            or a writable ``$PATH`` directory.
  * ``sudo_is_finding``   — passwordless sudo, or password sudo with a known login
                            password.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

# --- Section markers (shared with the module that builds the enum script) -----
M_ID = "___PT_ID___"
M_GROUPS = "___PT_GROUPS___"
M_PERMS = "___PT_PERMS___"
M_PATHW = "___PT_PATHW___"
M_CMDS = "___PT_CMDS___"
M_SUDOV = "___PT_SUDOV___"
M_SUDO = "___PT_SUDO___"
M_END = "___PT_END___"

_MARKER_TO_KEY = {
    M_ID: "id",
    M_GROUPS: "groups",
    M_PERMS: "perms",
    M_PATHW: "pathw",
    M_CMDS: "cmds",
    M_SUDOV: "sudov",
    M_SUDO: "sudo",
    M_END: "end",
}

# --- Security classification (single source of truth) -------------------------

#: Membership grants an easy, well-known path to root (no sudo needed).
ROOT_EQUIVALENT_GROUPS = frozenset({"docker", "lxd", "lxc", "disk", "shadow"})

#: Membership commonly grants administrative/root capability (usually via sudo).
PRIVILEGED_GROUPS = frozenset({"sudo", "wheel", "admin", "adm", "root", "sudoers", "staff"})


@dataclass(frozen=True)
class PathSpec:
    """A sensitive path to probe, and what a positive result means."""

    path: str
    label: str
    read_finding: bool = False   # readability is itself a finding (e.g. /etc/shadow)
    write_finding: bool = True    # writability is a finding (the common case)


#: Sensitive filesystem locations tested for r/w/x. Ordered for a stable report.
SENSITIVE_PATHS: tuple[PathSpec, ...] = (
    PathSpec("/etc/shadow", "password hashes", read_finding=True, write_finding=True),
    PathSpec("/etc/passwd", "user accounts", write_finding=True),
    PathSpec("/etc/sudoers", "sudo policy", write_finding=True),
    PathSpec("/etc/sudoers.d", "sudo policy directory", write_finding=True),
    PathSpec("/etc/ssh/sshd_config", "sshd configuration", write_finding=True),
    PathSpec("/etc/crontab", "system crontab", write_finding=True),
    PathSpec("/etc/cron.d", "cron directory", write_finding=True),
    PathSpec("/etc/hosts", "hosts file", write_finding=True),
    PathSpec("/etc", "/etc directory", write_finding=True),
    PathSpec("/root", "root home", read_finding=True, write_finding=True),
    PathSpec("/usr/local/bin", "local bin directory", write_finding=True),
)

#: Administrative / dangerous binaries whose availability is enumerated (display).
ADMIN_COMMANDS: tuple[str, ...] = (
    "sudo", "su", "passwd", "useradd", "usermod", "userdel", "groupadd", "visudo",
    "systemctl", "service", "mount", "umount", "iptables", "nft",
    "docker", "podman", "lxc", "crontab", "at",
    "apt", "apt-get", "yum", "dnf", "dpkg", "rpm",
)

#: Subset of ADMIN_COMMANDS that most directly enable privilege escalation.
HIGH_RISK_COMMANDS = frozenset({
    "docker", "podman", "lxc", "mount", "systemctl", "service",
    "iptables", "nft", "visudo", "useradd", "usermod", "userdel", "groupadd",
})


class SudoState(Enum):
    NOPASSWD_ALL = "nopasswd-all"          # passwordless sudo to ALL -> instant root
    NOPASSWD_SOME = "nopasswd-some"        # passwordless sudo to specific commands
    PASSWORD_REQUIRED = "password-required"  # has sudo rights but a password is needed
    NONE = "none"                          # not allowed to run sudo
    ABSENT = "absent"                      # sudo not installed on the host
    UNKNOWN = "unknown"                    # could not tell


@dataclass
class PermEntry:
    """r/w/x/presence result for one probed sensitive path."""

    path: str
    label: str
    present: bool
    readable: bool
    writable: bool
    executable: bool
    read_finding: bool
    write_finding: bool

    @property
    def is_finding(self) -> bool:
        return (self.readable and self.read_finding) or (self.writable and self.write_finding)

    def mode_str(self) -> str:
        return (
            ("r" if self.readable else "-")
            + ("w" if self.writable else "-")
            + ("x" if self.executable else "-")
        )


@dataclass
class PrivilegesResult:
    account: str
    authenticated: bool
    enumerated: bool                       # could we actually run the enum commands?
    username: Optional[str]
    uid: Optional[int]
    groups: list[str]
    privileged_groups: list[str]
    root_equivalent_groups: list[str]
    perms: list[PermEntry]
    writable_path_dirs: list[str]
    admin_commands: list[str]
    high_risk_commands: list[str]
    sudo_state: SudoState
    sudo_entries: list[str]
    have_password: bool
    notes: list[str] = field(default_factory=list)

    # -- finding predicates ----------------------------------------------------
    @property
    def group_is_finding(self) -> bool:
        return bool(self.privileged_groups or self.root_equivalent_groups)

    @property
    def files_is_finding(self) -> bool:
        return any(p.is_finding for p in self.perms) or bool(self.writable_path_dirs)

    @property
    def sudo_is_finding(self) -> bool:
        if self.sudo_state in (SudoState.NOPASSWD_ALL, SudoState.NOPASSWD_SOME):
            return True
        if self.sudo_state == SudoState.PASSWORD_REQUIRED and self.have_password:
            return True
        return False

    @property
    def any_finding(self) -> bool:
        return self.group_is_finding or self.files_is_finding or self.sudo_is_finding

    @property
    def writable_sensitive(self) -> list[PermEntry]:
        return [p for p in self.perms if p.writable and p.write_finding]

    @property
    def readable_sensitive(self) -> list[PermEntry]:
        return [p for p in self.perms if p.readable and p.read_finding]


# --- Parsing helpers (pure) ---------------------------------------------------

def parse_sections(raw: str) -> dict[str, list[str]]:
    """Split the enumeration script's output into its marker-delimited sections."""
    sections: dict[str, list[str]] = {}
    current: Optional[str] = None
    for line in raw.splitlines():
        key = _MARKER_TO_KEY.get(line.strip())
        if key is not None:
            current = key
            sections.setdefault(current, [])
            continue
        if current is None:
            continue
        sections[current].append(line)
    return sections


def parse_id(sections: dict[str, list[str]]) -> tuple[Optional[str], Optional[int]]:
    """Return ``(username, uid)`` parsed from the ``id`` line, if present."""
    for line in sections.get("id", []):
        m = re.search(r"uid=(\d+)\(([^)]+)\)", line)
        if m:
            return m.group(2), int(m.group(1))
    return None, None


def parse_groups(sections: dict[str, list[str]]) -> list[str]:
    """Group names from ``id -Gn`` / ``groups``, falling back to the ``id`` line."""
    for line in sections.get("groups", []):
        line = line.strip()
        if line:
            return line.split()
    for line in sections.get("id", []):
        m = re.search(r"groups=(.+)$", line)
        if m:
            return re.findall(r"\(([^)]+)\)", m.group(1))
    return []


def classify_groups(groups: list[str]) -> tuple[list[str], list[str]]:
    """Return ``(privileged, root_equivalent)`` subsets of *groups* (originals kept)."""
    root_eq = [g for g in groups if g.lower() in ROOT_EQUIVALENT_GROUPS]
    priv = [
        g for g in groups
        if g.lower() in PRIVILEGED_GROUPS and g.lower() not in ROOT_EQUIVALENT_GROUPS
    ]
    return priv, root_eq


def parse_perms(sections: dict[str, list[str]]) -> list[PermEntry]:
    """Turn the ``perms`` section (``r w x e /path`` lines) into PermEntry objects."""
    seen: dict[str, tuple[bool, bool, bool, bool]] = {}
    for line in sections.get("perms", []):
        parts = line.split()
        if len(parts) < 5:
            continue
        r, w, x, e = parts[0], parts[1], parts[2], parts[3]
        path = " ".join(parts[4:])
        seen[path] = (r == "r", w == "w", x == "x", e == "e")

    entries: list[PermEntry] = []
    for spec in SENSITIVE_PATHS:
        rwxe = seen.get(spec.path)
        if rwxe is None:
            readable = writable = executable = present = False
        else:
            readable, writable, executable, present = rwxe
        entries.append(PermEntry(
            path=spec.path, label=spec.label, present=present,
            readable=readable, writable=writable, executable=executable,
            read_finding=spec.read_finding, write_finding=spec.write_finding,
        ))
    return entries


def _nonempty(lines: list[str]) -> list[str]:
    return [ln.strip() for ln in lines if ln.strip()]


def _dedupe(items: list[str]) -> list[str]:
    """Order-preserving de-duplication (``$PATH`` may list a directory twice)."""
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


_SUDO_FULL_ROOT = re.compile(r"\(all(\s*:\s*all)?\)\s*(nopasswd:\s*)?all\b", re.IGNORECASE)


def parse_sudo(sections: dict[str, list[str]]) -> tuple[SudoState, list[str]]:
    """Classify ``sudo -n -l`` output into a :class:`SudoState` and its entries."""
    present_lines = _nonempty(sections.get("sudov", []))
    present = bool(present_lines) and present_lines[0].lower().startswith("present")
    if not present:
        return SudoState.ABSENT, []

    out_lines = sections.get("sudo", [])
    output = "\n".join(out_lines)
    low = output.lower()

    if "may run the following" in low:
        entries = [ln.strip() for ln in out_lines if ln.strip().startswith("(")]
        if _SUDO_FULL_ROOT.search(output):
            return SudoState.NOPASSWD_ALL, entries
        return SudoState.NOPASSWD_SOME, entries

    if "password is required" in low:
        return SudoState.PASSWORD_REQUIRED, []

    if ("not allowed to run sudo" in low or "not in the sudoers" in low
            or "may not run sudo" in low or "not allowed to execute" in low):
        return SudoState.NONE, []

    if not out_lines:
        return SudoState.UNKNOWN, []
    return SudoState.UNKNOWN, []


# --- Top-level assessment -----------------------------------------------------

def assess_privileges(
    *,
    account: str,
    authenticated: bool,
    sections: Optional[dict[str, list[str]]],
    have_password: bool,
    auth_note: Optional[str] = None,
) -> PrivilegesResult:
    """Turn the enumeration output into a :class:`PrivilegesResult` (see module docstring)."""
    notes: list[str] = []

    if not authenticated:
        notes.append(auth_note or (
            "could not authenticate with the supplied credentials — privileges cannot be "
            "enumerated (verify -u and the password/key)"
        ))
        return PrivilegesResult(
            account=account, authenticated=False, enumerated=False,
            username=None, uid=None, groups=[], privileged_groups=[],
            root_equivalent_groups=[], perms=[], writable_path_dirs=[],
            admin_commands=[], high_risk_commands=[], sudo_state=SudoState.UNKNOWN,
            sudo_entries=[], have_password=have_password, notes=notes,
        )

    sections = sections or {}
    enumerated = bool(sections.get("id") or sections.get("groups") or sections.get("perms"))
    if not enumerated:
        notes.append(
            "authenticated, but the enumeration commands produced no output — the account "
            "is likely shell-restricted (nologin / SFTP-only / forced command). Run the SHELL "
            "test to confirm what the account can do."
        )

    username, uid = parse_id(sections)
    groups = parse_groups(sections)
    privileged, root_eq = classify_groups(groups)
    perms = parse_perms(sections)
    writable_path_dirs = _dedupe(_nonempty(sections.get("pathw", [])))
    admin_commands = _nonempty(sections.get("cmds", []))
    high_risk = [c for c in admin_commands if c in HIGH_RISK_COMMANDS]
    sudo_state, sudo_entries = parse_sudo(sections)

    result = PrivilegesResult(
        account=account, authenticated=True, enumerated=enumerated,
        username=username, uid=uid, groups=groups, privileged_groups=privileged,
        root_equivalent_groups=root_eq, perms=perms, writable_path_dirs=writable_path_dirs,
        admin_commands=admin_commands, high_risk_commands=high_risk,
        sudo_state=sudo_state, sudo_entries=sudo_entries,
        have_password=have_password, notes=notes,
    )

    if uid == 0:
        result.notes.append("account has uid 0 (root-equivalent user)")
    if sudo_state == SudoState.PASSWORD_REQUIRED and have_password:
        result.notes.append(
            "sudo needs a password, but a password was supplied for login — the same secret "
            "very likely grants full sudo (privilege escalation)"
        )
    return result


__all__ = [
    "M_ID", "M_GROUPS", "M_PERMS", "M_PATHW", "M_CMDS", "M_SUDOV", "M_SUDO", "M_END",
    "ROOT_EQUIVALENT_GROUPS", "PRIVILEGED_GROUPS", "SENSITIVE_PATHS", "ADMIN_COMMANDS",
    "HIGH_RISK_COMMANDS", "PathSpec", "PermEntry", "SudoState", "PrivilegesResult",
    "parse_sections", "parse_id", "parse_groups", "classify_groups", "parse_perms",
    "parse_sudo", "assess_privileges",
]
