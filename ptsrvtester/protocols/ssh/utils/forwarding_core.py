"""Protocol-agnostic core for the SSH "port forwarding & tunneling" test.

Contains no paramiko / socket code: the module (:mod:`..modules.forwarding`)
performs the live probes and reduces each to a small :class:`State`, then hands
the states here for classification and verdicts — so the whole decision logic
(including the ``PermitOpen`` inference from a set of local-forward probes) is
unit-testable without a live server.

Capabilities assessed (all post-authentication):

  * **Local forwarding** (``direct-tcpip``) — the client asks the server to open
    an outbound TCP connection (``ssh -L``). Also underlies **dynamic / SOCKS**
    forwarding (``ssh -D``), which opens on-demand ``direct-tcpip`` channels, so
    SOCKS availability equals local-forwarding availability.
  * **PermitOpen** — inferred: if some destinations are allowed while others are
    *administratively prohibited*, a ``PermitOpen`` (or similar) allow-list is in
    effect rather than a blanket ``AllowTcpForwarding no``.
  * **Remote forwarding** (``tcpip-forward``) — the client asks the server to
    listen on a port and forward back (``ssh -R``).
  * **GatewayPorts** — a remote-forward bind on the wildcard address; only weakly
    observable remotely (OpenSSH silently downgrades to loopback when
    ``GatewayPorts no``), so it is reported with that caveat, never as a finding
    on its own.
  * **Agent forwarding** (``auth-agent-req@openssh.com``) — lets the server reach
    the client's ssh-agent (risk: agent hijack on a compromised host).
  * **X11 forwarding** (``x11-req``) — lets the server open X11 connections back
    (risk: keystroke/screen capture).
  * **PTY** (``pty-req``) — whether an interactive pseudo-terminal is granted.

Findings raised (see :class:`ForwardingResult`): TCP forwarding enabled
(local/remote/dynamic — pivoting/lateral-movement surface), agent forwarding
enabled, and X11 forwarding enabled.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class State(Enum):
    ALLOWED = "allowed"
    DENIED = "denied"
    ERROR = "error"
    UNKNOWN = "unknown"
    SKIPPED = "skipped"


@dataclass
class LocalProbe:
    """One ``direct-tcpip`` (local-forward) attempt to a specific destination."""

    dest: str
    state: State
    detail: str = ""


@dataclass
class ForwardingResult:
    account: str
    authenticated: bool
    local: State
    local_probes: list[LocalProbe]
    permitopen_restricted: Optional[bool]
    remote: State
    gateway: State
    agent: State
    x11: State
    pty: State
    notes: list[str] = field(default_factory=list)

    @property
    def dynamic(self) -> State:
        """SOCKS / dynamic forwarding uses on-demand ``direct-tcpip`` — same as local."""
        return self.local

    @property
    def tcp_forwarding_finding(self) -> bool:
        return State.ALLOWED in (self.local, self.remote)

    @property
    def agent_finding(self) -> bool:
        return self.agent == State.ALLOWED

    @property
    def x11_finding(self) -> bool:
        return self.x11 == State.ALLOWED

    @property
    def any_finding(self) -> bool:
        return self.tcp_forwarding_finding or self.agent_finding or self.x11_finding

    def enabled_tcp_kinds(self) -> list[str]:
        """Human list of the TCP-forwarding kinds found enabled (for the report)."""
        kinds: list[str] = []
        if self.local == State.ALLOWED:
            kinds.append("local (-L)")
            kinds.append("dynamic/SOCKS (-D)")
        if self.remote == State.ALLOWED:
            kinds.append("remote (-R)")
        return kinds


def classify_local(probes: list[LocalProbe]) -> tuple[State, Optional[bool]]:
    """Reduce the per-destination local probes to ``(overall_state, permitopen_restricted)``.

    * any allowed + any denied -> ALLOWED, restricted=True  (an allow-list is filtering)
    * all allowed              -> ALLOWED, restricted=False
    * all denied               -> DENIED,  restricted=None  (blanket off, or list excludes probes)
    * nothing conclusive       -> UNKNOWN, restricted=None
    """
    allowed = any(p.state == State.ALLOWED for p in probes)
    denied = any(p.state == State.DENIED for p in probes)
    if allowed and denied:
        return State.ALLOWED, True
    if allowed:
        return State.ALLOWED, False
    if denied:
        return State.DENIED, None
    return State.UNKNOWN, None


def assess_forwarding(
    *,
    account: str,
    authenticated: bool,
    local_probes: Optional[list[LocalProbe]] = None,
    remote: State = State.UNKNOWN,
    gateway: State = State.UNKNOWN,
    agent: State = State.UNKNOWN,
    x11: State = State.UNKNOWN,
    pty: State = State.UNKNOWN,
    auth_note: Optional[str] = None,
) -> ForwardingResult:
    """Assemble a :class:`ForwardingResult` from the collected probe states."""
    notes: list[str] = []

    if not authenticated:
        notes.append(auth_note or (
            "could not authenticate with the supplied credentials — forwarding capabilities "
            "cannot be tested (verify -u and the password/key)"
        ))
        return ForwardingResult(
            account=account, authenticated=False, local=State.UNKNOWN, local_probes=[],
            permitopen_restricted=None, remote=State.UNKNOWN, gateway=State.UNKNOWN,
            agent=State.UNKNOWN, x11=State.UNKNOWN, pty=State.UNKNOWN, notes=notes,
        )

    local_probes = local_probes or []
    local, permitopen_restricted = classify_local(local_probes)

    if permitopen_restricted:
        notes.append(
            "PermitOpen (or a similar allow-list) is in effect: some local-forward destinations "
            "were allowed while others were administratively prohibited"
        )
    elif local == State.DENIED:
        notes.append(
            "every probed local-forward destination was administratively prohibited — "
            "AllowTcpForwarding is likely 'no' or 'remote', or PermitOpen excludes the probed "
            "destinations (loopback)"
        )

    if gateway == State.ALLOWED:
        notes.append(
            "the server accepted a wildcard remote-forward bind, but with GatewayPorts=no OpenSSH "
            "silently binds loopback instead — confirm public exposure from an external host"
        )

    return ForwardingResult(
        account=account, authenticated=True, local=local, local_probes=local_probes,
        permitopen_restricted=permitopen_restricted, remote=remote, gateway=gateway,
        agent=agent, x11=x11, pty=pty, notes=notes,
    )


__all__ = [
    "State", "LocalProbe", "ForwardingResult", "classify_local", "assess_forwarding",
]
