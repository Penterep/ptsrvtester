"""Protocol-agnostic core for the SSH "is root login permitted?" test.

Contains no paramiko / socket code: the decision logic is fed the observations
(the auth methods the server advertises for the root account, the methods it
advertises for an ordinary name, and — if credentials were supplied — whether a
real root login succeeded) so it can be unit-tested without a live server. The
module (:mod:`..modules.rootlogin`) collects those observations over paramiko.

Remote limitation (reflected in the verdicts): without valid root credentials a
server cannot be *proven* to reject root — OpenSSH enforces ``PermitRootLogin``
only at the moment authentication would otherwise succeed, not when it advertises
methods. So the test reports what is observable:

  * ``confirmed``          — a real root login succeeded (definitive).
  * ``password-permitted`` — root may authenticate with a password/keyboard-
                             interactive (the classic hardening finding: root
                             password login should be off). A finding.
  * ``key-only``           — root is offered only non-password methods (public
                             key / gssapi); consistent with ``prohibit-password``.
  * ``disabled``           — the server offered root no usable auth method.
  * ``unknown``            — methods could not be read.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

#: Auth methods that mean "a secret the attacker can guess" for root.
PASSWORD_METHODS = frozenset({"password", "keyboard-interactive"})


@dataclass
class RootLoginResult:
    account: str
    root_methods: Optional[list[str]]
    baseline_methods: Optional[list[str]]
    root_reachable: bool                 # got a methods answer for the root account
    password_enabled: Optional[bool]     # password/kbd-int offered to root
    password_restricted: Optional[bool]  # baseline has password but root does not
    login_attempted: bool
    login_succeeded: Optional[bool]
    verdict: str
    notes: list[str] = field(default_factory=list)

    @property
    def is_finding(self) -> bool:
        """True when the result is a reportable weakness (root reachable by secret)."""
        return self.verdict in ("confirmed", "password-permitted")


def _has_password(methods: Optional[list[str]]) -> bool:
    return methods is not None and any(m.lower() in PASSWORD_METHODS for m in methods)


def assess_root_login(
    *,
    account: str,
    root_methods: Optional[list[str]],
    baseline_methods: Optional[list[str]],
    login_succeeded: Optional[bool],
    login_attempted: bool = False,
) -> RootLoginResult:
    """Turn the raw observations into a verdict (see module docstring)."""
    notes: list[str] = []

    root_reachable = root_methods is not None
    root_pw = _has_password(root_methods)
    base_pw = _has_password(baseline_methods)

    password_enabled = root_pw if root_methods is not None else None
    if root_methods is not None and baseline_methods is not None:
        password_restricted = base_pw and not root_pw
    else:
        password_restricted = None

    if login_succeeded is True:
        verdict = "confirmed"
        notes.append(f"root login CONFIRMED — authenticated as '{account}' with the supplied credentials")
    elif root_methods is None:
        verdict = "unknown"
        notes.append("could not read the authentication methods offered to root")
    elif len(root_methods) == 0:
        verdict = "disabled"
        notes.append("server offered root no authentication method")
    elif root_pw:
        verdict = "password-permitted"
        if login_attempted and login_succeeded is False:
            notes.append("supplied credentials did not authenticate root (wrong secret, or "
                         "PermitRootLogin blocks it); password path is still advertised for root")
    else:
        verdict = "key-only"
        if password_restricted:
            notes.append("root is offered only non-password methods while ordinary names are "
                         "offered a password — consistent with PermitRootLogin prohibit-password")
        else:
            notes.append("root is offered only non-password methods (public key / gssapi)")

    if verdict != "confirmed":
        notes.append("note: without valid root credentials, PermitRootLogin no vs yes cannot be "
                     "distinguished remotely — this reflects only what the server advertises")

    return RootLoginResult(
        account=account,
        root_methods=root_methods,
        baseline_methods=baseline_methods,
        root_reachable=root_reachable,
        password_enabled=password_enabled,
        password_restricted=password_restricted,
        login_attempted=login_attempted,
        login_succeeded=login_succeeded,
        verdict=verdict,
        notes=notes,
    )


__all__ = ["PASSWORD_METHODS", "RootLoginResult", "assess_root_login"]
