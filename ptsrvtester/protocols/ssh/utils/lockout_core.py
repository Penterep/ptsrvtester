"""Protocol-agnostic core for the SSH brute-force lockout test.

Contains no paramiko / socket code: it is driven by an injected
``attempt(user, password) -> Outcome`` callback so the decision logic can be
unit-tested without a live SSH server. The module (:mod:`..modules.lockout`)
supplies the real paramiko-based attempt function.

It answers two questions a pentester asks about password guessing:

* **Account lockout** — after several wrong passwords, does the *account* stop
  authenticating even with the correct password? (needs a valid canary password)
* **IP blocking** — after several failed logins, does the server stop answering
  *this source IP* (fail2ban / firewall drop)? (no valid password needed)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional


class Outcome(str, Enum):
    """Classified result of a single authentication attempt."""

    ACCEPTED = "accepted"      # login succeeded (valid credentials)
    REJECTED = "rejected"      # server processed auth and refused (normal failure)
    REFUSED = "refused"        # TCP refused (RST) — network-level block
    TIMEOUT = "timeout"        # no answer in time — network-level block (drop)
    RESET = "reset"            # connection reset mid-handshake — network-level block
    ERROR = "error"            # other/unclassified error

    @property
    def blocked(self) -> bool:
        """Network-level block signals (as opposed to a normal auth rejection)."""
        return self in (Outcome.REFUSED, Outcome.TIMEOUT, Outcome.RESET)


AttemptFn = Callable[[str, str], Outcome]          # (user, password) -> Outcome
WrongPasswordFn = Callable[[], str]                # produce a fresh wrong password
Logger = Callable[[str], None]
Progress = Callable[[str], None]


@dataclass
class LockoutResult:
    baseline_ok: bool
    attempts_made: int
    outcomes: list[Outcome] = field(default_factory=list)

    # IP blocking
    ip_block_detected: Optional[bool] = None       # None = could not determine
    ip_block_after: Optional[int] = None           # attempt # at which blocking began

    # Account lockout
    account_tested: bool = False                    # had a valid password + isolated result
    account_lockout_detected: Optional[bool] = None
    valid_baseline_ok: Optional[bool] = None        # did the valid password work before the burst

    # recovery (optional)
    recovery_probed: bool = False
    recovered: Optional[bool] = None

    notes: list[str] = field(default_factory=list)


def run_lockout_check(
    attempt: AttemptFn,
    *,
    user: str,
    valid_password: Optional[str],
    attempts: int,
    wrong_password: WrongPasswordFn,
    post_probes: int = 2,
    cooldown_seconds: float = 0.0,
    baseline_probes: int = 1,
    log: Logger = lambda _m: None,
    progress: Progress = lambda _p: None,
    sleeper: Callable[[float], None] = None,
) -> LockoutResult:
    """Drive the lockout assessment through ``attempt`` (see module docstring)."""
    import time as _time

    sleep = sleeper or _time.sleep
    notes: list[str] = []
    outcomes: list[Outcome] = []

    # (A) Valid-password baseline (only if we were given one to test account lockout).
    valid_baseline_ok: Optional[bool] = None
    if valid_password is not None:
        progress("verifying the account's valid password")
        log("baseline: trying the supplied valid password")
        o = attempt(user, valid_password)
        if o is Outcome.ACCEPTED:
            valid_baseline_ok = True
        elif o.blocked:
            valid_baseline_ok = False
            notes.append("valid-password baseline was blocked at the network level; "
                         "account-lockout cannot be isolated")
        else:
            valid_baseline_ok = False
            notes.append("the supplied password did not authenticate before the burst; "
                         "account-lockout result would be unreliable, so it is skipped")

    # (B) Connectivity baseline: one wrong password should be a normal REJECTED.
    progress("baseline connectivity")
    log("baseline: one wrong-password attempt")
    b = attempt(user, wrong_password())
    baseline_ok = not b.blocked
    if not baseline_ok:
        notes.append("baseline connection was already blocked/unreachable; cannot assess lockout")
        return LockoutResult(
            baseline_ok=False, attempts_made=0, outcomes=outcomes,
            valid_baseline_ok=valid_baseline_ok, notes=notes,
        )

    # (C) Burst of failed logins.
    ip_block_after: Optional[int] = None
    made = 0
    for i in range(1, max(1, attempts) + 1):
        progress(f"failed login attempts ({i}/{attempts})")
        o = attempt(user, wrong_password())
        outcomes.append(o)
        made = i
        log(f"attempt {i}/{attempts}: {o.value}")
        if o.blocked:
            ip_block_after = i
            break

    # (D) IP-block verdict: blocked mid-burst, or blocked on post-burst probes.
    if ip_block_after is not None:
        ip_block_detected: Optional[bool] = True
    else:
        progress("re-checking connectivity after the burst")
        blocked = 0
        for _ in range(max(1, post_probes)):
            o = attempt(user, wrong_password())
            if o.blocked:
                blocked += 1
        ip_block_detected = blocked > 0
        if ip_block_detected:
            ip_block_after = made  # first observed right after the burst

    # (E) Account-lockout re-test: only meaningful with a working valid baseline and
    #     when the IP itself is not blocked (otherwise we cannot isolate the cause).
    account_tested = False
    account_lockout_detected: Optional[bool] = None
    if valid_password is not None and valid_baseline_ok:
        progress("re-testing the valid password after failures")
        log("re-test: trying the valid password again")
        o = attempt(user, valid_password)
        if o.blocked:
            notes.append("valid-password re-test was blocked at the network level (IP block); "
                         "account lockout could not be isolated")
        else:
            account_tested = True
            account_lockout_detected = o is not Outcome.ACCEPTED

    result = LockoutResult(
        baseline_ok=True,
        attempts_made=made,
        outcomes=outcomes,
        ip_block_detected=ip_block_detected,
        ip_block_after=ip_block_after,
        account_tested=account_tested,
        account_lockout_detected=account_lockout_detected,
        valid_baseline_ok=valid_baseline_ok,
        notes=notes,
    )

    # (F) Optional recovery probe: does a detected block/lockout clear after a wait?
    if cooldown_seconds > 0 and (ip_block_detected or account_lockout_detected):
        progress(f"waiting {cooldown_seconds:g}s to check recovery")
        log(f"recovery: waiting {cooldown_seconds:g}s then re-probing")
        try:
            sleep(cooldown_seconds)
        except Exception:
            pass
        result.recovery_probed = True
        if account_tested and account_lockout_detected and valid_password is not None:
            o = attempt(user, valid_password)
            result.recovered = o is Outcome.ACCEPTED
        else:
            o = attempt(user, wrong_password())
            result.recovered = not o.blocked

    return result


__all__ = ["Outcome", "LockoutResult", "run_lockout_check", "AttemptFn"]