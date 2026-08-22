"""LOCKOUT — brute-force protection test (account lockout & IP blocking).

Answers the two questions:

  * Does guessing passwords lock the target user ACCOUNT?
    (needs -u <user> and -p <VALID password of a canary account>)
  * Does guessing passwords block the attacker's IP? (fail2ban / firewall)
    (needs only -u <user>)

Aggressive and destructive by design: it deliberately makes failed logins, which
may lock the account and/or ban this host's IP. It never runs in the default /
ALL sweep (``__RUN_IN_ALL__ = False``) — only when explicitly selected with
``-ts LOCKOUT``. While it runs, a live spinner (phase + elapsed) is shown, then
erased before the verdict is printed (same mechanism as the DHEAT test).
"""
import itertools
import secrets
import socket
import sys
import threading
import time

import paramiko
import paramiko.ssh_exception
from ptlibs.ptprinthelper import ptprint, clear_line

# Importing ssh_helpers applies paramiko's legacy-host-key + logging setup as a
# side effect (so old servers still negotiate and paramiko does not spam stderr).
from ptsrvtester.protocols.ssh.utils import ssh_helpers  # noqa: F401
from ptsrvtester.protocols.ssh.utils.helpers import text_or_file
from ptsrvtester.protocols.ssh.utils.lockout_core import (
    Outcome,
    run_lockout_check,
)
from ptsrvtester.protocols.ssh.utils.results import VULNS

__MODULELABEL__ = "Brute-force lockout (account & IP)"
__MODULECODE__ = "LOCKOUT"
__ORDER__ = 75
__RUN_IN_ALL__ = False

MAX_ATTEMPTS = 100
_ATTEMPT_TIMEOUT = 6.0


def _classify_attempt(ip: str, port: int, user: str, password: str, timeout: float = _ATTEMPT_TIMEOUT) -> Outcome:
    """One password auth attempt, classified into a lockout :class:`Outcome`."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy)
    try:
        ssh.connect(
            ip, port,
            username=user,
            password=password,
            look_for_keys=False,
            allow_agent=False,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
        )
        return Outcome.ACCEPTED
    except paramiko.AuthenticationException:
        # Covers BadAuthenticationType / PartialAuthentication too: the server
        # processed the auth and refused it — a normal failure, not a block.
        return Outcome.REJECTED
    except paramiko.ssh_exception.NoValidConnectionsError:
        return Outcome.REFUSED
    except ConnectionRefusedError:
        return Outcome.REFUSED
    except ConnectionResetError:
        return Outcome.RESET
    except (socket.timeout, TimeoutError):
        return Outcome.TIMEOUT
    except paramiko.SSHException as e:
        # fail2ban DROP shows up as a banner-read timeout; treat timeout-like
        # transport failures as a network block signal, anything else as error.
        msg = str(e).lower()
        if "banner" in msg or "timed out" in msg or "timeout" in msg:
            return Outcome.TIMEOUT
        return Outcome.ERROR
    except OSError:
        return Outcome.ERROR
    finally:
        try:
            ssh.close()
        except Exception:
            pass


def _wrong_password() -> str:
    """A password that is virtually certain to be wrong."""
    return "PT_lockout_" + secrets.token_urlsafe(18)


class _Progress:
    """Live spinner + phase + elapsed line (same mechanism as the DHEAT test)."""

    def __init__(self, ip: str, port: int) -> None:
        self.ip, self.port = ip, port
        self._phase = "starting…"
        self._start = time.time()
        self._lock = threading.Lock()
        self._stop = threading.Event()

    def set(self, phase: str) -> None:
        with self._lock:
            self._phase = phase

    def _current(self) -> str:
        with self._lock:
            return self._phase

    def run(self) -> None:
        frames = itertools.cycle("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
        sys.stdout.write("\033[?25l")
        sys.stdout.flush()
        try:
            while not self._stop.is_set():
                elapsed = time.time() - self._start
                ptprint(
                    f"    {next(frames)} Brute-force lockout {self.ip}:{self.port} "
                    f"— {self._current()} ({elapsed:0.0f}s)",
                    "TEXT", end="\r", flush=True, clear_to_eol=True, colortext="TITLE",
                )
                time.sleep(0.1)
        finally:
            clear_line(end="\r")
            sys.stdout.write("\033[?25h")
            sys.stdout.flush()

    def stop(self) -> None:
        self._stop.set()


def _first_user(a) -> str | None:
    """Single -u username, else the first line of a -U users file."""
    if a.user:
        return a.user if isinstance(a.user, str) else (a.user[0] if a.user else None)
    if a.users:
        names = text_or_file(None, a.users)
        return names[0] if names else None
    return None


def run(ctx):
    a = ctx.args
    ip, port = ctx.target

    user = _first_user(a)
    if not user:
        ctx.out("LOCKOUT requires -u/--user (target account)", "WARNING", indent=4)
        return

    valid_password = a.password or None
    attempts = getattr(a, "lockout_attempts", 8) or 8
    attempts = max(1, min(MAX_ATTEMPTS, int(attempts)))
    cooldown = float(getattr(a, "lockout_cooldown", 0.0) or 0.0)

    ctx.out(
        f"Testing brute-force lockout against {ip}:{port} as user '{user}' "
        f"({attempts} failed attempts) — this may lock the account and/or ban this IP",
        "WARNING", indent=4,
    )
    if valid_password is None:
        ctx.out(
            "No -p/--password given: only IP-blocking is tested. Add -p <valid password "
            "of a canary account> to also test account lockout.",
            "TEXT", indent=4,
        )

    # Heads-up if the server does not offer password auth (failed passwords may
    # not register the way the test assumes).
    try:
        methods = ssh_helpers.get_auth_methods(ip, port)
        if methods is not None and "password" not in methods and "keyboard-interactive" not in methods:
            ctx.out(
                f"Note: server does not advertise password auth (methods: {', '.join(methods)}); "
                "results may be limited",
                "TEXT", indent=4,
            )
    except Exception:
        pass

    show_progress = not ctx.json and sys.stdout.isatty()
    progress = _Progress(ip, port) if show_progress else None
    spinner = None
    if progress is not None:
        spinner = threading.Thread(target=progress.run, daemon=True)
        spinner.start()

    try:
        result = run_lockout_check(
            lambda u, p: _classify_attempt(ip, port, u, p),
            user=user,
            valid_password=valid_password,
            attempts=attempts,
            wrong_password=_wrong_password,
            cooldown_seconds=cooldown,
            log=ctx.debug,
            progress=(progress.set if progress is not None else (lambda _p: None)),
        )
    finally:
        if spinner is not None:
            progress.stop()
            spinner.join()

    _render(ctx, result, user)


def _render(ctx, r, user):
    if not r.baseline_ok:
        ctx.out("Lockout test inconclusive", "WARNING", indent=4)
        for n in r.notes:
            ctx.out(n, "TEXT", indent=8)
        with ctx.results_lock:
            ctx.properties["lockoutStatus"] = "inconclusive"
        return

    ctx.debug(f"attempts made: {r.attempts_made}; outcomes: "
              + ", ".join(o.value for o in r.outcomes))

    # --- Account lockout ---
    if r.account_tested:
        if r.account_lockout_detected:
            after = r.attempts_made
            ctx.out(f"Account lockout: ENFORCED (account '{user}' locked after ~{after} "
                    "failed attempts)", "OK", indent=4)
        else:
            ctx.out(f"Account lockout: NOT enforced (account '{user}' still authenticated "
                    f"after {r.attempts_made} failed attempts)", "VULN", indent=4)
    elif r.valid_baseline_ok is None:
        ctx.out("Account lockout: not tested (no -p/--password supplied)", "TEXT", indent=4)
    else:
        ctx.out("Account lockout: could not be determined", "WARNING", indent=4)

    # --- IP blocking ---
    if r.ip_block_detected is True:
        after = r.ip_block_after or r.attempts_made
        ctx.out(f"IP blocking: ENFORCED (this IP was blocked after ~{after} failed attempts)",
                "OK", indent=4)
    elif r.ip_block_detected is False:
        ctx.out(f"IP blocking: NOT enforced (this IP was still served after "
                f"{r.attempts_made} failed attempts)", "VULN", indent=4)
    else:
        ctx.out("IP blocking: could not be determined", "WARNING", indent=4)

    if r.recovery_probed:
        if r.recovered is True:
            ctx.out(f"Recovery: access restored after the {ctx.args.lockout_cooldown:g}s wait",
                    "TEXT", indent=8)
        elif r.recovered is False:
            ctx.out(f"Recovery: still blocked/locked after the {ctx.args.lockout_cooldown:g}s wait",
                    "TEXT", indent=8)

    for n in r.notes:
        ctx.out(n, "TEXT", indent=8)

    # --- JSON node properties + vulns (absence of protection is the finding) ---
    with ctx.results_lock:
        ctx.properties["lockoutStatus"] = "tested"
        ctx.properties["lockoutAttempts"] = r.attempts_made
        if r.account_tested:
            ctx.properties["accountLockout"] = bool(r.account_lockout_detected)
        ctx.properties["ipBlocking"] = (
            None if r.ip_block_detected is None else bool(r.ip_block_detected)
        )
        if r.ip_block_after is not None:
            ctx.properties["ipBlockAfterAttempts"] = r.ip_block_after

        if r.account_tested and r.account_lockout_detected is False:
            ctx.deferred_vulns.append({
                "vuln_code": VULNS.NoAccountLockout.value,
                "vuln_request": f"user: {user}\n{r.attempts_made} failed SSH logins",
                "vuln_response": f"account '{user}' still authenticated with the valid "
                                 "password after the failed attempts (no account lockout)",
            })
        if r.ip_block_detected is False:
            ctx.deferred_vulns.append({
                "vuln_code": VULNS.NoIpBlocking.value,
                "vuln_request": f"{r.attempts_made} failed SSH logins from this IP",
                "vuln_response": "the server kept serving this IP after the failed attempts "
                                 "(no fail2ban-style IP blocking)",
            })