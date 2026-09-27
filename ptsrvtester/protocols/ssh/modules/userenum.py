"""USERENUM — SSH username enumeration via an authentication timing side-channel.

Answers the question: *does the server respond differently to a valid username
than to an invalid one?* Many SSH daemons take measurably longer to process an
authentication attempt for a real account (the password is actually hashed) than
for an unknown name (CVE-2016-6210 class of leak). Sending a long password
amplifies that difference.

Workflow (see :mod:`..utils.userenum_core` for the pure decision logic):

  * The operator passes a **known-valid** login in ``-u/--user``. The test
    calibrates the timing oracle by comparing that login against several random
    (almost certainly invalid) names. If the valid login is statistically
    separable, username enumeration is possible — that is the finding.
  * If enumeration is possible **and** a candidate list is given in ``-U/--users``,
    every name in the list is then classified against the calibrated boundary and
    the ones that look valid are reported.

Aggressive by design: it makes repeated failed logins, which can trip fail2ban /
rate limiting (that would show up as unreadable timings). It never runs in the
default / ALL sweep (``__RUN_IN_ALL__ = False``) — only when named in ``-ts``.
Probes are deliberately **sequential** (never threaded): concurrency would add
scheduling noise and defeat the timing measurement. A live spinner is shown
while it runs, then erased before the verdict (same mechanism as LOCKOUT/DHEAT).
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
from ptsrvtester.protocols.ssh.utils import ssh_helpers
from ptsrvtester.protocols.ssh.utils.helpers import text_or_file
from ptsrvtester.protocols.ssh.utils.results import VULNS
from ptsrvtester.protocols.ssh.utils.userenum_core import (
    DEFAULT_BASELINE_USERS,
    DEFAULT_SAMPLES,
    DEFAULT_SIGMA,
    run_user_enum,
)

__MODULELABEL__ = "Username enumeration (timing side-channel)"
__MODULECODE__ = "USERENUM"
__ORDER__ = 35
__RUN_IN_ALL__ = False

#: Long password fed to every attempt to amplify the server-side hashing cost of
#: a valid account (the essence of the CVE-2016-6210 timing leak).
_LONG_PASSWORD = "A" * 25000
_CONNECT_TIMEOUT = 8.0
MAX_SAMPLES = 50
MAX_BASELINE_USERS = 25


def _timing_probe(ip: str, port: int, user: str, timeout: float = _CONNECT_TIMEOUT):
    """One password-auth attempt against ``user``; return the auth phase time (s).

    Only the ``auth_password`` phase is timed — the TCP connect and key exchange
    happen first and are excluded — so the measurement isolates the server's
    per-username authentication work. Returns ``None`` when the attempt could not
    be measured (unreachable, no password auth, transport error).
    """
    transport = paramiko.Transport((ip, port))
    transport.banner_timeout = timeout
    try:
        transport.start_client(timeout=timeout)
    except Exception:
        _safe_close(transport)
        return None

    start = time.perf_counter()
    try:
        # fallback=False: measure the password path only, never paramiko's
        # keyboard-interactive fallback (which would add unrelated timing).
        transport.auth_password(user, _LONG_PASSWORD, fallback=False)
        # An unexpected success (this password is bogus) — still a real timing.
        elapsed = time.perf_counter() - start
    except paramiko.BadAuthenticationType:
        # Server does not offer password auth for this request; not measurable.
        _safe_close(transport)
        return None
    except paramiko.AuthenticationException:
        # The normal path: server processed and rejected the attempt.
        elapsed = time.perf_counter() - start
    except (socket.timeout, TimeoutError, paramiko.SSHException, OSError):
        _safe_close(transport)
        return None
    _safe_close(transport)
    return elapsed


def _safe_close(transport) -> None:
    try:
        transport.close()
    except Exception:
        pass


def _random_invalid_names(count: int, avoid: set[str]) -> list[str]:
    """Random usernames that are virtually certain not to exist on the target."""
    names: list[str] = []
    while len(names) < count:
        name = "ptenum_" + secrets.token_hex(6)
        if name not in avoid and name not in names:
            names.append(name)
    return names


class _Progress:
    """Live spinner + phase + elapsed line (same mechanism as the LOCKOUT test)."""

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
                    f"    {next(frames)} Username enumeration {self.ip}:{self.port} "
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


def _clamp(value, lo, hi, default):
    try:
        value = int(value)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, value))


def run(ctx):
    a = ctx.args
    ip, port = ctx.target

    valid_user = a.user if isinstance(a.user, str) else (a.user[0] if a.user else None)
    if not valid_user:
        ctx.out("USERENUM requires -u/--user (a KNOWN-VALID login to calibrate the oracle)",
                "WARNING", indent=4)
        return

    candidates = text_or_file(None, a.users) if getattr(a, "users", None) else []
    candidates = [c.strip() for c in candidates if c and c.strip()]

    samples = _clamp(getattr(a, "enum_samples", DEFAULT_SAMPLES), 3, MAX_SAMPLES, DEFAULT_SAMPLES)
    baseline_n = _clamp(getattr(a, "enum_baseline", DEFAULT_BASELINE_USERS), 2,
                        MAX_BASELINE_USERS, DEFAULT_BASELINE_USERS)
    try:
        sigma = float(getattr(a, "enum_sigma", DEFAULT_SIGMA) or DEFAULT_SIGMA)
    except (TypeError, ValueError):
        sigma = DEFAULT_SIGMA

    ctx.out(
        f"Timing username enumeration against {ip}:{port} — calibrating on known-valid "
        f"login '{valid_user}' vs {baseline_n} random names ({samples} samples each)",
        "WARNING", indent=4,
    )
    ctx.out(
        "This makes repeated failed logins and may trigger fail2ban / rate limiting.",
        "TEXT", indent=4,
    )

    # Password auth is the measured path; warn early if the server does not offer it.
    try:
        methods = ssh_helpers.get_auth_methods(ip, port)
        if methods is not None and "password" not in methods:
            ctx.out(
                f"Server does not advertise password auth (methods: {', '.join(methods)}); "
                "the timing side-channel needs the password path — results will be inconclusive",
                "WARNING", indent=4,
            )
    except Exception:
        methods = None

    invalid_users = _random_invalid_names(baseline_n, avoid={valid_user, *candidates})

    show_progress = not ctx.json and sys.stdout.isatty()
    progress = _Progress(ip, port) if show_progress else None
    spinner = None
    if progress is not None:
        spinner = threading.Thread(target=progress.run, daemon=True)
        spinner.start()

    try:
        result = run_user_enum(
            lambda u: _timing_probe(ip, port, u),
            valid_user=valid_user,
            candidates=candidates,
            invalid_users=invalid_users,
            samples=samples,
            sigma=sigma,
            log=ctx.debug,
            progress=(progress.set if progress is not None else (lambda _p: None)),
        )
    finally:
        if spinner is not None:
            progress.stop()
            spinner.join()

    _render(ctx, result, valid_user, candidates)


def _ms(value):
    return "n/a" if value is None else f"{value * 1000:.1f} ms"


def _render(ctx, result, valid_user, candidates):
    cal = result.calibration

    if not cal.ok:
        ctx.out("Username enumeration: INCONCLUSIVE (could not calibrate the timing oracle)",
                "WARNING", indent=4)
        for n in cal.notes:
            ctx.out(n, "TEXT", indent=8)
        with ctx.results_lock:
            ctx.properties["userEnumStatus"] = "inconclusive"
        return

    gap_ms = abs(cal.gap) * 1000
    ctx.debug(
        f"valid '{valid_user}' median {_ms(cal.valid_center)}; invalid baseline "
        f"{_ms(cal.invalid_center)} (spread {_ms(cal.invalid_spread)}); gap {gap_ms:.1f} ms "
        f"= {cal.observed_sigma:.1f}σ (threshold {cal.sigma:g}σ)"
    )

    if not result.possible:
        ctx.out(
            f"Username enumeration: NOT possible — valid login '{valid_user}' is not "
            f"distinguishable from invalid names (gap {gap_ms:.1f} ms = {cal.observed_sigma:.1f}σ, "
            f"below {cal.sigma:g}σ)",
            "NOTVULN", indent=4,
        )
        for n in cal.notes:
            ctx.out(n, "TEXT", indent=8)
        with ctx.results_lock:
            ctx.properties["userEnumStatus"] = "not-possible"
            ctx.properties["userEnumTimingGapMs"] = round(gap_ms, 1)
        return

    slower = "slower" if cal.direction > 0 else "faster"
    ctx.out(
        f"Username enumeration: POSSIBLE — valid login '{valid_user}' is {gap_ms:.1f} ms "
        f"{slower} than invalid names ({cal.observed_sigma:.1f}σ, threshold {cal.sigma:g}σ)",
        "VULN", indent=4,
    )
    for n in cal.notes:
        ctx.out(n, "TEXT", indent=8)

    with ctx.results_lock:
        ctx.properties["userEnumStatus"] = "possible"
        ctx.properties["userEnumValidUser"] = valid_user
        ctx.properties["userEnumTimingGapMs"] = round(gap_ms, 1)
        ctx.properties["userEnumSigma"] = round(cal.observed_sigma, 1)
        ctx.deferred_vulns.append({
            "vuln_code": VULNS.UserEnum.value,
            "vuln_request": f"known-valid login: {valid_user}\n"
                            f"baseline: {len(cal.invalid_stats)} random names, "
                            f"{cal.valid_stat.attempted} samples each",
            "vuln_response": f"valid login responds {gap_ms:.1f} ms {slower} than invalid "
                             f"names ({cal.observed_sigma:.1f}σ) — usernames can be enumerated "
                             "by timing",
        })

    if not candidates:
        ctx.out("Provide -U/--users <wordlist> to enumerate usernames from a list.",
                "TEXT", indent=8)
        return

    # Enumerate the supplied list against the calibrated boundary.
    if result.found:
        ctx.out(f"{len(result.found)} of {len(candidates)} names look VALID:", "INFO",
                colortext=True, indent=4)
        for name in result.found:
            median = next((m for n, m, v in result.candidates if n == name), None)
            ctx.out(f"{name}  ({_ms(median)})", "VULN", indent=8)
    else:
        ctx.out(f"No names in the -U list of {len(candidates)} looked valid.",
                "NOTVULN", indent=4)

    unmeasured = [n for n, m, v in result.candidates if v is None]
    if unmeasured:
        ctx.out(f"{len(unmeasured)} name(s) could not be measured: {', '.join(unmeasured[:10])}"
                + (" …" if len(unmeasured) > 10 else ""), "TEXT", indent=8)

    with ctx.results_lock:
        ctx.properties["userEnumFound"] = list(result.found)
        ctx.properties["userEnumCandidates"] = len(candidates)
        if result.found:
            ctx.deferred_vulns.append({
                "vuln_code": VULNS.UserEnum.value,
                "vuln_request": f"candidate list: {len(candidates)} names (-U)",
                "vuln_response": "enumerated valid usernames: " + ", ".join(result.found),
            })
