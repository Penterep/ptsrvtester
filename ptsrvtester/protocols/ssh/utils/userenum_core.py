"""Protocol-agnostic core for the SSH user-enumeration (timing side-channel) test.

Contains no paramiko / socket code: it is driven by an injected
``probe(user) -> float | None`` callback that returns **one** timing sample (in
seconds) for a single authentication attempt against ``user`` (or ``None`` when
that probe could not be measured). The module (:mod:`..modules.userenum`)
supplies the real paramiko-based probe; the tests supply a fake one, so the
decision logic can be unit-tested without a live SSH server.

Idea (CVE-2016-6210 class of leak): many SSH servers spend measurably more time
processing an authentication request for a **valid** username — the password is
actually hashed against the account's stored hash — than for an unknown one,
which is rejected early. Feeding a long password amplifies the gap.

Because raw timings are noisy (network RTT, scheduling jitter) we do not trust a
single number. The test:

  1. **Calibrates** the oracle on a *known-valid* login (passed by the operator
     in ``-u``) against several synthetic random names that are almost certainly
     invalid, and decides whether the valid login is *statistically separable*
     from the invalid baseline. That answer alone tells the operator whether
     user enumeration is possible on this server.
  2. If it is, and a candidate list was given (``-U``), it **classifies** each
     name against the calibrated boundary and reports the ones that look valid.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from statistics import median as _statistics_median
from typing import Callable, Optional

# probe(user) -> one timing sample in seconds, or None if it could not be measured
Probe = Callable[[str], Optional[float]]
Logger = Callable[[str], None]
Progress = Callable[[str], None]

# Defaults (the operator overrides samples / baseline count / sigma from the CLI).
DEFAULT_SAMPLES = 5
DEFAULT_BASELINE_USERS = 5
DEFAULT_SIGMA = 3.0

#: Timing gaps below this (seconds) are treated as measurement noise regardless
#: of how many sigmas they represent — avoids "separable" verdicts on a server
#: whose invalid timings happen to be extremely stable (spread ~ 0).
MIN_ABS_DELTA = 0.010          # 10 ms

#: Floor for the invalid-baseline spread so a near-zero std does not make an
#: arbitrarily tiny gap look like many sigmas.
SPREAD_FLOOR = 0.002           # 2 ms


def _median(xs) -> Optional[float]:
    vals = [x for x in xs if x is not None]
    if not vals:
        return None
    return float(_statistics_median(vals))


def _std(xs) -> float:
    """Sample standard deviation (0.0 for fewer than two values)."""
    vals = [x for x in xs if x is not None]
    n = len(vals)
    if n < 2:
        return 0.0
    mean = sum(vals) / n
    var = sum((x - mean) ** 2 for x in vals) / (n - 1)
    return var ** 0.5


@dataclass
class UserStat:
    """The measured timing profile of one username."""

    name: str
    samples: list[float]
    median: Optional[float]
    ok: int                     # probes that produced a sample
    attempted: int


@dataclass
class Calibration:
    """Outcome of calibrating the oracle on the known-valid login."""

    valid_user: str
    valid_stat: UserStat
    invalid_stats: list[UserStat]
    invalid_center: Optional[float]     # median of the invalid usernames' medians
    invalid_spread: float               # std of the invalid usernames' medians
    valid_center: Optional[float]       # the valid login's median
    gap: Optional[float]                # valid_center - invalid_center
    direction: int                      # +1 valid slower, -1 valid faster
    boundary: Optional[float]           # decision boundary for candidate names
    sigma: float                        # required separation (in std devs)
    observed_sigma: Optional[float]     # |gap| / effective spread
    ok: bool                            # enough data to decide at all
    separable: bool                     # valid login distinguishable => enum possible
    notes: list[str] = field(default_factory=list)


@dataclass
class UserEnumResult:
    calibration: Calibration
    possible: bool
    candidates: list[tuple[str, Optional[float], Optional[bool]]]  # (name, median, is_valid)
    found: list[str]
    notes: list[str] = field(default_factory=list)


def collect(
    probe: Probe,
    user: str,
    samples: int,
    *,
    log: Logger = lambda _m: None,
    progress: Progress = lambda _p: None,
) -> UserStat:
    """Probe ``user`` ``samples`` times and summarise it as a :class:`UserStat`."""
    n = max(1, int(samples))
    vals: list[float] = []
    for i in range(n):
        progress(f"probing '{user}' ({i + 1}/{n})")
        v = probe(user)
        if v is not None:
            vals.append(float(v))
        log(f"probe '{user}' {i + 1}/{n}: " + ("no sample" if v is None else f"{v * 1000:.1f} ms"))
    return UserStat(name=user, samples=vals, median=_median(vals), ok=len(vals), attempted=n)


def calibrate(
    probe: Probe,
    valid_user: str,
    invalid_users: list[str],
    *,
    samples: int = DEFAULT_SAMPLES,
    sigma: float = DEFAULT_SIGMA,
    min_abs_delta: float = MIN_ABS_DELTA,
    log: Logger = lambda _m: None,
    progress: Progress = lambda _p: None,
) -> Calibration:
    """Measure the valid login against the invalid baseline and decide separability."""
    notes: list[str] = []

    valid_stat = collect(probe, valid_user, samples, log=log, progress=progress)
    invalid_stats = [
        collect(probe, u, samples, log=log, progress=progress) for u in invalid_users
    ]

    inv_medians = [s.median for s in invalid_stats if s.median is not None]
    valid_center = valid_stat.median

    def _fail(reason: str) -> Calibration:
        notes.append(reason)
        return Calibration(
            valid_user=valid_user, valid_stat=valid_stat, invalid_stats=invalid_stats,
            invalid_center=_median(inv_medians), invalid_spread=_std(inv_medians),
            valid_center=valid_center, gap=None, direction=1, boundary=None,
            sigma=sigma, observed_sigma=None, ok=False, separable=False, notes=notes,
        )

    if valid_center is None:
        return _fail("could not measure the valid login's timing (no successful probes)")
    if len(inv_medians) < 2:
        return _fail("not enough invalid-baseline samples to establish a timing baseline")

    invalid_center = _median(inv_medians)
    invalid_spread = _std(inv_medians)
    spread_eff = max(invalid_spread, SPREAD_FLOOR)

    gap = valid_center - invalid_center
    direction = 1 if gap >= 0 else -1
    abs_gap = abs(gap)
    observed_sigma = abs_gap / spread_eff
    boundary = invalid_center + direction * abs_gap / 2

    separable = (observed_sigma >= sigma) and (abs_gap >= min_abs_delta)
    if separable and direction < 0:
        notes.append("valid login was faster than the invalid baseline (unusual, but the "
                     "signal is consistent) — enumeration still possible")

    return Calibration(
        valid_user=valid_user, valid_stat=valid_stat, invalid_stats=invalid_stats,
        invalid_center=invalid_center, invalid_spread=invalid_spread,
        valid_center=valid_center, gap=gap, direction=direction, boundary=boundary,
        sigma=sigma, observed_sigma=observed_sigma, ok=True, separable=separable, notes=notes,
    )


def classify(stat: UserStat, cal: Calibration) -> Optional[bool]:
    """True if ``stat`` looks like a valid user against the calibrated boundary."""
    if stat.median is None or cal.gap is None or not cal.separable:
        return None
    return (stat.median - cal.invalid_center) * cal.direction >= abs(cal.gap) / 2


def enumerate_candidates(
    probe: Probe,
    cal: Calibration,
    candidates: list[str],
    *,
    samples: int = DEFAULT_SAMPLES,
    log: Logger = lambda _m: None,
    progress: Progress = lambda _p: None,
) -> list[tuple[str, Optional[float], Optional[bool]]]:
    """Classify each candidate name against the calibrated oracle."""
    out: list[tuple[str, Optional[float], Optional[bool]]] = []
    for name in candidates:
        stat = collect(probe, name, samples, log=log, progress=progress)
        out.append((name, stat.median, classify(stat, cal)))
    return out


def run_user_enum(
    probe: Probe,
    *,
    valid_user: str,
    candidates: list[str],
    invalid_users: list[str],
    samples: int = DEFAULT_SAMPLES,
    sigma: float = DEFAULT_SIGMA,
    min_abs_delta: float = MIN_ABS_DELTA,
    log: Logger = lambda _m: None,
    progress: Progress = lambda _p: None,
) -> UserEnumResult:
    """Full assessment: calibrate on ``valid_user``, then enumerate ``candidates``.

    ``candidates`` is only enumerated when calibration says enumeration is
    possible; otherwise the returned lists are empty and ``possible`` is False.
    """
    cal = calibrate(
        probe, valid_user, invalid_users,
        samples=samples, sigma=sigma, min_abs_delta=min_abs_delta,
        log=log, progress=progress,
    )
    possible = cal.separable
    cand_results: list[tuple[str, Optional[float], Optional[bool]]] = []
    found: list[str] = []
    if possible and candidates:
        progress("enumerating candidate usernames")
        cand_results = enumerate_candidates(
            probe, cal, candidates, samples=samples, log=log, progress=progress
        )
        found = [name for name, _median_val, is_valid in cand_results if is_valid]
    return UserEnumResult(
        calibration=cal, possible=possible, candidates=cand_results,
        found=found, notes=list(cal.notes),
    )


__all__ = [
    "Probe", "UserStat", "Calibration", "UserEnumResult",
    "collect", "calibrate", "classify", "enumerate_candidates", "run_user_enum",
    "DEFAULT_SAMPLES", "DEFAULT_BASELINE_USERS", "DEFAULT_SIGMA", "MIN_ABS_DELTA",
]
