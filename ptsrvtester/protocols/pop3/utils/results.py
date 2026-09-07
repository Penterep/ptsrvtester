"""POP3 result types and vulnerability codes."""
from __future__ import annotations

from enum import Enum
from typing import NamedTuple

from .helpers import Creds
from .ptntlmauth.ptntlmauth import NTLMInfo


class NTLMResult(NamedTuple):
    success: bool
    ntlm: NTLMInfo | None


class InfoResult(NamedTuple):
    banner: str | None
    capability: dict[str, list[str]] | None
    capability_stls: dict[str, list[str]] | None = None


class HelpInfoResult(NamedTuple):
    """HELP (non-standard) + IMPLEMENTATION from CAPA (RFC 2449)."""
    help_response: str | None
    implementation: str | None


class EncryptionResult(NamedTuple):
    plaintext_ok: bool
    stls_ok: bool
    tls_ok: bool


CatchAllResult = str  # "not_configured" | "indeterminate"


# ─── NOOP Connection Limit Tests ──────────────────────────────────────────────
# POP3 RFC 1939: 10-minute minimum auto-logout timer (if implemented).
# Pre-auth limits should be stricter than post-auth for DoS protection.

# Pre-authentication duration test (NOOPLIM1)
POP3_NOOP_PREAUTH_DUR_TEST_SECONDS = 35 * 60  # Test for 35 minutes (captures "high" threshold)
POP3_NOOP_PREAUTH_DUR_INTERVAL_SECONDS = 4 * 60  # Send NOOP every 4 minutes (RFC 1939: 10min minimum timeout)
POP3_NOOP_PREAUTH_DUR_TIMEOUT_SECONDS = 30    # Socket recv timeout

# Pre-authentication duration thresholds (in seconds)
POP3_NOOP_PREAUTH_DUR_INCREASED_MIN = 5 * 60   # >5 min → increased
POP3_NOOP_PREAUTH_DUR_SIGNIFICANT_MIN = 15 * 60 # >15 min → significant
POP3_NOOP_PREAUTH_DUR_HIGH_MIN = 30 * 60       # >30 min → high

# NOOP1 timing (SMTP-compatible verdicts)
NOOP1_SLOWDOWN_MIN_RATIO = 1.5
NOOP1_SLOWDOWN_MIN_SECONDS = 0.5
NOOP1_ERROR_RATE_OK_MAX_PCT = 5.0
NOOP2_AVG_TIME_OK_MAX_SECONDS = 5.0
NOOP2_ERROR_RATE_OK_MAX_PCT = 5.0


def noop2_count_from_args(args, default: int, cap: int | None = None) -> int:
    n = getattr(args, "noop2_count", None)
    if n is None:
        n = getattr(args, "noop2_connections", None)
    if n is None:
        n = default
    n = int(n)
    if cap is not None:
        n = min(n, cap)
    return max(1, n)


NOOP1_RT_WINDOW = 10
NOOP1_PROGRESS_EVERY = 25  # live progress + -vv snapshot interval (commands)

# Pre-authentication connection count test (NOOPLIM2)
POP3_NOOP_PREAUTH_CONN_TEST_SECONDS = 120      # Hold connections for 2 minutes
POP3_NOOP_PREAUTH_CONN_INTERVAL_SECONDS = 60   # Send NOOP every minute (short interval for connection count test)
POP3_NOOP_PREAUTH_CONN_TIMEOUT_SECONDS = 30
POP3_NOOP_PREAUTH_CONN_MAX_ATTEMPTS = 150      # Try up to 150 connections (safety cap)

# CLI default for --count
NOOP2_DEFAULT_CONNECTIONS = POP3_NOOP_PREAUTH_CONN_MAX_ATTEMPTS

# Pre-authentication connection count thresholds
POP3_NOOP_PREAUTH_CONN_INCREASED_MIN = 20      # >20 connections → increased
POP3_NOOP_PREAUTH_CONN_SIGNIFICANT_MIN = 50    # >50 connections → significant
POP3_NOOP_PREAUTH_CONN_HIGH_MIN = 100          # >100 connections → high

# Post-authentication duration test (NOOPLIM3)
POP3_NOOP_POSTAUTH_DUR_TEST_SECONDS = 70 * 60  # Test for 70 minutes (captures "high" threshold)
POP3_NOOP_POSTAUTH_DUR_INTERVAL_SECONDS = 5 * 60  # Send NOOP every 5 minutes (RFC 1939: 10min minimum timeout)
POP3_NOOP_POSTAUTH_DUR_TIMEOUT_SECONDS = 30

# Post-authentication duration thresholds (in seconds)
POP3_NOOP_POSTAUTH_DUR_INCREASED_MIN = 30 * 60  # >30 min → increased
POP3_NOOP_POSTAUTH_DUR_SIGNIFICANT_MIN = 60 * 60 # >60 min → significant
POP3_NOOP_POSTAUTH_DUR_HIGH_MIN = 120 * 60      # >120 min (unlimited) → high

# Post-authentication connection count test (NOOPLIM4)
POP3_NOOP_POSTAUTH_CONN_TEST_SECONDS = 180
POP3_NOOP_POSTAUTH_CONN_INTERVAL_SECONDS = 60  # Send NOOP every minute (short interval for connection count test)
POP3_NOOP_POSTAUTH_CONN_TIMEOUT_SECONDS = 30
POP3_NOOP_POSTAUTH_CONN_MAX_ATTEMPTS = 600     # Try up to 600 connections (safety cap)

# Post-authentication connection count thresholds (per IP)
POP3_NOOP_POSTAUTH_CONN_IP_INCREASED_MIN = 50
POP3_NOOP_POSTAUTH_CONN_IP_SIGNIFICANT_MIN = 100
POP3_NOOP_POSTAUTH_CONN_IP_HIGH_MIN = 500

# Post-authentication connection count thresholds (per account)
POP3_NOOP_POSTAUTH_CONN_ACCT_INCREASED_MIN = 20
POP3_NOOP_POSTAUTH_CONN_ACCT_SIGNIFICANT_MIN = 50
POP3_NOOP_POSTAUTH_CONN_ACCT_HIGH_MIN = 100


class NoopDurationResult(NamedTuple):
    """NOOP connection duration test: keep one connection alive with periodic NOOP."""
    authenticated: bool                # Pre-auth (False) or post-auth (True)
    test_duration_seconds: float       # How long the test was configured to run
    maintained_seconds: float          # How long the connection actually stayed alive
    noops_sent: int                    # Number of NOOPs successfully sent
    noops_ok: int                      # Number of +OK replies
    noops_error: int                   # Number of -ERR or timeout/socket errors
    disconnected: bool                 # True if server closed the connection
    disconnect_after_seconds: float | None  # When the disconnect happened
    hit_test_cap: bool                 # True if we reached the test duration limit
    error_message: str | None          # Error detail if test failed to start
    delay_seconds: float = 0.0         # Configured wait between NOOPs (0 = max speed)
    min_rt_seconds: float | None = None
    max_rt_seconds: float | None = None
    avg_rt_seconds: float | None = None
    baseline_avg_seconds: float | None = None
    last_window_avg_seconds: float | None = None
    slowdown_detected: bool = False
    error_rate_pct: float = 0.0
    idle_disconnect: bool = False      # Closed while waiting, not during a NOOP


def noop1_rt_display(value: float | None) -> str:
    """Format a round-trip time as ``Xs`` / ``X.Ys`` (same as SMTP)."""
    if value is None:
        return "N/A"
    if value >= 10:
        return f"{int(round(value))}s"
    if value >= 1:
        return f"{value:.1f}s"
    return f"{value:.2f}s"


def noop1_stats_from_rtts(rtts: list[float], commands_sent: int, commands_error: int) -> dict:
    """Baseline / last-window slowdown and error rate (SMTP NOOP1 rules)."""
    min_rt = min(rtts) if rtts else None
    max_rt = max(rtts) if rtts else None
    avg_rt = (sum(rtts) / len(rtts)) if rtts else None
    window = NOOP1_RT_WINDOW
    baseline_avg = (sum(rtts[:window]) / min(len(rtts), window)) if rtts else None
    last_rtts = rtts[-window:] if rtts else []
    last_window_avg = (sum(last_rtts) / len(last_rtts)) if last_rtts else None
    slowdown = False
    if baseline_avg is not None and last_window_avg is not None and len(rtts) >= window * 2:
        slowdown = (
            last_window_avg >= baseline_avg * NOOP1_SLOWDOWN_MIN_RATIO
            or last_window_avg >= NOOP1_SLOWDOWN_MIN_SECONDS
        )
    error_rate = (100.0 * commands_error / commands_sent) if commands_sent else 0.0
    return {
        "min_rt_seconds": min_rt,
        "max_rt_seconds": max_rt,
        "avg_rt_seconds": avg_rt,
        "baseline_avg_seconds": baseline_avg,
        "last_window_avg_seconds": last_window_avg,
        "slowdown_detected": slowdown,
        "error_rate_pct": error_rate,
    }


class NoopConnectionCountResult(NamedTuple):
    """NOOP connection count test: how many connections can be maintained with NOOP."""
    authenticated: bool                # Pre-auth (False) or post-auth (True)
    max_connections_attempted: int     # How many connections we tried to open
    connections_established: int       # How many got past the greeting
    connections_maintained: int        # How many stayed alive for the test duration
    test_duration_seconds: float       # How long we held the connections
    total_noops_sent: int              # Total NOOPs across all connections
    total_noops_ok: int
    total_noops_error: int
    early_disconnect_count: int        # Connections that died during the test
    error_message: str | None
    establish_errors: int = 0
    establish_disconnected: int = 0
    establish_timeouts: int = 0
    reaped_before_storm: int = 0
    storm_pool_connections: int = 0
    min_rt_seconds: float | None = None
    max_rt_seconds: float | None = None
    avg_rt_seconds: float | None = None
    error_rate_pct: float = 0.0
    early_exit_no_connections: bool = False
    terminated_connections: tuple[tuple[int, str, str], ...] = ()
    delay_seconds: float = 0.0


class VULNS(Enum):
    Anonymous = "PTV-GENERAL-ANONYMOUS"
    NTLM = "PTV-GENERAL-NTLMINFO"
    WeakCreds = "PTV-GENERAL-WEAKCREDENTIALS"
    Banner = "PTV-SVC-BANNER"
    NoopDurationPreauth = "PTV-SVC-POP3-NOOPLIMDUR-PREAUTH"
    NoopDurationPostauth = "PTV-SVC-POP3-NOOPLIMDUR-POSTAUTH"
    NoopConnCountPreauth = "PTV-SVC-POP3-NOOPLIMCONN-PREAUTH"
    NoopConnCountPostauth = "PTV-SVC-POP3-NOOPLIMCONN-POSTAUTH"
