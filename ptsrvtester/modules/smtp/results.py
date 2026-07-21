import re, socket
from dataclasses import dataclass
from enum import Enum
from typing import NamedTuple

from ...ptntlmauth.ptntlmauth import NTLMInfo

try:
    from ntlm_auth.ntlm import NtlmContext
except ImportError:
    NtlmContext = None

from ..utils.helpers import Creds

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False


from .helpers import *

__all__ = ['NTLMResult', 'RateLimitResult', 'RCPT_LIMIT_DEFAULT_ATTEMPTS', 'RCPT_LIMIT_POLICY_REJECT_CAP', 'RCPT_LIMIT_VERDICT_OK_MAX', 'RCPT_LIMIT_VERDICT_WARN_MAX', 'RCPT_LIMIT_POSTHIT_PROBE_COUNT', 'RCPT_LIMIT_MIN_RECOMMENDED_NAME_COUNT', 'RCPT_LIMIT_ACCEPT_ALL_PROBE_LOCAL', '_ID_RCPT_ERROR_MAIL_FROM', '_ID_RCPT_ERROR_RCPT', '_RL_TOO_MUCH_MAIL_RE', '_rl_extract_too_much_mail_error', 'DEFAULT_SMTP_SUBJECT', 'DEFAULT_SMTP_DATA', 'AV_CATEGORY_TITLES', 'ALIAS_VARIANT_TITLES', 'SSRF_VARIANT_TITLES', 'SSRF_VARIANT_PAYLOAD_LABELS', 'ZIPXXE_VARIANT_TITLES', 'ZIPXXE_VARIANT_PAYLOAD_LABELS', '_smtp_minimal_probe_data', 'EMAIL_HDR_TEST', 'EMAIL_HDR_TEST_ID', 'EMAIL_TEST_ANTIVIRUS', 'EMAIL_TEST_SSRF', 'EMAIL_TEST_ZIPXXE', 'EMAIL_TEST_ALIAS', 'EMAIL_TEST_REPLAY', 'EMAIL_TEST_BOMB', '_PTL_EMAIL_TAG_RE', '_email_subject_clean', 'RCPT_DUP_DEFAULT', 'RCPT_DUP_MAX', '_rcpt_duplicate_error_is_environmental', 'RATE_LIMIT_DEFAULT_ATTEMPTS', 'RATE_LIMIT_CONN_VULN_THRESHOLD', 'RATE_LIMIT_BAN_MIN_SECONDS', 'RATE_LIMIT_INITIAL_TIMEOUT_MAX_SECONDS', 'RATE_LIMIT_IDLE_TIMEOUT_MAX_SECONDS', 'RATE_LIMIT_TIMEOUT_CAP_SECONDS', '_rate_limit_duration_display', 'NOOP_FLOOD1_MAX_COMMANDS', 'NOOP_FLOOD1_TIMEOUT_SECONDS', 'NOOP_FLOOD1_OVERALL_CAP_SECONDS', 'NOOP_FLOOD_DISCONNECT_OK_MAX', 'NOOP_FLOOD_SLOWDOWN_MIN_RATIO', 'NOOP_FLOOD_SLOWDOWN_MIN_SECONDS', 'NOOP_FLOOD_ERROR_RATE_OK_MAX_PCT', 'NOOP_FLOOD2_DEFAULT_CONNECTIONS', 'NOOP_FLOOD2_MAX_CONNECTIONS', 'NOOP_FLOOD2_RUN_SECONDS', 'NOOP_FLOOD2_CONNECT_TIMEOUT', 'NOOP_FLOOD2_RECV_TIMEOUT', 'NOOP_FLOOD2_AVG_TIME_OK_MAX_SECONDS', 'NOOP_FLOOD2_DEBUG_TICK_SECONDS', 'NOOP_FLOOD1_PROGRESS_EVERY', 'NoopFlood1Result', 'NoopFlood2Result', '_noop_rt_window_display', 'ACCEPTED_DOMAIN_PLACEHOLDER_DOMAINS', '_accepted_domain_is_placeholder', 'RcptLimitResult', 'RcptDuplicateResult', 'AcceptedDomainProbeResult', 'EnumResult', 'BlacklistEntry', 'BlacklistResult', 'InfoResult', 'EncryptionResult', 'RoleResult', 'CatchAllResult', 'CATCH_ALL_INDETERMINATE_VARIANTS', 'AuthEnumResult', 'AUTH_FORMAT_PROBE_DELAY_SEC', 'AUTH_FORMAT_EXTERNAL_SUFFIX', 'AuthFormatTargetDomainDerivation', 'AuthFormatProbeRow', 'AuthFormatProbeResult', '_auth_format_row_symbol', '_auth_format_conclude', 'HeloValidationResult', 'AuthDowngradeResult', 'InvCommTestCase', 'InvCommResult', 'HeloOnlyResult', 'HeloBypassResult', 'BounceReplayResult', '_bounce_replay_active', '_bounce_replay_from_addr', '_classify_connection_error', 'AntivirusCategoryResult', 'AntivirusResult', 'SsrfVariantResult', 'SsrfResult', 'ZipxxeVariantResult', 'ZipxxeResult', 'SpoofHeaderVariantResult', 'SpoofHeaderResult', 'BccTestResult', 'AliasVariantResult', 'AliasTestResult', 'FloodResult', 'BombResult', 'SMTPResults', 'VULNS']


# region data classes


class NTLMResult(NamedTuple):
    success: bool
    ntlm: NTLMInfo | None


class RateLimitResult(NamedTuple):
    connected: int | None                  # Max simultaneous connections accepted
    max_attempts: int                      # Attempt budget used for this run (for JSON context)
    banned: bool                           # True if the server refused further connections within ramp-up
    ban_duration_probe_ran: bool           # True only when ban-duration probe ran (implies banned)
    ban_duration_seconds: float | None     # Seconds until server accepted new conn after ban (None if no ban)
    ban_duration_exceeded: bool            # True if ban-duration probe hit the 5 min cap
    initial_timeout_seconds: float | None  # Seconds the banner-only (no EHLO) session stayed open
    initial_timeout_exceeded: bool         # True if banner-only session hit the 5 min cap
    idle_timeout_seconds: float | None     # Seconds the after-EHLO session stayed open
    idle_timeout_exceeded: bool            # True if after-EHLO session hit the 5 min cap


# RCPT TO limit (-rl): max RCPT attempts per session (default); policy-reject early stop (no accept yet).
RCPT_LIMIT_DEFAULT_ATTEMPTS = 1000
RCPT_LIMIT_POLICY_REJECT_CAP = 50
# Terminal verdict / JSON ManyRcpt: OK ≤100, warning 101–500, error / vuln >500
RCPT_LIMIT_VERDICT_OK_MAX = 100
RCPT_LIMIT_VERDICT_WARN_MAX = 500
# Post-hit disconnect probe: how many extra RCPT TO are sent after the per-message
# limit is detected to determine whether the server eventually closes the session.
RCPT_LIMIT_POSTHIT_PROBE_COUNT = 20
# MTA-not-relay: recommend at least this many local names in -u / -U for a meaningful limit probe.
RCPT_LIMIT_MIN_RECOMMENDED_NAME_COUNT = 500
# Pre-probe local part for accept-all / catch-all detection via RCPT TO (before -rl storm).
RCPT_LIMIT_ACCEPT_ALL_PROBE_LOCAL = "xxxfoofff"
# -id RCPT error-syntax probe (invalid recipient; throwaway MAIL FROM).
_ID_RCPT_ERROR_MAIL_FROM = "probe@probe.invalid"
_ID_RCPT_ERROR_RCPT = "nonexistent-local@invalid.invalid"
# Client IP rate limit (Postfix and similar): 450 4.7.1 Error: too much mail from <ip>
_RL_TOO_MUCH_MAIL_RE = re.compile(
    r"4\.7\.1\s+Error:\s+too much mail from\s+[\da-fA-F:.]+",
    re.IGNORECASE,
)


def _rl_extract_too_much_mail_error(text: str | None) -> str | None:
    """Return normalized ``4.7.1 Error: too much mail from …`` line when present."""
    if not text:
        return None
    one_line = " ".join(str(text).replace("\r", "\n").split())
    if m := _RL_TOO_MUCH_MAIL_RE.search(one_line):
        return m.group(0)
    lower = one_line.lower()
    if "too much mail from" not in lower:
        return None
    start = lower.find("4.7.1")
    if start >= 0:
        return one_line[start:].strip()
    start = lower.find("too much mail from")
    return one_line[start:].strip()


DEFAULT_SMTP_SUBJECT = "SMTP test"
DEFAULT_SMTP_DATA = "SMTP test message."

AV_CATEGORY_TITLES: dict[str, str] = {
    "eicar": "Eicar file test",
    "double_ext": "Double Extension test",
    "executable": "Executable test",
    "nested_archive": "Nested archive test",
    "encoded_content": "Encoded content test",
    "html_sanitization": "HTML sanitization test",
    "xxe": "XXE test",
    "mime_malformed": "MIME malformed test",
    "zip_bomb": "Zip bomb test",
}

ALIAS_VARIANT_TITLES: dict[str, str] = {
    "case": "Local part case test",
    "case_domain": "Domain case test",
    "dotted": "Dotted local part test",
    "plus": "Plus addressing test",
    "percent": "Percent addressing test",
    "bang_simple": "UUCP bang path test",
    "bang_nested": "Nested UUCP bang path test",
}

SSRF_VARIANT_TITLES: dict[str, str] = {
    "plain": "Plain URL test",
    "html_link": "HTML link test",
    "html_img": "HTML image test",
    "html_iframe": "HTML iframe test",
    "multipart": "Multipart test",
    "ssrf_malformed": "Malformed MIME test",
    "ssrf_nested": "Nested MIME test",
    "internal_127": "Internal 127.0.0.1 URL test",
    "internal_localhost": "Internal localhost URL test",
    "internal_10": "Internal 10.0.0.1 URL test",
}

SSRF_VARIANT_PAYLOAD_LABELS: dict[str, str] = {
    "plain": "plain text URL",
    "html_link": "HTML link",
    "html_img": "HTML image",
    "html_iframe": "HTML iframe",
    "multipart": "multipart plain + HTML",
    "ssrf_malformed": "malformed MIME boundary",
    "ssrf_nested": "deeply nested MIME",
    "internal_127": "http://127.0.0.1/ssrf-pt-test",
    "internal_localhost": "http://localhost/ssrf-pt-test",
    "internal_10": "http://10.0.0.1/ssrf-pt-test",
}

ZIPXXE_VARIANT_TITLES: dict[str, str] = {
    "billion_laughs_attach": "Billion laughs attachment test",
    "billion_laughs_body": "Billion laughs body test",
    "xxe_zip": "XXE in ZIP test",
    "xxe_docx": "XXE in DOCX test",
    "xxe_body": "XXE in body test",
    "zip_bomb": "Zip bomb test",
    "zip_bomb_full": "Zip bomb full test",
}

ZIPXXE_VARIANT_PAYLOAD_LABELS: dict[str, str] = {
    "billion_laughs_attach": "billion_laughs.xml",
    "billion_laughs_body": "body (XML)",
    "xxe_zip": "report.zip",
    "xxe_docx": "document.docx",
    "xxe_body": "body (XML)",
    "zip_bomb": "zipbomb.zip",
    "zip_bomb_full": "zipbomb_full.zip",
}


def _smtp_minimal_probe_data(
    *,
    from_addr: str,
    subject: str,
    body: str,
    message_id_tag: str,
    domain: str,
    probe_uuid: str,
    to_addr: str | None = None,
) -> str:
    """Minimal RFC822 payload for SMTP DATA probes (no vendor X-headers)."""
    lines = [f"From: {from_addr}"]
    if to_addr:
        lines.append(f"To: {to_addr}")
    lines.extend(
        [
            f"Subject: {subject}",
            f"Message-ID: <{message_id_tag}-{probe_uuid}@{domain}>",
            "",
            body,
        ]
    )
    return "\r\n".join(lines)


# Outbound SMTP test e-mail markers (no PT / Penterep prefix in headers or bodies).
EMAIL_HDR_TEST = "X-Test"
EMAIL_HDR_TEST_ID = "X-Test-ID"
EMAIL_TEST_ANTIVIRUS = "SMTP-ANTIVIRUS"
EMAIL_TEST_SSRF = "SMTP-SSRF"
EMAIL_TEST_ZIPXXE = "SMTP-ZIPXXE"
EMAIL_TEST_ALIAS = "SMTP-ALIAS"
EMAIL_TEST_REPLAY = "SMTP-REPLAY"
EMAIL_TEST_BOMB = "SMTP-BOMB"
_PTL_EMAIL_TAG_RE = re.compile(r"PTL-SVC-SMTP-")


def _email_subject_clean(subject: str) -> str:
    """Strip legacy PTL-SVC-SMTP-* vendor tags from Subject lines."""
    s = re.sub(r"\s*\(PTL-SVC-SMTP-[^)]+\)", "", subject or "")
    s = _PTL_EMAIL_TAG_RE.sub("", s)
    return " ".join(s.split()).strip()


# Duplicate RCPT TO (-rdd): same envelope recipient repeated N times in one MAIL transaction.
# RFC 5321 does not forbid this; delivery fan-out is implementation-defined (dedupe vs N copies).
RCPT_DUP_DEFAULT = 10
RCPT_DUP_MAX = 50


def _rcpt_duplicate_error_is_environmental(err: str | None) -> bool:
    """True when duplicate-RCPT probe cannot start (policy / AUTH), not a vulnerability finding."""
    if not err:
        return False
    return "MAIL FROM rejected for all candidates" in err


# Parallel SMTP sessions (-rt / --rate-limit): default max ramp-up attempts
RATE_LIMIT_DEFAULT_ATTEMPTS = 100

# Rate limiting verdict thresholds (placeholder values – will be tuned later).
RATE_LIMIT_CONN_VULN_THRESHOLD = 50            # >= this many simultaneous conns accepted → vulnerable
RATE_LIMIT_BAN_MIN_SECONDS = 30                # ban shorter than this → vulnerable
RATE_LIMIT_INITIAL_TIMEOUT_MAX_SECONDS = 60    # banner-only timeout longer than this → vulnerable
RATE_LIMIT_IDLE_TIMEOUT_MAX_SECONDS = 180      # idle (after EHLO) timeout longer than this → vulnerable
RATE_LIMIT_TIMEOUT_CAP_SECONDS = 300           # hard cap for any individual timeout / ban measurement


def _rate_limit_duration_display(seconds: float | None, exceeded: bool) -> str:
    """Format -rt durations for console / flat JSON: ``MM:SS``, or ``> MM:SS`` when the hard cap was hit."""
    if seconds is None:
        return "N/A"
    mm = int(seconds // 60)
    ss = int(seconds % 60)
    mmss = f"{mm:02d}:{ss:02d}"
    return f"> {mmss}" if exceeded else mmss


# ─── NOOP Flooding (-ts NOOP1 / -ts NOOP2) ────────────────────────────────────
# RFC 5321 §4.1.1.9: NOOP must return 250; any other reply (421/4xx/5xx) or a
# socket-level failure counts as an error for our error-rate metric.
#
# Defaults / verdict thresholds are derived from Postfix built-ins:
#   - smtpd_junk_command_limit = 100 (each further NOOP increments the error
#     counter; under overload the limit drops to 1).
#   - smtpd_hard_error_limit = 20 (1 under overload).
#   - smtpd_soft_error_limit = 10 / smtpd_error_sleep_time = 1s → responses
#     start to slow down once the error counter is between 10 and the hard
#     limit.
# → A well-configured Postfix drops the connection after ~120 NOOPs with a
# gradual slowdown starting around 110. Sendmail has no equivalent junk limit
# (relies on Timeout.misc = 2m) and is effectively vulnerable by default.

NOOP_FLOOD1_MAX_COMMANDS = 1000             # per-connection safety cap
NOOP_FLOOD1_TIMEOUT_SECONDS = 30.0          # recv() timeout for a single NOOP reply
NOOP_FLOOD1_OVERALL_CAP_SECONDS = 180.0     # never let a single -ts NOOP1 run exceed this

NOOP_FLOOD_DISCONNECT_OK_MAX = 120          # ≤ this many NOOPs before disconnect → OK (Postfix default-ish)
NOOP_FLOOD_SLOWDOWN_MIN_RATIO = 1.5         # last-window avg / baseline avg ≥ this → slowdown configured
NOOP_FLOOD_SLOWDOWN_MIN_SECONDS = 0.5       # OR last-window avg ≥ this (absolute) → slowdown configured
NOOP_FLOOD_ERROR_RATE_OK_MAX_PCT = 5.0      # ≤ this % error replies → OK

NOOP_FLOOD2_DEFAULT_CONNECTIONS = 50        # default parallel connections (-nf2 without argument)
NOOP_FLOOD2_MAX_CONNECTIONS = 1000          # user-specified ceiling (safety)
NOOP_FLOOD2_RUN_SECONDS = 30.0              # steady-state duration (per thread) after ramp-up
NOOP_FLOOD2_CONNECT_TIMEOUT = 10.0
NOOP_FLOOD2_RECV_TIMEOUT = 30.0
NOOP_FLOOD2_AVG_TIME_OK_MAX_SECONDS = 5.0   # avg time between NOOPs under load ≤ this → OK
NOOP_FLOOD2_DEBUG_TICK_SECONDS = 2.0        # (reserved) storm-tick interval; -vv logs per-connection events
NOOP_FLOOD1_PROGRESS_EVERY = 25               # live progress + -vv snapshot interval (commands)


class NoopFlood1Result(NamedTuple):
    """Single-connection NOOP flood (-ts NOOP1)."""
    commands_sent: int                 # Total NOOPs issued (ok + error)
    commands_ok: int                   # 250 OK replies
    commands_error: int                # 4xx/5xx/timeout/socket reset
    disconnected: bool                 # True if server closed the connection
    disconnect_after: int | None       # Number of NOOPs after which server closed (None if never)
    hit_command_cap: bool              # True when we stopped on NOOP_FLOOD1_MAX_COMMANDS
    hit_time_cap: bool                 # True when we stopped on NOOP_FLOOD1_OVERALL_CAP_SECONDS
    min_rt_seconds: float | None       # Fastest per-command round-trip observed
    max_rt_seconds: float | None       # Slowest (pre-disconnect) per-command round-trip
    avg_rt_seconds: float | None       # Mean per-command round-trip
    baseline_avg_seconds: float | None # Mean of the first ≤10 successful replies
    last_window_avg_seconds: float | None  # Mean of the last ≤10 successful replies
    slowdown_detected: bool            # True if the last-window avg vs baseline indicates trolling
    error_rate_pct: float              # 100 * commands_error / commands_sent


class NoopFlood2Result(NamedTuple):
    """Parallel-connection NOOP DoS flood (-nf2)."""
    requested_connections: int         # What the user asked for
    established_connections: int       # How many sockets actually got past 220
    run_duration_seconds: float        # How long we actually hammered the server
    commands_sent: int                 # Total NOOPs across all threads
    commands_ok: int                   # 250 OK replies
    commands_error: int                # Errors (4xx/5xx/timeouts/closed sockets)
    min_rt_seconds: float | None
    max_rt_seconds: float | None
    avg_rt_seconds: float | None       # Mean per-command round-trip across all threads
    error_rate_pct: float              # 100 * commands_error / commands_sent
    # ── Connection-survival tracking (added with the live "active" probe) ──
    active_connections_end: int = 0    # Sockets still alive when the storm finished
    disconnected_during_test: int = 0  # established - active_connections_end
    early_exit_no_connections: bool = False  # All sockets dropped before the time limit
    # ── Ramp-up failure breakdown (every requested socket is attempted) ──
    establish_errors: int = 0          # Generic failures while opening sockets
    establish_disconnected: int = 0    # Refused / reset / server-closed sockets
    establish_timeouts: int = 0        # Connect/handshake timeouts
    # ── Pre-storm liveness sweep ──
    reaped_before_storm: int = 0       # Established sockets the server already closed
                                       # before the storm began (idle reap / conn cap).
    storm_pool_connections: int = 0    # Sockets actually alive at storm start (= 100% base)
    # Per-connection terminations during the storm: tuple of (index, reason, detail).
    terminated_connections: tuple = ()


def _noop_rt_window_display(value: float | None) -> str:
    """Format a round-trip time as ``Xs`` / ``X.Ys`` for terminal output."""
    if value is None:
        return "N/A"
    if value >= 10:
        return f"{int(round(value))}s"
    if value >= 1:
        return f"{value:.1f}s"
    return f"{value:.2f}s"


# Common MTA / doc placeholder hostnames: -pd may still infer them; flag for analysts
ACCEPTED_DOMAIN_PLACEHOLDER_DOMAINS: frozenset[str] = frozenset(
    {
        "example.com",
        "example.net",
        "example.org",
        "example.invalid",
        "test.com",
        "localhost",
        "localhost.localdomain",
    }
)


def _accepted_domain_is_placeholder(domain: str | None) -> bool:
    if not domain or not str(domain).strip():
        return False
    return str(domain).strip().lower().rstrip(".") in ACCEPTED_DOMAIN_PLACEHOLDER_DOMAINS


class RcptLimitResult(NamedTuple):
    """Result of RCPT TO limit test: max accepted before server rejected or we stopped."""
    max_accepted: int
    limit_triggered: bool  # True if server sent 421/452/5xx or closed connection
    server_response: str | None  # First error response when limit triggered
    rejected_addresses: bool = False  # True if server rejected test addresses (450/550) before any accepted
    domain_used: str | None = None  # Domain used for MAIL FROM/RCPT TO (for hint when test failed)
    # Session error limit (smtpd_hard_error_limit): probe continues on 554/550/553 to detect disconnect
    failed_before_limit: int = 0  # Number of failed RCPTs before 421 or disconnect
    session_limit_triggered: bool = False  # True if server disconnected or returned 421
    no_session_limit: bool = False  # True if server allowed N failed RCPTs without disconnecting
    # ── Pre-check context (added with --rl smart routing) ───────────────────────
    role: str | None = None  # mta | submission | hybrid | indeterminate | None when not detected
    auth_required: bool | None = None  # AUTH required for RCPT TO (per role probe)
    auth_used: bool = False  # True if --rl performed AUTH LOGIN before probing
    open_relay: bool | None = None  # Open relay verdict (only meaningful for MTA/hybrid)
    skipped: bool = False  # True when --rl was not relevant for this server configuration
    skip_reason: str | None = None  # 'mta_not_relay_no_wordlist' | 'submission_auth_required' | 'auth_failed' | 'rate_limited'
    skip_message: str | None = None  # Human-readable explanation for output / JSON
    recipients_source: str | None = None  # 'synthetic' (1@dom, 2@dom) | 'wordlist' (real local users)
    # ── Post-hit disconnect probe (only when limit_triggered is True) ───────────
    disconnect_after_limit: bool | None = None  # True = server closed session after extra rejects;
                                                # False = stayed open through full POSTHIT probe;
                                                # None = not measured (skipped/error/no limit found)
    posthit_probe_count: int = 0  # Number of additional RCPT TOs sent after limit hit
    accept_all_via_rcpt: bool = False  # True when pre-probe accepted RCPT_LIMIT_ACCEPT_ALL_PROBE_LOCAL@domain
    # ── Legacy catch-all bounce probe fields (unused; kept for JSON compat) ──
    catch_all_bounce_mailbox: str | None = None
    catch_all_delivery_rcpt: str | None = None  # Probe RCPT (``xxxfoofff@domain``)
    catch_all_delivery_attempted: bool = False  # True when a DATA probe was submitted
    catch_all_delivery_data_ok: bool = False  # True when server accepted DATA (250)
    catch_all_probe_uuid: str | None = None  # Correlates manual inbox check (Message-ID / X-header)
    # ── RCPTLIM with ``--send``: deliver one message after the RCPT storm ──
    limit_send_mode: bool = False  # True when ``--send`` was used with RCPTLIM
    limit_send_attempted: bool = False  # True when DATA was submitted (accepted > 0)
    limit_send_ok: bool = False  # True when server accepted DATA (250)
    limit_send_data_code: int | None = None
    limit_send_data_reply: str | None = None
    limit_send_mail_from: str | None = None  # Envelope MAIL FROM from ``-m``


class RcptDuplicateResult(NamedTuple):
    """Same address repeated in multiple RCPT TO within one MAIL transaction (-rdd)."""
    recipient: str
    duplicate_count: int
    rcpt_replies: tuple[tuple[int, str], ...]
    all_rcpt_2xx: bool
    first_failure_index: int | None
    data_sent: bool
    data_code: int | None
    data_reply_snippet: str | None
    mail_from_used: str | None
    probe_uuid: str | None


class AcceptedDomainProbeResult(NamedTuple):
    """Informational RCPT probe (-pd): inferred recipient domain; no vulnerability code in JSON."""
    domain: str | None
    confidence: str  # high | medium | low | none
    detail: str | None = None
    candidates_tested: tuple[str, ...] = ()
    universal_accept_detected: bool = False
    likely_placeholder_domain: bool = False


class EnumResult(NamedTuple):
    method: str
    vulnerable: bool
    slowdown: bool | None
    results: list[str] | None
    server_reply: str | None = None  # First server response, e.g. "[550] User unknown"
    blocked_by_rbl: bool = False  # True when server rejected due to RBL (could not test)


class BlacklistEntry(NamedTuple):
    blacklist: str
    reason: str
    ttl: str


class BlacklistResult(NamedTuple):
    listed: bool
    results: list[BlacklistEntry] | None


class InfoResult(NamedTuple):
    banner: str
    ehlo: str
    ehlo_starttls: str | None = None  # EHLO after STARTTLS upgrade (when PLAIN had STARTTLS)


class EncryptionResult(NamedTuple):
    """
    Result of encryption test: which connection types are available on the port.
    Stored in SMTPResults.encryption so that subsequent tests can use it to choose
    the appropriate connection mode (plaintext, STARTTLS, or TLS).
    """
    plaintext_ok: bool
    starttls_ok: bool
    tls_ok: bool


class RoleResult(NamedTuple):
    """Result of role identification test: MTA, Submission, Hybrid, or indeterminate."""
    role: str              # "mta" | "submission" | "hybrid" | "indeterminate"
    port_hint: str         # "mta" | "submission" | "unknown"
    auth_advertised: bool  # AUTH found in EHLO (plain or STARTTLS)
    auth_required: bool | None  # True=all RCPT require auth, False=no, None=not tested
    detail: str            # Human-readable reason


# Catch-all test result:
#   "configured" | "not_configured" | "indeterminate"
#   | "indeterminate_accept_all_rcpt" (RCPT-only: all invalid RCPT accepted)
CatchAllResult = str
CATCH_ALL_INDETERMINATE_VARIANTS = frozenset(
    {"indeterminate", "indeterminate_accept_all_rcpt"}
)


class AuthEnumResult(NamedTuple):
    """Result of AUTH user enumeration test."""
    vulnerable: bool
    indeterminate: bool
    method_tested: str  # "LOGIN" | "PLAIN" | "NTLM"
    protocol_flow_vuln: bool  # True if server responded 5xx after username (before password)
    invalid_user_responses: list[str]  # Responses for invalid user(s)
    valid_user_response: str | None  # Response for first -u / -U file candidate + wrong password
    enumerated_users: tuple[str, ...]  # Subset of -u / -U file whose response differs from invalid baseline
    detail: str | None


# PTL-SVC-SMTP-AUTH-FORMAT: infer expected AUTH LOGIN identity shape (username vs e-mail vs NetBIOS).
AUTH_FORMAT_PROBE_DELAY_SEC = 1.5
AUTH_FORMAT_EXTERNAL_SUFFIX = "example.com"


class AuthFormatTargetDomainDerivation(NamedTuple):
    """How probe-B domain was chosen (last-2-label heuristic; not PSL-aware)."""

    domain: str | None
    source: str  # scan_last2 | ehlo_last2 | none
    analyst_note: str | None  # always-on context for operators (PSL / IP fallback)
    ehlo_hostname: str | None  # set when source == ehlo_last2
    scan_hostname: str | None  # set when source == scan_last2


class AuthFormatProbeRow(NamedTuple):
    """One LOGIN probe (fresh connection)."""

    probe_id: str  # single_label | target_domain | external_domain | netbios
    label: str  # human label for UI
    identity: str
    skipped: bool
    skip_reason: str | None
    code_after_identity: int | None
    password_phase: bool  # 334 after identity → server accepted identity shape for this step
    code_after_password: int | None
    reply_after_identity: str | None
    rate_limited: bool


class AuthFormatProbeResult(NamedTuple):
    """Result of AUTH LOGIN format detection (PTL-SVC-SMTP-AUTH-FORMAT)."""

    method_tested: str  # "LOGIN" or ""
    rows: tuple[AuthFormatProbeRow, ...]
    challenge_decoded: str | None
    challenge_hint: str | None
    conclusion: str
    conclusion_id: str
    target_domain_used: str | None
    netbios_domain_used: str | None
    rate_limited: bool
    indeterminate: bool
    detail: str | None
    # Probe B context (PSL not used — analysts must sanity-check, esp. .co.uk etc.)
    target_domain_source: str  # scan_last2 | ehlo_last2 | none
    target_domain_analyst_note: str | None
    target_domain_ehlo_hostname: str | None
    target_domain_scan_hostname: str | None


def _auth_format_row_symbol(row: AuthFormatProbeRow) -> str:
    if row.skipped:
        return "skip"
    # Rate limit at username phase only — 334 then temp fail at password still means "accepted identity shape"
    if row.rate_limited and not row.password_phase:
        return "rate"
    c = row.code_after_identity
    if c == 334 and row.password_phase:
        return "334"
    if c is not None and 500 <= c < 600:
        return "535"
    if c is not None and 400 <= c < 500:
        return "4xx"
    if c is not None and 200 <= c < 300:
        return "2xx"
    return "?"


def _auth_format_conclude(
    sym_a: str,
    sym_b: str,
    sym_c: str,
    sym_d: str,
    b_ran: bool,
    d_ran: bool,
    challenge_hint: str | None,
) -> tuple[str, str]:
    """
    Map probe symbols to (conclusion_id, human conclusion).
    A=single_label, B=target_domain, C=external_domain, D=netbios.
    """
    if challenge_hint and sym_a == "?" and sym_b == "?" and sym_c == "?":
        return ("challenge_hint_only", f"Heuristic from LOGIN challenge text: {challenge_hint}")

    def acc(x: str) -> bool:
        return x == "334"

    def rej(x: str) -> bool:
        return x == "535"

    def acc_or_skip(x: str) -> bool:
        return x == "skip" or acc(x)

    all_acc_core = acc(sym_a) and acc(sym_c) and acc_or_skip(sym_b) and acc_or_skip(sym_d)

    # NetBIOS and "flexible vs NetBIOS" — keep before generic e-mail / catch-all buckets
    if b_ran and d_ran:
        if rej(sym_a) and rej(sym_b) and rej(sym_c) and acc(sym_d):
            return (
                "netbios_suggested",
                "NetBIOS-style identity accepted on LOGIN (DOMAIN\\user); other shapes rejected",
            )
        if acc(sym_a) and acc(sym_b) and acc(sym_c) and not acc(sym_d):
            return ("flexible_all_formats", "Flexible / accepts all tested identity formats")

    # --- 1. E-mail required (single-label rejected) ---
    if sym_a == "535":
        if b_ran and sym_b == "334":
            if sym_c == "334":
                return (
                    "email_format_any",
                    "Email address format required (any domain accepted)",
                )
            return (
                "email_format_target",
                "Full email address required (target domain specific)",
            )
        if not b_ran and sym_c == "334":
            return (
                "email_format_generic",
                "Email address format required (any domain likely accepted)",
            )

    # --- 2. Username only (single-label OK; e-mail shapes rejected) ---
    if sym_a == "334":
        if (not b_ran or sym_b == "535") and sym_c == "535":
            return (
                "username_only",
                "Username only — email address format rejected",
            )

    # A + target-domain accepted, external rejected (schema gap vs. username_only)
    if b_ran and d_ran and acc(sym_a) and acc(sym_b) and rej(sym_c) and not acc(sym_d):
        return (
            "username_or_target_domain",
            "Username or target-domain e-mail accepted (rejects arbitrary external domain)",
        )
    if b_ran and not d_ran and acc(sym_a) and acc(sym_b) and rej(sym_c):
        return (
            "username_or_target_domain",
            "Username or target-domain e-mail accepted (rejects arbitrary external domain)",
        )

    # --- 3. Catch-all / flexible (all probed shapes reach password phase) ---
    if all_acc_core:
        return (
            "generic_masking",
            "Generic behavior — all identities reach password phase (possible catch-all masking)",
        )

    # --- 4. Aggressive enumeration protection (reject at username for A; B/C consistent) ---
    if sym_a == "535":
        if (not b_ran or sym_b == "535") and sym_c == "535":
            return (
                "aggressive_protection",
                "Aggressive enumeration protection — all identities rejected at username phase",
            )

    if not b_ran and (acc(sym_a) or rej(sym_a)) and (acc(sym_c) or rej(sym_c)):
        return (
            "indeterminate_no_target_domain",
            "Indeterminate: target domain unknown (scan by IP). Use hostname target or inspect manually.",
        )

    return ("mixed_responses", "Mixed responses — manual review recommended")


class HeloValidationResult(NamedTuple):
    """Result of HELO/EHLO hostname validation test (RFC 5321, best practices)."""
    vulnerable: bool  # True = accepts syntactic nonsense or localhost
    weak_config: bool  # True = accepts non-existent FQDN (no DNS lookup)
    indeterminate: bool  # True = baseline failed (5xx on mail.google.com)
    ehlo_bypass: bool | None  # True = different EHLO extensions for different hostnames
    accepted_vectors: list[str]
    rejected_vectors: list[str]
    ehlo_comparison: dict[str, list[str]] | None  # hostname -> extension keys
    detail: str | None


class AuthDowngradeResult(NamedTuple):
    """Result of AUTH downgrade test: server changes AUTH offer after failed auth."""
    vulnerable: bool  # True = new weaker methods appeared after failure
    weakness: bool  # True = strong methods disappeared, PLAIN remained
    indeterminate: bool  # True = connection closed, no AUTH, etc.
    info_defensive: bool  # True = AUTH disappeared entirely (defensive reaction)
    methods_before: list[str]
    methods_after: list[str]
    auth_method_used: str  # XOAUTH2, OAUTHBEARER, etc.
    server_response: str | None
    detail: str | None
    rset_ok: bool | None = None  # None = not attempted, True = RSET OK, False = connection closed during RSET


class InvCommTestCase(NamedTuple):
    """Single invalid-commands test case result (PTL-SVC-SMTP-INVCOMM)."""
    category: str  # "invalid", "long_input", "special_chars", "bad_sequence"
    command_display: str  # Short display string
    status: int | None  # SMTP code or None if connection lost/timeout
    reply: str | None  # Server reply text
    session_ok: bool | None  # True=RSET/NOOP worked after, False=conn closed, None=not attempted
    info_leak: bool  # True if reply contains paths, versions, stack trace
    vulnerable: bool  # True if crash/timeout or accepted invalid (2xx)
    response_time_sec: float | None = None  # Time to receive response (for long_input ReDoS detection)
    slow_response: bool = False  # True if response took > threshold (possible ReDoS in parser)
    vuln_type: str | None = None  # "acceptance" | "crash" | "timeout" when vulnerable


class InvCommResult(NamedTuple):
    """Result of invalid/non-standard SMTP commands test (PTL-SVC-SMTP-INVCOMM)."""
    vulnerable: bool  # True = crash, timeout, or accepted invalid command
    weakness: bool  # True = verbose error messages (info leak)
    indeterminate: bool  # True = rate limit or could not complete
    tests: tuple[InvCommTestCase, ...]
    detail: str | None
    baseline_latency_sec: float | None = None  # Measured NOOP latency before fuzzing (for adaptive threshold)
    tarpitting_detected: bool = False  # True when constant delay on invalid commands (smtpd_error_sleep_time)


class HeloOnlyResult(NamedTuple):
    """Result of HELO-only test (PTL-SVC-SMTP-HELOONLY). Server supports only HELO, no EHLO extensions."""
    vulnerable: bool  # True = server supports only HELO, no EHLO extensions
    indeterminate: bool  # True = could not complete (connection error, rate limit)
    helo_status: int | None  # SMTP status from HELO (e.g. 250)
    helo_reply: str | None  # Raw reply from HELO
    ehlo_status: int | None  # SMTP status from EHLO (e.g. 250, 500, 502)
    ehlo_reply: str | None  # Raw reply from EHLO
    extensions: tuple[str, ...]  # Parsed ESMTP extensions from EHLO (empty if none/vulnerable)
    connection_type: str  # "plain" | "starttls" | "tls"
    detail: str | None


class HeloBypassResult(NamedTuple):
    """Result of HELO/EHLO bypass test (PTL-SVC-SMTP-HELO)."""
    vulnerable: bool
    indeterminate: bool
    submission_bypass_ehlo: tuple[str, ...]
    relay_bypass_ehlo: tuple[str, ...]
    accepts_invalid_format: tuple[str, ...]
    ehlo_consistent: bool
    ehlo_comparison: dict
    tarpitting_detected: tuple[str, ...]
    rcpt_latencies: dict
    detail: str | None


class BounceReplayResult(NamedTuple):
    """Result of bounce replay / backscatter test (PTL-SVC-SMTP-REPLAY)."""
    vulnerable: bool
    indeterminate: bool
    message_accepted: bool
    rcpt_rejected_in_session: bool
    bounce_addr: str
    recipient_used: str
    test_id: str
    smtp_trace: tuple[str, ...]
    tarpitting_or_timeout: bool  # True when response took >30s or timeout (greylisting/tarpitting)
    detail: str | None
    message_accepted_return_path: bool  # Second probe: DATA with Return-Path header
    test_id_return_path: str
    probe1_detail: str | None = None        # Detail from Probe 1 _phase()
    probe2_detail: str | None = None        # Detail from Probe 2 _phase()
    probe1_indeterminate: bool = False      # True when Probe 1 timed out / connection lost
    probe2_indeterminate: bool = False      # True when Probe 2 timed out / connection lost
    auth_used: bool = False                 # True when -u/-p (or -U/-P first line) AUTH ran before probes


def _bounce_replay_active(args) -> bool:
    """True when `-br` / `--bounce-replay` was passed."""
    return bool(getattr(args, "bounce_replay", False))


def _bounce_replay_from_addr(args) -> str | None:
    """Controlled bounce address: `-m` / `--mail-from` when `-br` is active."""
    if not _bounce_replay_active(args):
        return None
    m = getattr(args, "mail_from", None) or ""
    s = str(m).strip()
    return s if s else None


def _classify_connection_error(exc: BaseException) -> tuple[str, str]:
    """
    Classify connection error for BOMB test.
    Returns (last_error_type, last_error_message).
    - connection_reset: Typically Firewall/IPS (Layer 4)
    - timeout: Often Tarpitting or queue overload on MTA
    """
    msg = str(exc).lower()
    if isinstance(exc, ConnectionResetError):
        return ("connection_reset", str(exc))
    if isinstance(exc, BrokenPipeError):
        return ("broken_pipe", str(exc))
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return ("timeout", str(exc))
    if isinstance(exc, OSError) and hasattr(exc, "errno"):
        if exc.errno in (104, 54):  # ECONNRESET, ECONNABORTED
            return ("connection_reset", str(exc))
        if exc.errno in (110, 60):  # ETIMEDOUT, ETIMEDOUT on Windows
            return ("timeout", str(exc))
    if "timeout" in msg or "timed out" in msg:
        return ("timeout", str(exc))
    if "reset" in msg or "connection reset" in msg or "eof" in msg:
        return ("connection_reset", str(exc))
    if "broken pipe" in msg or "pipe" in msg:
        return ("broken_pipe", str(exc))
    return ("other", str(exc))


class AntivirusCategoryResult(NamedTuple):
    """Result of one category in ANTIVIRUS test (PTL-SVC-SMTP-ANTIVIRUS)."""
    category: str
    sent: int
    accepted: int
    rejected: int
    error: int
    smtp_trace: tuple[str, ...]
    detail: str | None
    message_summary: tuple[str, ...] = ()
    test_id: str = ""
    payload_test_ids: tuple[str, ...] = ()


class AntivirusResult(NamedTuple):
    """Result of ANTIVIRUS test (PTL-SVC-SMTP-ANTIVIRUS)."""
    vulnerable: bool
    indeterminate: bool
    partial_protection: bool
    categories: tuple[AntivirusCategoryResult, ...]
    elapsed_sec: float
    auth_used: bool
    detail: str | None


class SsrfVariantResult(NamedTuple):
    """Result of one variant in SSRF test (PTL-SVC-SMTP-SSRF)."""
    variant: str
    sent: int
    accepted: int
    rejected: int
    error: int
    smtp_trace: tuple[str, ...]
    detail: str | None
    message_summary: tuple[str, ...] = ()
    test_id: str = ""


class SsrfResult(NamedTuple):
    """Result of SSRF test (PTL-SVC-SMTP-SSRF)."""
    manual_verification_required: bool
    canary_url: str
    variants: tuple[SsrfVariantResult, ...]
    elapsed_sec: float
    auth_used: bool
    detail: str | None
    verification_instructions: str


class ZipxxeVariantResult(NamedTuple):
    """Result of one variant in ZIPXXE test (PTL-SVC-SMTP-ZIPXXE)."""
    variant: str
    sent: int
    accepted: int
    rejected: int
    error: int
    smtp_trace: tuple[str, ...]
    detail: str | None
    message_summary: tuple[str, ...] = ()
    test_id: str = ""


class ZipxxeResult(NamedTuple):
    """Result of ZIPXXE test (PTL-SVC-SMTP-ZIPXXE)."""
    manual_verification_required: bool
    canary_url: str
    variants: tuple[ZipxxeVariantResult, ...]
    elapsed_sec: float
    auth_used: bool
    detail: str | None
    verification_instructions: str
    all_rejected_at_rcpt: bool


class SpoofHeaderVariantResult(NamedTuple):
    """Result of one variant in Spoof headers test."""
    variant: str  # "from", "reply_to", "return_path"
    test_id: str
    accepted: bool
    rejected: bool
    error: bool
    smtp_status: int | None
    smtp_reply: str | None
    detail: str | None
    envelope_header_mismatch: bool  # True for "from" when MAIL FROM != From header
    smtp_trace: tuple[str, ...]


class SpoofHeaderResult(NamedTuple):
    """Result of Spoof headers test."""
    vulnerable: bool
    indeterminate: bool
    variants: tuple[SpoofHeaderVariantResult, ...]
    elapsed_sec: float
    detail: str | None
    vulnerable_note: str | None  # Blue Team: SPF/DMARC impact disclaimer


class BccTestResult(NamedTuple):
    """Result of Bcc header test – manual verification required."""
    message_accepted: bool
    smtp_status: int | None
    smtp_reply: str | None
    recipients_to: tuple[str, ...]
    recipients_cc: tuple[str, ...]
    recipients_bcc: tuple[str, ...]
    elapsed_sec: float
    detail: str | None
    verification_instructions: str
    smtp_trace: tuple[str, ...]
    test_id: str = ""


class AliasVariantResult(NamedTuple):
    """Result of one variant in Alias bypass test (PTL-SVC-SMTP-ALIAS)."""
    variant: str
    address: str
    accepted: bool
    rejected: bool
    error: bool
    smtp_status: int | None
    smtp_reply: str | None
    detail: str | None
    uucp_warning: bool  # True when bang_simple accepted – warn about UUCP/relay risk
    smtp_trace: tuple[str, ...]
    test_id: str = ""


class AliasTestResult(NamedTuple):
    """Result of Alias & Addressing bypass test (PTL-SVC-SMTP-ALIAS)."""
    base_address: str
    variants: tuple[AliasVariantResult, ...]
    elapsed_sec: float
    detail: str | None
    verification_instructions: str
    base_mail_sent: bool = False
    base_test_id: str = ""
    base_smtp_trace: tuple[str, ...] = ()


class FloodResult(NamedTuple):
    """Result of FLOOD test (PTL-SVC-SMTP-FLOOD) – queue overload, SIZE extension."""
    vulnerable: bool
    indeterminate: bool
    partial_protection: bool
    size_advertised: bool
    size_limit_bytes: int | None
    size_enforced: bool | None  # None = N/A (SIZE not advertised)
    messages_sent: int
    messages_accepted: int
    messages_rejected: int
    first_rejection_at: int | None
    tarpitting_detected: bool
    elapsed_sec: float
    smtp_trace: tuple[str, ...]
    queue_attempts: int
    flood_notes: tuple[str, ...]
    auth_used: bool
    detail: str | None
    test_id: str = ""


class BombResult(NamedTuple):
    """Result of BOMB (mail flood) test (PTL-SVC-SMTP-BOMB)."""
    vulnerable: bool
    indeterminate: bool
    partial_protection: bool  # True when server limited but only after many messages (first_rejection_at > 50)
    sent: int
    delivered: int
    rate_limited: int
    blocked: int
    connection_lost: int
    first_rejection_at: int | None
    elapsed_sec: float
    tarpitting_detected: bool
    last_error: str  # Last connection_lost error message
    last_error_type: str  # "connection_reset" | "timeout" | "broken_pipe" | "other" | ""
    avg_rtt_ms: float | None  # Average response time per message [ms]; None if no measurable samples
    smtp_trace: tuple[str, ...]
    per_message_delivered: tuple[bool, ...]  # one entry per completed attempt, in message order (1..sent)
    aborted_on_smtp_500: bool
    abort_at_message: int | None
    auth_used: bool
    detail: str | None
    sample_test_id: str = ""


@dataclass
class SMTPResults:
    blacklist: BlacklistResult | None = None
    blacklist_private_ip_skipped: bool = False  # True when target is private IP (not on public blacklists)
    spf_records: dict[str, list[str]] | None = None
    spf_error: str | None = None  # When run-all SPF test fails
    spf_requires_domain: bool = False  # True when SPF requested but target is IP
    creds: set[Creds] | None = None
    enum_results: list[EnumResult] | None = None
    enum_error: str | None = None  # When run-all enumeration fails (e.g. timeout)
    info: InfoResult | None = None
    info_error: str | None = None  # When run-all info/connect fails
    banner_requested: bool = False
    commands_requested: bool = False
    authentications_requested: bool = False
    rate_limit: RateLimitResult | None = None
    rate_limit_error: str | None = None
    noop_flood1: NoopFlood1Result | None = None
    noop_flood1_error: str | None = None
    noop_flood2: NoopFlood2Result | None = None
    noop_flood2_error: str | None = None
    ntlm: NTLMResult | None = None
    ntlm_error: str | None = None  # When run-all NTLM test fails
    open_relay: bool | None = None
    open_relay_error: str | None = None  # When run-all open relay test fails
    blacklist_error: str | None = None  # When run-all blacklist test fails
    encryption: EncryptionResult | None = None
    encryption_error: str | None = None  # When encryption test fails
    catch_all: CatchAllResult | None = None  # see CatchAllResult above
    rcpt_limit: RcptLimitResult | None = None
    rcpt_limit_error: str | None = None
    rcpt_duplicate: RcptDuplicateResult | None = None
    rcpt_duplicate_error: str | None = None
    role: RoleResult | None = None
    role_error: str | None = None  # When role identification test fails
    auth_enum: AuthEnumResult | None = None
    auth_enum_methods: tuple[AuthEnumResult, ...] | None = None
    auth_enum_ntlm_note: str | None = None
    auth_enum_error: str | None = None
    auth_format: AuthFormatProbeResult | None = None
    auth_format_error: str | None = None
    helo_validation: HeloValidationResult | None = None
    helo_validation_error: str | None = None
    auth_downgrade: AuthDowngradeResult | None = None
    auth_downgrade_error: str | None = None
    inv_comm: InvCommResult | None = None
    inv_comm_error: str | None = None
    helo_only: HeloOnlyResult | None = None
    helo_only_error: str | None = None
    helo_bypass: HeloBypassResult | None = None
    helo_bypass_error: str | None = None
    bounce_replay: BounceReplayResult | None = None
    bounce_replay_error: str | None = None
    mail_bomb: BombResult | None = None
    mail_bomb_error: str | None = None
    antivirus: AntivirusResult | None = None
    antivirus_error: str | None = None
    ssrf: SsrfResult | None = None
    ssrf_error: str | None = None
    zipxxe: ZipxxeResult | None = None
    zipxxe_error: str | None = None
    flood: FloodResult | None = None
    flood_error: str | None = None
    spoof_header: SpoofHeaderResult | None = None
    spoof_header_error: str | None = None
    bcc_test: BccTestResult | None = None
    bcc_test_error: str | None = None
    alias_test: AliasTestResult | None = None
    alias_test_error: str | None = None
    identify: "ServerIdentifyResult | None" = None
    identify_error: str | None = None
    accepted_domain_probe: AcceptedDomainProbeResult | None = None
    accepted_domain_probe_error: str | None = None


class VULNS(Enum):
    """Per-method AUTH codes kept for compatibility; JSON flat output for -A uses AuthMethods only."""
    AuthMethods = "PTV-SVC-SMTP-AUTHMETHODS"
    AuthAnonymous = "PTV-SVC-SMTP-AUTHANONYMOUS"
    AuthCramMd5 = "PTV-SVC-SMTP-AUTHCRAMMD5"
    AuthDigestMd5 = "PTV-SVC-SMTP-AUTHDIGESTMD5"
    AuthGssapi = "PTV-SVC-SMTP-AUTHGSSAPI"
    AuthKerberos = "PTV-SVC-SMTP-AUTHKERBEROS"
    AuthLogin = "PTV-SVC-SMTP-AUTHLOGIN"
    AuthNtlm = "PTV-SVC-SMTP-AUTHNTLM"
    AuthPlain = "PTV-SVC-SMTP-AUTHPLAIN"
    Banner = "PTV-SVC-BANNER"
    BigSize = "PTV-SVC-SMTP-BIGSIZE"
    Blacklist = "PTV-SVC-SMTP-BLACK"
    CmdATRN = "PTV-SVC-SMTP-COMMATRN"
    CmdDEBUG = "PTV-SVC-SMTP-COMMDEBUG"
    CmdETRN = "PTV-SVC-SMTP-COMMETRN"
    CmdEXPN = "PTV-SVC-SMTP-COMMEXPN"
    CmdSAML = "PTV-SVC-SMTP-COMMSAML"
    CmdSEND = "PTV-SVC-SMTP-COMMSEND"
    CmdSOML = "PTV-SVC-SMTP-COMMSOML"
    CmdTURN = "PTV-SVC-SMTP-COMMTURN"
    CmdVERB = "PTV-SVC-SMTP-COMMVERB"
    CmdVRFY = "PTV-SVC-SMTP-COMMVRFY"
    CryptOnly = "PTV-SVC-CRYPTONLY"
    HybridRole = "PTV-SMTP-HYBRIDROLE"
    ManyRcpt = "PTV-SVC-SMTP-MANYRCPT"
    ManyRcptReject = "PTV-SVC-SMTP-MANYRCPTREJECT"
    RcptNoCut = "PTV-SVC-SMTP-RCPTNOCUT"
    RcptDuplicate = "PTV-SVC-SMTP-RCPTDUP"
    NoStarttls = "PTV-SVC-SMTP-NOSTARTTLS"
    NTLM = "PTV-SVC-NTLMINFO"
    OpenRelay = "PTV-SVC-SMTP-RELAY"
    UserEnumAUTH = "PTV-SVC-SMTP-USRENUMAUTH"
    UserEnumEXPN = "PTV-SVC-SMTP-USRENUMEXPN"
    UserEnumVRFY = "PTV-SVC-SMTP-USRENUMVRFY"
    UserEnumRCPT = "PTV-SVC-SMTP-USRENUMRCPT"
    WeakCreds = "PTV-GENERAL-WEAKCREDENTIALS"
    HeloNoValidation = "PTV-SVC-SMTP-HELONOVAL"
    AuthDowngrade = "PTV-SVC-SMTP-DOWN"
    InvComm = "PTV-SVC-SMTP-INVCOMM"
    HeloOnly = "PTL-SVC-SMTP-HELOONLY"
    HeloBypass = "PTL-SVC-SMTP-HELO"
    BounceReplay = "PTL-SVC-SMTP-REPLAY"
    Bomb = "PTL-SVC-SMTP-BOMB"
    Antivirus = "PTL-SVC-SMTP-ANTIVIRUS"
    Ssrf = "PTL-SVC-SMTP-SSRF"
    Zipxxe = "PTL-SVC-SMTP-ZIPXXE"
    Flood = "PTL-SVC-SMTP-FLOOD"
    SpoofHeader = "PTL-SVC-SMTP-SPOOFHDR"
    BccTest = "PTL-SVC-SMTP-BCC"
    AliasBypass = "PTL-SVC-SMTP-ALIAS"
    # Rate limiting / connection-limit sub-checks (placeholder codes – will be renamed later).
    ManyConns = "PTV-SVC-SMTP-CONN"
    BanDurationShort = "PTV-SVC-SMTP-BANSHORT"
    InitialTimeoutLong = "PTV-SVC-SMTP-TOUTBANNER"
    IdleTimeoutLong = "PTV-SVC-SMTP-TOUTIDLE"
    # NOOP Flooding sub-checks (placeholder codes – will be renamed later).
    NoopFloodNoLimit = "PTV-SVC-SMTP-NOOPFLOOD"
    NoopFloodNoTrottle = "PTV-SVC-SMTP-NOOPTROT"
    NoopFloodErrors = "PTV-SVC-SMTP-NOOPERR"
    NoopFloodDosSlow = "PTV-SVC-SMTP-NOOPDOSSLOW"
    NoopFloodDosErrors = "PTV-SVC-SMTP-NOOPDOSERR"
    NoopFloodDosDropAll = "PTV-SVC-SMTP-NOOPDOSDROP"


# endregion
