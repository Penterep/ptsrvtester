"""IMAP result types, constants and vulnerability codes."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, NamedTuple

from .helpers import Creds
from .ptntlmauth.ptntlmauth import NTLMInfo

class NTLMResult(NamedTuple):
    """NTLMSSP info from AUTHENTICATE NTLM challenge (PTL-SVC-IMAP-NTLMINFO when decoded)."""
    success: bool
    ntlm: NTLMInfo | None
    auth_ntlm_advertised: bool  # AUTH=NTLM in pre-login CAPABILITY (or banner)


class InfoResult(NamedTuple):
    banner: str | None
    id: str | None
    capability: list[str] | None  # Raw list from imap.capabilities (pre-auth or post-STLS)
    capability_starttls: list[str] | None = None  # CAPABILITY after STARTTLS upgrade


class EncryptionResult(NamedTuple):
    """Result of encryption test: plaintext, STARTTLS, implicit TLS."""
    plaintext_ok: bool
    starttls_ok: bool
    tls_ok: bool


class ImapAuthMechRow(NamedTuple):
    """One AUTH= mechanism: advertised in CAPABILITY, then AUTHENTICATE probe."""

    name: str
    usable: bool
    outcome: str  # continuation | tagged_no | tagged_bad | io_error | other_response
    dangerous: bool  # IMAP_AUTH_METHOD_LEVEL ERROR (cleartext credential/SASL risk)


class ImapAuthListPath(NamedTuple):
    path: str  # cleartext | starttls | tls
    available: bool
    skip_reason: str | None
    methods: tuple[ImapAuthMechRow, ...]


class ImapAuthListResult(NamedTuple):
    """AUTHLIST: advertised AUTH= on cleartext / STARTTLS / implicit TLS."""

    paths: tuple[ImapAuthListPath, ...]
    vulnerable: bool  # dangerous mechanism usable on cleartext
    detail: str


class SniffableResult(NamedTuple):
    """
    Cleartext LOGIN + SELECT INBOX (PTV-SVC-SNIFFABLE).
    Requires a single -u/-p. Meaningful only on plain TCP (not --tls).
    """

    skipped: bool
    skip_reason: str | None
    login_ok: bool
    select_ok: bool
    select_typ: str | None
    select_detail: str | None
    vulnerable: bool
    detail: str


CatchAllResult = str  # "configured" | "not_configured" | "indeterminate" | "unreachable"

# Order of AUTHENTICATE probes when multiple mechanisms are advertised (most sensitive first).
_SNIFFABLE_AUTH_PROBE_PRIORITY = (
    "PLAIN",
    "LOGIN",
    "CRAM-MD5",
    "DIGEST-MD5",
    "NTLM",
    "GSSAPI",
    "KERBEROS_V4",
    "ANONYMOUS",
)

# Connection limits / idle: parallel ramp, idle probes.
CONN_LIMIT_DEFAULT_ATTEMPTS = 100
CONN_LIMIT_CONN_IP_THRESHOLD = 50  # finding if connected > 50; --count must be > 50 to decide
CONN_LIMIT_TIMEOUT_CAP_SECONDS = 300.0
CONN_LIMIT_PREAUTH_IDLE_MAX_OK_SEC = 60.0  # banner-only idle (compare SMTP initial timeout)
CONN_LIMIT_POST_CAP_IDLE_MAX_OK_SEC = 180.0  # after CAPABILITY (compare SMTP post-EHLO idle)
CONN_LIMIT_DURATION_RECOMMENDED_SEC = 180.0  # --duration must be > 180 to decide CAPABILITY/IDLE
CONN_LIMIT_BAN_MIN_SECONDS = 30.0
# Post-login probes (require `-u` / `-p` without wordlists)
CONN_LIMIT_AUTH_PARALLEL_MAX = 30
CONN_LIMIT_AUTH_PARALLEL_DELAY_SEC = 0.15
CONN_LIMIT_AUTH_PARALLEL_VULN_THRESHOLD = 10  # many simultaneous LOGINS ok → weak per-account limit
CONN_LIMIT_IDLE_AFTER_LOGIN_MAX_OK_SEC = 180.0  # IDLE state allowed longer than this → CONNLONG finding

_LONG_COMMAND_BODY_LEN = 8000
# EICAR standard anti-malware test file (68 bytes, https://www.eicar.org/)
_EICAR_STANDARD_LINE = (
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)
# Fixed wrong password for LOGIN user-enumeration probes (never a real credential).
_IMAP_USRENUM_DEFAULT_PASSWORD = "PtSrv_IMAP_USRENUM_!@#_2026"
_IMAP_USRENUM_MARKER_LABEL = "(fixed_wrong_password)"
# TCP + IMAP greeting; limits hangs on filtered hosts / silent packet drops (RFC-style clients often use similar bounds).
_IMAP_CONNECT_TIMEOUT_SEC = 8.0
# Authenticated resource-load probe: bounded APPEND burst + SEARCH burst (PTV-SVC-IMAP-RESLOAD).
# Safety caps only (not RFC numbers). RFC 9208: APPEND over quota → tagged NO [OVERQUOTA].
# Completing the cap with OK = missing limit; connection drop = instability; slowdown = warning.
_IMAP_LOAD_APPEND_MAX_DEFAULT = 400
_IMAP_LOAD_SEARCH_MAX_DEFAULT = 600
_IMAP_LOAD_PER_CMD_TIMEOUT_SEC = 30.0
_IMAP_LOAD_PROGRESS_APPEND_INTERVAL = 25
_IMAP_LOAD_SEARCH_INTERVAL = 50
_IMAP_LOAD_SLOWDOWN_RATIO = 1.5
_IMAP_LOAD_SLOWDOWN_MIN_DELTA_SEC = 0.1
_IMAP_LOAD_SUBJECT_PREFIX = "ptsrv-resload-"
_IMAP_LOAD_LIMIT_CODES = (
    "OVERQUOTA",
    "TOOBIG",
    "MESSAGELIMIT",
    "MAXCONVERTS",
    "LIMIT",
    "QUOTA",
)
# Post-login mailbox isolation / shared-folder hygiene (PTV-SVC-IMAP-AUTHZ-BYPASS).
# Methodology aligns with RFC 3501 (SELECT), RFC 2342 (NAMESPACE), RFC 4314/2086 (GETACL), and common
# configuration-review practice (LIST surveys, "anyone"/authenticated ACL checks — cf. Dovecot/Cyrus docs).
_IMAP_MBOX_ISO_CMD_TIMEOUT_SEC = 25.0
_IMAP_MBOX_ISO_LIST_ROOT_MAX_PARSE = 500
_IMAP_MBOX_ISO_LIST_SAMPLE = 10
_IMAP_MBOX_ISO_DICT_PROGRESS_EVERY = 3
_IMAP_MBOX_ISO_LIST_DICTIONARY_PATTERNS: tuple[str, ...] = (
    "finance/*",
    "hr/*",
    "admin/*",
    "team/*",
    "shared/*",
    "Shared/*",
    "public/*",
    "Public/*",
    "users/*",
    "user/*",
    "archive/*",
    "groups/*",
    "support/*",
    "mail/*",
    "postmaster/*",
)
_IMAP_MBOX_ISO_ENUM_MIN_TOTAL_LISTED = 15  # heuristic: many hits across guessed LIST patterns
_IMAP_MBOX_ISO_ENUM_MIN_NONZERO_PATTERNS = 3
_IMAP_MBOX_ISO_GETACL_MAX = 20
_IMAP_ACL_WORLD_IDS = frozenset({"anyone", "anonymous", "guest", "authenticated"})
_IMAP_ACL_SKIP_IDS = frozenset({"owner", "administrators", "admin", "authuser", "-authuser"})
# TLS + certificate audit (PTV-SVC-IMAP-TLSAUDIT): RFC 8996 / NIST SP 800-52r2 /
# TLSRef Intermediate cipher policy; RFC 9525 identity.
_IMAP_TLS_AUDIT_TIMEOUT_SEC = 12.0
_IMAP_TLS_EXPIRY_WARN_DAYS = 30
_IMAP_TLS_EXPIRY_VULN_DAYS = 14
_IMAP_TLS_AUDIT_SECTION_TITLE = "TLS and Certificate Audit"
_INVCOMM_READ_DEADLINE_SEC = 25.0
_INVCOMM_SLOW_BASE_SEC = 2.0
_INVCOMM_SLOW_EXTRA_SEC = 1.5
_INVCOMM_INFO_LEAK_MARKERS = (
    b"traceback",
    b"exception",
    b"/etc/",
    b"c:\\",
    b"internal server",
    b"stack trace",
    b".py",
    b".java",
    b"0x000",
    b"segmentation",
    b"assertion",
)


class InvCommImapCase(NamedTuple):
    """One invalid / malformed IMAP command probe (PTV-SVC-IMAP-INVCOMM)."""
    category: str
    command_display: str
    send_text: str
    outcome: str
    reply_snippet: str | None
    response_time_sec: float | None
    slow_response: bool
    info_leak: bool
    session_ok_after: bool | None
    probe_vulnerable: bool


class InvCommImapResult(NamedTuple):
    """Aggregate invalid-command resilience audit for IMAP."""
    tests: tuple[InvCommImapCase, ...]
    vulnerable: bool
    weakness: bool
    detail: str
    baseline_latency_sec: float | None


def conn_limit_count_verdict(
    connected: int,
    max_attempts: int,
    threshold: int = CONN_LIMIT_CONN_IP_THRESHOLD,
) -> tuple[str, str]:
    """Console category + text for the concurrent-session limit check.

    Vuln only when more than ``threshold`` sessions were accepted. If ``--count``
    is too low to prove that, return WARNING instead of a false OK/VULN.
    """
    if connected <= 0:
        return (
            "WARNING",
            "Could not open any connection. Connection limit was not tested.",
        )
    if max_attempts <= threshold and connected >= max_attempts:
        return (
            "WARNING",
            f"Cannot determine connection limit (count too low, Recommended > {threshold})",
        )
    if connected > threshold:
        return "VULN", f"Connection limit > {threshold}"
    return "NOTVULN", f"Connection limit ≤ {threshold}"


def _imap_conn_duration_display(seconds: float | None, exceeded: bool) -> str:
    """Format idle/ban durations for console / JSON (same idea as SMTP _rate_limit_duration_display)."""
    if seconds is None:
        return "N/A"
    mm = int(seconds // 60)
    ss = int(seconds % 60)
    mmss = f"{mm:02d}:{ss:02d}"
    return f"> {mmss}" if exceeded else mmss


class ImapConnLimitsResult(NamedTuple):
    """IMAP connection policy probe: concurrency ramp, idle probes, optional post-login."""

    connected: int
    max_attempts: int
    banned: bool
    establish_errors: int
    establish_disconnected: int
    establish_timeout: int
    dropped_while_idle: int
    ban_duration_probe_ran: bool
    ban_duration_seconds: float | None
    ban_duration_exceeded: bool
    preauth_idle_seconds: float | None
    preauth_idle_exceeded: bool
    post_cap_idle_seconds: float | None
    post_cap_idle_exceeded: bool
    # Optional post-login phase (same-account credentials on CLI only)
    auth_parallel_accepted: int
    auth_parallel_attempted: int
    auth_login_stopped_early: bool
    idle_logged_seconds: float | None
    idle_logged_exceeded: bool
    auth_phase_skip_reason: str | None
    idle_probe_detail: str | None
    idle_disconnected: int
    idle_disconnected_all: bool
    terminated_connections: tuple[tuple[int, str, str], ...]


class AnonymousLoginProbe(NamedTuple):
    """One LOGIN probe (anonymous / guest / public, empty or matching password)."""

    username: str
    password: str
    accepted: bool
    detail: str | None = None


class AnonymousAccessResult(NamedTuple):
    """Anonymous / pseudo-anonymous IMAP access (SASL ANONYMOUS, LOGIN patterns)."""
    auth_anonymous_advertised: bool
    authenticate_anonymous_ok: bool
    login_anonymous_empty_ok: bool
    weak_credentials_ok: tuple[str, ...]  # e.g. "guest / guest"
    vulnerable: bool
    detail: str
    auth_probed: bool
    login_probed: bool
    authenticate_detail: str | None = None
    login_attempts: tuple[AnonymousLoginProbe, ...] = ()


class EicarVariantResult(NamedTuple):
    """One EICAR APPEND payload (plain body, .com/.txt attachment, or ZIP)."""

    label: str
    append_typ: str | None
    append_detail: str | None
    accepted: bool


class EicarAppendResult(NamedTuple):
    """APPEND EICAR variants (PTV-SVC-IMAP-EICAR when any payload is accepted)."""
    skipped: bool
    skip_reason: str | None
    mailbox: str
    append_typ: str | None
    append_detail: str | None
    vulnerable: bool
    variants: tuple[EicarVariantResult, ...] = ()


# Same titles / payload filenames as SMTP ZIPXXE (terminal + JSON stay aligned).
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


class ZipxxeVariantResult(NamedTuple):
    """One ZIPXXE APPEND variant (PTL-SVC-IMAP-ZIPXXE; manual verification)."""
    variant: str
    sent: int
    accepted: int
    rejected: int
    error: int
    imap_trace: tuple[str, ...]
    detail: str | None
    test_id: str = ""


class ZipxxeResult(NamedTuple):
    """ZIPXXE via APPEND: zip bomb / Billion Laughs / XXE (PTL-SVC-IMAP-ZIPXXE)."""
    manual_verification_required: bool
    canary_url: str
    mailbox: str
    variants: tuple[ZipxxeVariantResult, ...]
    elapsed_sec: float
    auth_used: bool
    detail: str | None
    verification_instructions: str
    all_rejected_at_append: bool


class ImapResourceLoadPhase(NamedTuple):
    """One phase of the bounded APPEND / SEARCH resource probe."""

    label: str  # APPEND | SEARCH
    attempted: int
    ok: int
    failed: int
    limited: int
    disconnected: bool
    disconnect_after: int | None
    hit_cap: bool
    limit_enforced: bool
    limit_code: str | None
    limit_after: int | None
    min_rt_seconds: float | None
    max_rt_seconds: float | None
    avg_rt_seconds: float | None
    baseline_avg_seconds: float | None
    last_window_avg_seconds: float | None
    slowdown: bool
    error_rate_pct: float


class ImapResourceLoadResult(NamedTuple):
    """Bounded authenticated APPEND + SEARCH resource-limit check (PTV-SVC-IMAP-RESLOAD)."""

    skipped: bool
    skip_reason: str | None
    mailbox: str
    append_max_requested: int
    search_max_requested: int
    append: ImapResourceLoadPhase | None
    search: ImapResourceLoadPhase | None
    search_skipped_reason: str | None
    quota_advertised: bool
    quota_root_detail: str | None
    cleanup_deleted: int | None
    cleanup_detail: str | None
    vulnerable: bool
    detail: str
    io_login: tuple[str, str] | None = None
    io_select: tuple[str, str] | None = None
    io_capability: tuple[str, str] | None = None
    io_quota: tuple[tuple[str, str], ...] = ()
    io_append: tuple[str, str] | None = None
    io_search: tuple[str, str] | None = None
    io_cleanup: tuple[str, str] | None = None


class ImapMailboxIsoSelectRow(NamedTuple):
    """One EXAMINE probe after LOGIN (read-only open; PTV-SVC-IMAP-AUTHZ-BYPASS)."""

    probe_id: str
    mailbox: str
    typ: str | None
    detail: str | None
    ok_selected: bool
    send_text: str | None = None
    recv_text: str | None = None


class ImapMailboxIsoListSurveyRow(NamedTuple):
    """LIST reference + pattern survey (namespace / shared-folder discovery)."""

    reference: str
    pattern: str
    typ: str | None
    detail: str | None
    listed_count: int
    sample_mailboxes: tuple[str, ...]
    send_text: str | None = None
    recv_text: str | None = None


class ImapMailboxIsoAclRow(NamedTuple):
    """GETACL on one mailbox (own INBOX or a LIST-discovered folder)."""

    mailbox: str
    typ: str | None
    anyone_rights: str | None
    anonymous_rights: str | None
    authenticated_rights: str | None
    overbroad_world: bool
    user_like_ids: tuple[str, ...]
    raw: str | None
    send_text: str | None = None
    recv_text: str | None = None


class ImapMailboxIsoResult(NamedTuple):
    """
    Authenticated checks for cross-mailbox access, ACL hygiene, LIST/NAMESPACE surface (PTV-SVC-IMAP-AUTHZ-BYPASS).
    """

    skipped: bool
    skip_reason: str | None
    own_mailbox: str
    foreign_user_token: str
    login_username: str
    acl_in_capability: bool
    namespace_typ: str | None
    namespace_raw: str | None
    get_acl_typ: str | None
    get_acl_raw: str | None
    acl_anyone_rights: str | None
    acl_anonymous_rights: str | None
    acl_authenticated_rights: str | None
    acl_overbroad_world: bool
    list_root_typ: str | None
    list_root_count: int
    list_root_truncated: bool
    list_root_sample: tuple[str, ...]
    foreign_like_mailbox_visible_in_root_list: bool
    select_probes: tuple[ImapMailboxIsoSelectRow, ...]
    list_dictionary: tuple[ImapMailboxIsoListSurveyRow, ...]
    list_dictionary_total_listed: int
    list_dictionary_nonzero_patterns: int
    enumeration_signal: bool
    foreign_examine_ok: bool
    vulnerable: bool
    detail: str
    acl_folder_probes: tuple[ImapMailboxIsoAclRow, ...] = ()
    acl_enumerated_users: tuple[str, ...] = ()
    getacl_command_ok: bool = False
    login_send: str | None = None
    login_recv: str | None = None
    select_own_send: str | None = None
    select_own_recv: str | None = None
    namespace_send: str | None = None
    namespace_recv: str | None = None
    list_root_send: str | None = None
    list_root_recv: str | None = None


class ImapTlsCipherOffer(NamedTuple):
    """One cipher suite the server accepted for a TLS version."""

    name: str
    rating: str  # ok | warn | bad
    reason: str


class ImapTlsVersionScan(NamedTuple):
    """Offered TLS protocol version and the cipher suites accepted under it."""

    version: str  # TLS 1.0 / TLS 1.1 / TLS 1.2 / TLS 1.3
    offered: bool
    rating: str  # ok | warn | bad
    rating_reason: str
    cipher_order: str | None  # server | client | mixed | None
    cipher_order_note: str | None
    ciphers: tuple[ImapTlsCipherOffer, ...]


class ImapTlsAuditProbeResult(NamedTuple):
    """One TLS path (implicit TLS or STARTTLS), PTV-SVC-IMAP-TLSAUDIT."""

    mode: str  # implicit_tls | starttls
    attempted: bool
    skipped_reason: str | None
    starttls_advertised: bool | None  # meaningful for starttls mode; None for implicit_tls
    handshake_ok: bool
    handshake_error: str | None
    tls_version: str | None
    cipher_name: str | None
    cipher_protocol: str | None
    peer_subject: str | None
    peer_issuer: str | None
    san_dns: tuple[str, ...]
    not_before: str | None
    not_after: str | None
    days_until_expiry: int | None
    cert_expired: bool
    cert_not_yet_valid: bool
    weak_tls_version: bool
    weak_cipher: bool
    expires_within_vuln_days: bool
    expires_within_warn_days: bool
    peer_key_summary: str | None
    peer_signature_hash: str | None
    crypto_warnings: tuple[str, ...]
    versions: tuple[ImapTlsVersionScan, ...] = ()
    imap_trace: tuple[str, ...] = ()
    identity_ok: bool = False
    identity_detail: str | None = None
    identity_wildcard: bool = False
    cert_trust_ok: bool = False
    connection_mode: str = "No certificate"


class ImapTlsAuditResult(NamedTuple):
    """Strict TLS / X.509 posture for IMAP (PTV-SVC-IMAP-TLSAUDIT)."""

    host: str
    port: int
    implicit_tls_intended: bool
    probes: tuple[ImapTlsAuditProbeResult, ...]
    vulnerable: bool
    detail: str


class ImapUserEnumProbeRow(NamedTuple):
    """One LOGIN attempt with a fixed wrong password (PTV-SVC-IMAP-USRENUM)."""

    username: str
    probe_kind: str  # wordlist | control_invalid
    reply_raw: str | None
    reply_normalized: str | None
    elapsed_ms: float | None
    unexpected_ok: bool  # LOGIN succeeded with wrong password
    error: str | None
    probe_index: int


class ImapUserEnumResult(NamedTuple):
    """Username enumeration assessment (LOGIN or AUTHENTICATE PLAIN + fixed wrong password)."""

    probes: tuple[ImapUserEnumProbeRow, ...]
    invalid_baseline_normalized: tuple[str, ...]
    enumerated_usernames: tuple[str, ...]
    vulnerable: bool
    indeterminate: bool
    detail: str
    wrong_password_marker: str
    login_disabled_advertised: bool  # LOGINDISABLED in CAPABILITY / banner (RFC 3501)
    enumeration_method: str  # "LOGIN" | "AUTHENTICATE PLAIN"
    auth_plain_advertised: bool  # AUTH=PLAIN in merged pre-auth CAPABILITY / banner


# ─── NOOP Connection Limit Tests ──────────────────────────────────────────────
# IMAP4rev2: 30-minute minimum autologout for authenticated sessions; servers may
# use shorter pre-auth timeouts for DoS protection. Pre-auth limits should be stricter.
# Note: IDLE is distinct from NOOP — IDLE is for waiting on mailbox changes; NOOP
# is a normal command that can reset the inactivity timer.

# Pre-authentication duration test (NOOPLIM1)
IMAP_NOOP_PREAUTH_DUR_TEST_SECONDS = 35 * 60  # Test for 35 minutes (captures "high" threshold)
IMAP_NOOP_PREAUTH_DUR_INTERVAL_SECONDS = 4 * 60  # Send NOOP every 4 minutes (shorter pre-auth for DoS protection)
IMAP_NOOP_PREAUTH_DUR_TIMEOUT_SECONDS = 30    # Socket recv timeout

# Pre-authentication duration thresholds (in seconds)
IMAP_NOOP_PREAUTH_DUR_INCREASED_MIN = 5 * 60   # >5 min → increased
IMAP_NOOP_PREAUTH_DUR_SIGNIFICANT_MIN = 10 * 60 # >10 min → significant
IMAP_NOOP_PREAUTH_DUR_HIGH_MIN = 30 * 60       # >30 min → high

# NOOP1 timing: throttling if last-window avg is ≥ 0.1s slower than baseline.
NOOP1_SLOWDOWN_MIN_DELTA_SECONDS = 0.1
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
IMAP_NOOP_PREAUTH_CONN_TEST_SECONDS = 120     # Hold connections for 2 minutes
IMAP_NOOP_PREAUTH_CONN_INTERVAL_SECONDS = 60  # Send NOOP every minute (short interval for connection count test)
IMAP_NOOP_PREAUTH_CONN_TIMEOUT_SECONDS = 30
IMAP_NOOP_PREAUTH_CONN_MAX_ATTEMPTS = 150     # Try up to 150 connections (safety cap)

# CLI default for --count
NOOP2_DEFAULT_CONNECTIONS = IMAP_NOOP_PREAUTH_CONN_MAX_ATTEMPTS

# Pre-authentication connection count thresholds
IMAP_NOOP_PREAUTH_CONN_INCREASED_MIN = 20     # >20 connections → increased
IMAP_NOOP_PREAUTH_CONN_SIGNIFICANT_MIN = 50   # >50 connections → significant
IMAP_NOOP_PREAUTH_CONN_HIGH_MIN = 100         # >100 connections → high

# Post-authentication duration test (NOOPLIM3)
IMAP_NOOP_POSTAUTH_DUR_TEST_SECONDS = 130 * 60 # Test for 130 minutes (captures "high" threshold)
IMAP_NOOP_POSTAUTH_DUR_INTERVAL_SECONDS = 20 * 60  # Send NOOP every 20 minutes (RFC: 30min minimum timeout)
IMAP_NOOP_POSTAUTH_DUR_TIMEOUT_SECONDS = 30

# Post-authentication duration thresholds (in seconds)
IMAP_NOOP_POSTAUTH_DUR_INCREASED_MIN = 60 * 60  # >60 min → increased
IMAP_NOOP_POSTAUTH_DUR_SIGNIFICANT_MIN = 120 * 60 # >120 min → significant
IMAP_NOOP_POSTAUTH_DUR_HIGH_MIN = 180 * 60      # >180 min (unlimited) → high

# Post-authentication connection count test (NOOPLIM4)
IMAP_NOOP_POSTAUTH_CONN_TEST_SECONDS = 180
IMAP_NOOP_POSTAUTH_CONN_INTERVAL_SECONDS = 60  # Send NOOP every minute (short interval for connection count test)
IMAP_NOOP_POSTAUTH_CONN_TIMEOUT_SECONDS = 30
IMAP_NOOP_POSTAUTH_CONN_MAX_ATTEMPTS = 600    # Try up to 600 connections (safety cap)

# Post-authentication connection count thresholds (per IP)
IMAP_NOOP_POSTAUTH_CONN_IP_INCREASED_MIN = 50
IMAP_NOOP_POSTAUTH_CONN_IP_SIGNIFICANT_MIN = 100
IMAP_NOOP_POSTAUTH_CONN_IP_HIGH_MIN = 500

# Post-authentication connection count thresholds (per account)
IMAP_NOOP_POSTAUTH_CONN_ACCT_INCREASED_MIN = 20
IMAP_NOOP_POSTAUTH_CONN_ACCT_SIGNIFICANT_MIN = 50
IMAP_NOOP_POSTAUTH_CONN_ACCT_HIGH_MIN = 100


class NoopDurationResult(NamedTuple):
    """NOOP connection duration test: keep one connection alive with periodic NOOP."""
    authenticated: bool                # Pre-auth (False) or post-auth (True)
    test_duration_seconds: float       # How long the test was configured to run
    maintained_seconds: float          # How long the connection actually stayed alive
    noops_sent: int                    # Number of NOOPs successfully sent
    noops_ok: int                      # Number of OK replies
    noops_error: int                   # Number of NO/BAD or timeout/socket errors
    disconnected: bool                 # True if server closed the connection
    disconnect_after_seconds: float | None  # When the disconnect happened
    hit_test_cap: bool                 # True if we reached the test duration limit
    error_message: str | None          # Error detail if test failed to start
    delay_seconds: float = 0.0
    min_rt_seconds: float | None = None
    max_rt_seconds: float | None = None
    avg_rt_seconds: float | None = None
    baseline_avg_seconds: float | None = None
    last_window_avg_seconds: float | None = None
    slowdown_detected: bool = False
    error_rate_pct: float = 0.0
    idle_disconnect: bool = False


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
        slowdown = (last_window_avg - baseline_avg) >= NOOP1_SLOWDOWN_MIN_DELTA_SECONDS
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


@dataclass
class IMAPResults:
    info: InfoResult | None = None
    info_error: str | None = None  # When connect/info fails
    banner_requested: bool = False
    commands_requested: bool = False
    anonymous: AnonymousAccessResult | None = None
    ntlm: NTLMResult | None = None
    creds: set[Creds] | None = None
    encryption: EncryptionResult | None = None
    encryption_error: str | None = None
    sniffable: SniffableResult | None = None
    sniffable_error: str | None = None
    imap_authlist: ImapAuthListResult | None = None
    imap_authlist_error: str | None = None
    inv_comm: InvCommImapResult | None = None
    inv_comm_error: str | None = None
    catch_all: CatchAllResult | None = None
    conn_limits: "ImapConnLimitsResult | None" = None
    conn_limits_error: str | None = None
    eicar: EicarAppendResult | None = None
    zipxxe: ZipxxeResult | None = None
    zipxxe_error: str | None = None
    imap_usrenum: ImapUserEnumResult | None = None
    imap_usrenum_error: str | None = None
    imap_usrenum_plain: ImapUserEnumResult | None = None
    imap_usrenum_plain_error: str | None = None
    imap_resource_load: ImapResourceLoadResult | None = None
    imap_resource_load_error: str | None = None
    imap_mailbox_iso: ImapMailboxIsoResult | None = None
    imap_mailbox_iso_error: str | None = None
    imap_tls_audit: ImapTlsAuditResult | None = None
    imap_tls_audit_error: str | None = None
    noop_duration_preauth: NoopDurationResult | None = None
    noop_duration_preauth_error: str | None = None
    noop_conn_count_preauth: NoopConnectionCountResult | None = None
    noop_conn_count_preauth_error: str | None = None
    noop_duration_postauth: NoopDurationResult | None = None
    noop_duration_postauth_error: str | None = None
    noop_conn_count_postauth: NoopConnectionCountResult | None = None
    noop_conn_count_postauth_error: str | None = None


class VULNS(Enum):
    Anonymous = "PTL-SVC-IMAP-ANONYMOUS"
    NTLM = "PTL-SVC-IMAP-NTLMINFO"
    WeakCreds = "PTV-GENERAL-WEAKCREDENTIALS"
    AuthMethods = "PTV-SVC-IMAP-AUTHMETHODS"
    Sniffable = "PTV-SVC-SNIFFABLE"
    InvComm = "PTV-SVC-IMAP-INVCOMM"
    ConnCntIp = "PTV-SVC-IMAP-CONNCNTIP"
    ConnCntGlob = "PTV-SVC-IMAP-CONNCNTGLOB"
    ConnLong = "PTV-SVC-IMAP-CONNLONG"
    ConnRate = "PTV-SVC-IMAP-CONNRATE"
    Eicar = "PTV-SVC-IMAP-EICAR"
    Zipxxe = "PTL-SVC-IMAP-ZIPXXE"
    UserEnumLogin = "PTV-SVC-IMAP-USRENUM"
    ResourceLoad = "PTV-SVC-IMAP-RESLOAD"
    AuthzBypass = "PTV-SVC-IMAP-AUTHZ-BYPASS"
    TlsAudit = "PTV-SVC-IMAP-TLSAUDIT"
    NoopDurationPreauth = "PTV-SVC-IMAP-NOOPLIMDUR-PREAUTH"
    NoopDurationPostauth = "PTV-SVC-IMAP-NOOPLIMDUR-POSTAUTH"
    NoopConnCountPreauth = "PTV-SVC-IMAP-NOOPLIMCONN-PREAUTH"
    NoopConnCountPostauth = "PTV-SVC-IMAP-NOOPLIMCONN-POSTAUTH"


