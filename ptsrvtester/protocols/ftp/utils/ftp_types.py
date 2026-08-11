"""FTP result types, constants and vulnerability codes."""
from __future__ import annotations

import collections
import ftplib
import ipaddress
import posixpath
import random
import re
import secrets
import select
import socket
import ssl
import statistics
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from difflib import SequenceMatcher
from enum import Enum
from io import BytesIO
from ssl import SSLSocket
from string import ascii_uppercase
from typing import NamedTuple

from .helpers import Creds, Target, valid_target, vendor_from_cpe, get_mode, text_or_file
from .service_identification import identify_service

EICAR_STANDARD_TEST_FILE = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)

# FTP processing-resilience: warn if control channel stays quiet too long after last data byte → 226, or NOOP is slow.
FTP_DOS_DELTA_WARN_SEC = 2.0
FTP_DOS_NOOP_WARN_SEC = 3.0
FTP_DOS_POLICY_BLOCK_CODES = frozenset({450, 451, 452, 550, 551, 552, 553, 554})


class TestFailedError(Exception):
    """Custom exception for run-all mode: test failed but continue with next test."""
    pass


class InvCmdAuditSetupError(Exception):
    """Invalid-command audit failed before probes (e.g. TLS wrap on --tls / --starttls)."""

    def __init__(
        self,
        message: str,
        *,
        tls_handshake_hint: str | None = None,
        obsolete_tls_suspected: bool = False,
    ):
        super().__init__(message)
        self.tls_handshake_hint = tls_handshake_hint
        self.obsolete_tls_suspected = obsolete_tls_suspected


def valid_target_ftp(target: str) -> Target:
    """Argparse helper: IP or hostname with optional port (like SMTP)."""
    return valid_target(target, domain_allowed=True)


def valid_target_bounce(target: str) -> Target:
    """Argparse helper: IP:PORT or HOST:PORT for bounce target."""
    return valid_target(target, port_required=True, domain_allowed=True)


def nop_callback(_: str):
    """RETR callback helper"""
    pass


def _ftp_list_line_directory_rel_name(line: str) -> str | None:
    """
    Relative directory name from a Unix-style FTP LIST row (drwx…).
    Supports:
      - "... Mon DD  YYYY name" / "... Mon DD YYYY name" (year = 4 digits)
      - "... Mon DD HH:MM name" (time contains ':')
      - legacy "... timestamp with single ':' ... name" heuristic (narrow case)
    """
    stripped = (line or "").rstrip("\r\n")
    if len(stripped) < 11 or stripped[0] != "d":
        return None
    parts = stripped.split()
    if len(parts) >= 9:
        tok7 = parts[7]
        if len(tok7) == 4 and tok7.isdigit():
            cand = " ".join(parts[8:]).strip()
            return cand or None
        if ":" in tok7:
            cand = " ".join(parts[8:]).strip()
            return cand or None
    if ":" not in stripped:
        return None
    try:
        after_colon = stripped.split(":", 1)[1]
        remainder = after_colon.split(None, 1)
        if len(remainder) < 2:
            return None
        return remainder[1].strip() or None
    except Exception:
        return None


# endregion


# region helper classes


class AccessCheckHelper:
    def __init__(self):
        self.lines_read: list[str] | None = None

    def read_callback(self, line: str) -> None:
        """LIST callback helper"""
        if self.lines_read is None:
            self.lines_read = []

        self.lines_read.append(line)


# inspired by https://stackoverflow.com/questions/12164470/python-ftp-implicit-tls-connection-issue
class FTP_TLS_implicit(ftplib.FTP_TLS):
    """Helper class for implicit TLS"""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._sock = None

    @property
    def sock(self):
        return self._sock

    @sock.setter
    def sock(self, value):
        if not isinstance(value, SSLSocket):
            self._sock = self.context.wrap_socket(value)
        else:
            self._sock = value


# endregion


# region data classes
class BounceRequestResult(NamedTuple):
    ftpserver_filepath: str
    stored: bool
    uploaded: bool
    cleaned: bool


class BounceResult(NamedTuple):
    target: Target
    used_creds: Creds | None
    bounce_accepted: bool | None
    port_accessible: bool | None
    request: BounceRequestResult | None


@dataclass
class AccessPermissions:
    creds: Creds
    dirlist: list[str] | None = None
    write: str | None = None
    read: str | None = None
    delete: str | None = None


class AccessCheckResult(NamedTuple):
    errors: list[str] | None
    results: list[AccessPermissions] | None


class FtpEicarRow(NamedTuple):
    """One account’s EICAR upload / post-upload verification (PTL-SVC-FTP-ANTIVIRUS)."""

    creds: Creds
    remote_path: str
    stor_ok: bool
    stor_error: str | None
    post_stor_delay_seconds: float
    size_bytes: int | None
    size_error: str | None
    retr_ok: bool
    retr_payload_match: bool | None
    retr_error: str | None
    vanished_after_stor_suspected: bool
    on_access_scan_suspected: bool
    delete_ok: bool
    delete_error: str | None
    delete_note: str | None


class FtpEicarAuditResult(NamedTuple):
    """Aggregate EICAR / on-access probe result."""

    post_stor_delay_seconds: float
    rows: tuple[FtpEicarRow, ...]
    detail: str
    risky_content_reachable: bool
    upload_blocked_all: bool


class FtpStorTimingOutcome(NamedTuple):
    """STOR timing slice: totals and delay from last client data byte to final control reply (usually 226)."""

    ok: bool
    error: str | None
    reply_code: int | None
    reply_line: str | None
    total_seconds: float | None
    delta_last_byte_to_226_seconds: float | None
    timed_out: bool


class FtpDosProbeRow(NamedTuple):
    """One payload in the FTP processing-resilience session (PTL-SVC-FTP-PROC-DOS)."""

    probe_label: str
    remote_filename: str
    payload_bytes: int
    stor_ok: bool
    stor_error: str | None
    stor_reply_snippet: str | None
    reply_code: int | None
    total_transfer_seconds: float | None
    delta_last_byte_to_226_seconds: float | None
    noop_ok: bool | None
    noop_error: str | None
    noop_elapsed_seconds: float | None
    blocked_by_policy: bool
    background_processing_suspected: bool
    timed_out: bool
    delete_ok: bool
    delete_error: str | None


class FtpDosAuditResult(NamedTuple):
    """Single-session XML + ZIP processing stress (default minimal zip; optional full bomb)."""

    timeout_seconds: float
    zip_mode: str
    creds_user: str
    probes: tuple[FtpDosProbeRow, ...]
    detail: str
    post_processing_dos_suspected: bool
    all_blocked_by_policy: bool


class InfoResult(NamedTuple):
    banner: str | None
    help_response: str | None  # HELP command output (list of supported commands)
    syst: str | None
    stat: str | None


class EncryptionResult(NamedTuple):
    """Result of encryption test: plaintext, AUTH TLS (explicit), implicit TLS."""
    plaintext_ok: bool
    auth_tls_ok: bool
    tls_ok: bool


class ModesResult(NamedTuple):
    """Result of passive/active mode availability test."""
    passive_ok: bool
    active_ok: bool
    pasv_ip_leak: str | None = None  # leaked internal IP from 227 if differs from target


class ActiveAuditStep(NamedTuple):
    """Single step in PTL-SVC-FTP-ACTIVE (PORT/PASV policy) audit."""

    phase: str  # preAuth | postAuth
    name: str
    command: str
    reply: str
    code: int | None = None
    note: str | None = None
    interpretation: str | None = None
    list_reply: str | None = None
    list_code: int | None = None


class ActiveAuditResult(NamedTuple):
    """PORT/PASV policy audit (PTL-SVC-FTP-ACTIVE)."""

    steps: tuple[ActiveAuditStep, ...]
    post_auth_ran: bool
    foreign_ip_accepted: bool
    low_port_accepted: bool
    list_after_own_port_ok: bool | None
    low_ports_accepted: tuple[int, ...]  # ports <1000 that got 200 on PORT
    full_audit: bool


class CmdAuditRisk(NamedTuple):
    """Single risky capability (PTL-SVC-FTP-CMD)."""

    tier: str  # critical | high | medium
    token: str
    source: str


class CommandAuditResult(NamedTuple):
    """HELP/FEAT/SITE command surface audit (PTL-SVC-FTP-CMD)."""

    help_pre_auth: str
    feat_response: str
    site_help_pre: str | None
    site_help_all_pre: str | None
    site_help_post: str | None
    site_help_all_post: str | None
    feat_features: tuple[str, ...]
    matched_risks: tuple[CmdAuditRisk, ...]
    response_truncated: bool
    site_help_all_pre_error: str | None = None
    site_help_all_post_error: str | None = None


class CmdActiveProbeResult(NamedTuple):
    """One active SITE probe (PTL-SVC-FTP-CMD active phase)."""

    probe_id: str
    command_sent: str
    reply_code: int | None
    reply_line: str
    classification: str
    advertised_in_passive_audit: bool
    error: str | None


class CommandAuditActiveResult(NamedTuple):
    """Active SITE probes after passive cmd audit; requires login + writable STOR."""

    probe_timeout_seconds: float
    probe_file: str | None
    cleanup_ok: bool
    cleanup_error: str | None
    probes: tuple[CmdActiveProbeResult, ...]
    setup_error: str | None = None


class InvalidCmdProbeResult(NamedTuple):
    """One raw-line probe (PTL-SVC-FTP-INVCOMM); bytes sent on wire, not via ftplib."""

    phase: str
    probe_id: str
    intent_label: str
    bytes_line_hex: str
    line_sent_preview: str
    reply_code: int | None
    reply_text: str
    classification: str
    connection_ok_after: bool
    error: str | None
    follow_up_command: str | None = None
    follow_up_reply_code: int | None = None
    follow_up_reply_snippet: str | None = None
    null_byte_outcome: str | None = None


class InvalidCmdSessionResult(NamedTuple):
    """preAuth or postAuth invalid-command session."""

    phase: str
    probes: tuple[InvalidCmdProbeResult, ...]
    resilience_rating: str
    null_byte_truncation_suspected: bool
    had_connection_drop: bool


class InvalidCmdAuditResult(NamedTuple):
    """Invalid / non-standard FTP command resilience audit (PTL-SVC-FTP-INVCOMM)."""

    probe_timeout_seconds: float
    pre_auth: InvalidCmdSessionResult | None
    post_auth: InvalidCmdSessionResult | None
    overall_resilience_rating: str
    null_byte_truncation_suspected: bool
    setup_error: str | None = None
    post_auth_login_error: str | None = None
    tls_handshake_hint: str | None = None
    obsolete_tls_suspected: bool = False


@dataclass
class PathEnumResult:
    """Result of path enumeration (dictionary attack): found path with type and optional size."""
    path: str
    exists: bool
    is_directory: bool | None  # True=CWD ok, False=SIZE ok (file), None=unknown
    size: int | None  # for files when SIZE succeeds


@dataclass
class FtpUserEnumProbeRow:
    """One USER/PASS probe for PTL-SVC-FTP-USRENUM."""

    username: str
    probe_kind: str  # wordlist | control_random | control_long | control_special
    user_reply_code: int | None
    user_reply_line: str
    pass_reply_code: int | None
    pass_reply_line: str
    pass_elapsed_ms: float | None
    connection_ok_after: bool
    error: str | None
    probe_index: int = 0


@dataclass
class FtpUserEnumResult:
    """FTP username enumeration assessment (RFC 2577 alignment)."""

    probes: tuple[FtpUserEnumProbeRow, ...]
    fixed_password_marker: str  # never the real password in JSON
    distinct_user_reply_codes: tuple[int, ...]
    distinct_pass_reply_norms: tuple[str, ...]
    enumeration_suspected: bool
    timing_anomaly_suspected: bool
    pass_text_similarity_min: float | None  # pairwise min of max(raw, template) SequenceMatcher
    detail: str
    timing_notes: tuple[str, ...] = ()
    timing_control_median_ms: float | None = None
    timing_wordlist_median_ms: float | None = None
    timing_slow_usernames_ms: tuple[tuple[str, float], ...] = ()


@dataclass
class PasvPortRangeProbe:
    """One sample in PTL-SVC-FTP-PASIVE passive data-port spread check."""

    sample_index: int
    data_port: int | None
    error: str | None


@dataclass
class PasvPortRangeResult:
    """
    Repeated PASV + LIST samples on separate control sessions (PTL-SVC-FTP-PASIVE).
    wide_passive_range: observed max-min across successful samples exceeds threshold
    (firewall-unfriendly spread in this run).
    """

    probes: tuple[PasvPortRangeProbe, ...]
    successful_ports: tuple[int, ...]
    min_port: int | None
    max_port: int | None
    observed_span: int | None
    max_span_threshold: int
    min_samples_for_verdict: int
    wide_passive_range: bool
    inconclusive: bool
    detail: str


@dataclass
class ConnLimitsParallelOutcome:
    """Parallel pre-auth control connections (PTL-SVC-FTP-CONN)."""

    attempted: int
    succeeded: int
    failed: int
    error_samples: tuple[str, ...]


@dataclass
class ConnLimitsSequentialOutcome:
    """Rapid sequential control connections."""

    attempts: int
    succeeded: int
    failed: int
    inter_connect_delay_ms: float
    error_samples: tuple[str, ...]


@dataclass
class ConnLimitsPasvSpam:
    """Repeated PASV on one control session without data transfer."""

    attempts: int
    reply227: int
    reply530: int
    reply_other: int
    last_reply_snippet: str | None
    error: str | None


@dataclass
class ConnLimitsIdleProbe:
    """Idle / slow-control behaviour."""

    performed: bool
    wait_seconds: float
    kick_observed: bool  # 421/426 or EOF while idle
    note: str


@dataclass
class ConnLimitsSlowAuth:
    """USER … long wait … PASS (wrong password)."""

    performed: bool
    gap_seconds: float
    still_connected_after_pass: bool | None
    pass_reply_snippet: str | None
    note: str


@dataclass
class ConnLimitsAuditResult:
    """
    Connection / rate / idle limits observation (PTL-SVC-FTP-CONN).
    limits_insufficient_suspected: heuristic from bounded probes — not full DoS.
    """

    crypto_mode: str  # plain | implicit_tls | starttls
    parallel: ConnLimitsParallelOutcome
    sequential: ConnLimitsSequentialOutcome
    pasv_pre_auth: ConnLimitsPasvSpam
    pasv_post_auth: ConnLimitsPasvSpam | None
    idle_pre_auth: ConnLimitsIdleProbe
    slow_auth: ConnLimitsSlowAuth
    idle_post_auth: ConnLimitsIdleProbe | None
    limits_insufficient_suspected: bool
    risk_factors: tuple[str, ...]
    detail: str


def _conn_limits_parallel_suspect(par: ConnLimitsParallelOutcome) -> bool:
    return par.attempted >= 10 and par.failed == 0 and par.succeeded == par.attempted


def _conn_limits_sequential_suspect(seq: ConnLimitsSequentialOutcome) -> bool:
    return seq.attempts >= 20 and seq.failed == 0 and seq.succeeded == seq.attempts


def _conn_limits_pasv_pre_suspect(pp: ConnLimitsPasvSpam) -> bool:
    return pp.attempts >= 15 and pp.reply227 >= 14 and pp.error is None


def _conn_limits_pasv_post_suspect(po: ConnLimitsPasvSpam | None) -> bool:
    if po is None:
        return False
    return po.attempts >= 15 and po.reply227 >= 14 and po.error is None


def _conn_limits_idle_pre_suspect(ipr: ConnLimitsIdleProbe) -> bool:
    return ipr.performed and ipr.wait_seconds >= 60.0 and not ipr.kick_observed


def _conn_limits_slow_auth_suspect(sa: ConnLimitsSlowAuth) -> bool:
    return sa.performed and sa.gap_seconds >= 40.0 and sa.still_connected_after_pass is True


def _conn_limits_idle_post_suspect(ipo: ConnLimitsIdleProbe | None) -> bool:
    return (
        ipo is not None
        and ipo.performed
        and ipo.wait_seconds >= 60.0
        and not ipo.kick_observed
        and "NOOP succeeded" in ipo.note
    )


@dataclass
class ChrootCwdProbeRow:
    """Single CWD probe after fresh login (PTL-SVC-FTP-CHROOT)."""

    probe_id: str
    path: str
    success: bool
    pwd_after: str | None
    error_or_reply: str | None


@dataclass
class ChrootDotdotResult:
    """Repeated CWD .. from post-login directory."""

    steps_ok: int
    pwd_initial: str
    pwd_final: str | None
    stopped_reason: str


@dataclass
class ChrootAuditResult:
    """
    User isolation / chroot-style checks: absolute CWD targets, .. chain, /etc/passwd SIZE.
    isolation_broken_suspected: heuristic; chroot with jail root '/' may still false-negative/positive — confirm manually.
    """

    pwd_initial: str
    cwd_probes: tuple[ChrootCwdProbeRow, ...]
    dotdot: ChrootDotdotResult
    home_parent_accessible: bool
    system_paths_accessible: tuple[str, ...]
    passwd_size_ok: bool
    shadow_size_ok: bool
    dotdot_parent_escape_suspected: bool
    isolation_broken_suspected: bool
    detail: str
    passwd_size_bytes: int | None = None
    shadow_size_bytes: int | None = None


@dataclass
class FTPResults:
    info: InfoResult | None = None
    info_error: str | None = None  # When run-all info/connect fails
    banner_requested: bool = False
    commands_requested: bool = False
    access: AccessCheckResult | None = None
    access_error: str | None = None  # When run-all access check fails
    anonymous: bool | None = None
    anonymous_error: str | None = None  # When run-all anonymous test fails
    creds: set[Creds] | None = None
    bounce: BounceResult | None = None
    encryption: EncryptionResult | None = None
    encryption_error: str | None = None
    path_enum: list[PathEnumResult] | None = None
    path_enum_error: str | None = None
    modes: ModesResult | None = None
    modes_error: str | None = None
    active_audit: ActiveAuditResult | None = None
    active_audit_error: str | None = None
    cmd_audit: CommandAuditResult | None = None
    cmd_audit_error: str | None = None
    cmd_audit_active: CommandAuditActiveResult | None = None
    cmd_audit_active_error: str | None = None
    invalid_cmd_audit: InvalidCmdAuditResult | None = None
    invalid_cmd_audit_error: str | None = None
    user_enum: FtpUserEnumResult | None = None
    user_enum_error: str | None = None
    pasv_port_range: PasvPortRangeResult | None = None
    pasv_port_range_error: str | None = None
    conn_limits: ConnLimitsAuditResult | None = None
    conn_limits_error: str | None = None
    chroot_audit: ChrootAuditResult | None = None
    chroot_audit_error: str | None = None
    eicar_audit: FtpEicarAuditResult | None = None
    eicar_audit_error: str | None = None
    dos_audit: FtpDosAuditResult | None = None
    dos_audit_error: str | None = None


class VULNS(Enum):
    Anonymous = "PTL-SVC-FTP-ANONYMOUS"
    Bounce = "PTV-FTP-BOUNCE"
    WeakCreds = "PTV-GENERAL-WEAKCREDENTIALS"
    FtpActivePolicy = "PTL-SVC-FTP-ACTIVE"
    FtpCmdSurface = "PTL-SVC-FTP-CMD"
    FtpInvalidCommandHandling = "PTL-SVC-FTP-INVCOMM"
    FtpObsoleteTls = "PTL-SVC-FTP-OLD-TLS"
    FtpUserEnumeration = "PTL-SVC-FTP-USRENUM"
    FtpPassivePortRange = "PTL-SVC-FTP-PASIVE"
    FtpConnectionLimits = "PTL-SVC-FTP-CONN"
    FtpChrootIsolation = "PTL-SVC-FTP-CHROOT"
    FtpAntivirusEicar = "PTL-SVC-FTP-ANTIVIRUS"
    FtpProcessingResilience = "PTL-SVC-FTP-PROC-DOS"


# endregion


# region -ts test registry (single source of truth for `-ts/--tests`)

# Internal per-test dest flags driven by -ts. The legacy test flags were removed;
# -ts is the only public interface, so these bool dests must be initialised
# explicitly (argparse no longer defines them). run() reads exactly these.
# Value modifiers (--bounce, --access-list, --paths-wordlist, --conn-limits-*, ...)
# keep their own argparse defaults and are documented per-test.
