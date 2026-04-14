import argparse, collections, ftplib, ipaddress, posixpath, random, re, secrets, select, socket, ssl, statistics, threading, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from difflib import SequenceMatcher
from enum import Enum
from io import BytesIO
from ssl import SSLSocket
from string import ascii_uppercase
from typing import NamedTuple

from ptlibs.ptjsonlib import PtJsonLib

from ._base import BaseModule, BaseArgs, Out
from ptlibs.ptprinthelper import get_colored_text
from ptlibs.threads import ptthreads

from .utils.helpers import (
    Target,
    Creds,
    ArgsWithBruteforce,
    check_if_brute,
    get_mode,
    valid_target,
    vendor_from_cpe,
    add_bruteforce_args,
    simple_bruteforce,
    text_or_file,
)
from .utils.service_identification import identify_service


# region helper methods


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


# endregion

# region arguments


class FTPArgs(ArgsWithBruteforce):
    target: Target
    active: bool
    tls: bool
    starttls: bool
    anonymous: bool
    info: bool
    access: bool
    access_list: bool
    bounce: Target | None
    bounce_file: str | None
    isencrypt: bool

    @staticmethod
    def get_help():
        return [
            {"description": ["FTP Testing Module"]},
            {"usage": ["ptsrvtester ftp <options> <target>"]},
            {"usage_example": [
                "ptsrvtester ftp --starttls -iAal 127.0.0.1",
                "ptsrvtester ftp -ie 127.0.0.1",
                "ptsrvtester ftp -Am 127.0.0.1",
                "ptsrvtester ftp -AM 127.0.0.1",
                "ptsrvtester ftp -u admin -P passwords.txt 127.0.0.1:21",
                "ptsrvtester ftp -AC 127.0.0.1",
                "ptsrvtester ftp -AC --cmd-audit-active 127.0.0.1",
                "ptsrvtester ftp -iv 127.0.0.1",
                "ptsrvtester ftp -eu --user-enum-wordlist users.txt 127.0.0.1",
                "ptsrvtester ftp -AR 127.0.0.1",
                "ptsrvtester ftp -L 127.0.0.1",
                "ptsrvtester ftp -u user -p pass -J 127.0.0.1",
            ]},
            {"options": [
                ["-i", "--info", "", "Grab banner and inspect HELP, SYST, STAT commands"],
                ["-b", "--banner", "", "Grab banner + Service Identification (product, version, CPE)"],
                ["-c", "--commands", "", "Grab HELP, SYST and STAT commands only"],
                ["-ie", "--is-encrypt", "", "Test encryption options (plaintext, AUTH TLS, implicit TLS)"],
                ["-A", "--anonymous", "", "Check anonymous authentication"],
                ["-a", "--access", "", "Read/write check (use with -A and/or -u/-p)"],
                ["-l", "--access-list", "", "Display directory listing"],
                ["-B", "--bounce", "", "FTP bounce attack"],
                ["", "--bounce-file", "<file>", "File with request to send (requires --access)"],
                ["-m", "--modes", "", "Test passive/active data modes + PASV IP leakage"],
                ["-R", "--pasv-port-audit", "", "Passive data port spread (PASV+LIST)"],
                ["", "--pasv-port-audit-samples", "<n>", "Samples for -R (default 8, min 4)"],
                ["", "--pasv-port-audit-max-span", "<n>", "Max acceptable max-min across samples (default 8192)"],
                ["-L", "--conn-limits-audit", "", "Connection/rate/idle/PASV limits; bounded probes"],
                ["", "--conn-limits-parallel", "<n>", "Simultaneous pre-auth sessions for -L (default 12, max 40)"],
                ["", "--conn-limits-sequential", "<n>", "Rapid sequential connects for -L (default 24, max 80)"],
                ["", "--conn-limits-pasv-attempts", "<n>", "PASV spam count per session for -L (default 18, max 60)"],
                ["", "--conn-limits-idle-pre-auth", "<s>", "Pre-login idle seconds (0=skip); 421/close check"],
                ["", "--conn-limits-slow-auth-gap", "<s>", "Seconds between USER and PASS (0=skip); wrong PASS"],
                ["", "--conn-limits-idle-post-auth", "<s>", "Post-login idle seconds if creds (0=skip); NOOP after"],
                ["-J", "--chroot-audit", "", "User isolation: CWD .., /etc, /home, SIZE passwd"],
                ["", "--chroot-audit-paths", "<list>", "Extra comma-separated absolute paths for -J"],
                ["-M", "--active-audit", "", "Quick PORT/PASV policy audit"],
                ["", "--active-audit-full", "", "Full methodology: isolated sessions, raw LIST (D0), PORT+LIST, hints"],
                ["", "--active-audit-low-ports", "<list>", "Comma-separated data ports <1000 for full audit (default 80,443,21)"],
                ["-C", "--cmd-audit", "", "HELP/FEAT/SITE command surface audit"],
                ["", "--cmd-audit-active", "", "After -C: safe SITE probes (needs login); timeouts + DELE cleanup"],
                ["-iv", "--invalid-cmd-audit", "", "Invalid command resilience; raw bytes, resilienceRating"],
                ["-eu", "--user-enum", "", "Username enumeration: USER then wrong PASS; needs --user-enum-wordlist"],
                ["", "--user-enum-wordlist", "<file>", "Usernames for -eu, one per line"],
                ["", "--user-enum-password", "<str>", "Fixed wrong password after 331/332 (default built-in)"],
                ["", "--user-enum-keep-alive", "", "One TCP session for all -eu probes (no --user-enum-threads > 1)"],
                ["", "--user-enum-timing", "", "Median PASS-phase timing: candidates vs controls"],
                ["", "--user-enum-threads", "<n>", "Parallel connections for -eu (default 1)"],
                ["", "--user-enum-max", "<n>", "Cap wordlist size for -eu (0 = no limit)"],
                ["", "--active", "", "Use active mode"],
                ["", "--tls", "", "Use implicit SSL/TLS"],
                ["", "--starttls", "", "Use explicit SSL/TLS"],
                ["-u", "--user", "<username>", "FTP username (known account with -p, or bruteforce with -P)"],
                ["-U", "--users", "<wordlist>", "File with usernames"],
                ["-p", "--password", "<password>", "FTP password (known account with -u, or bruteforce with -U)"],
                ["-P", "--passwords", "<wordlist>", "File with passwords"],
                ["-e", "--enum-paths", "", "Dictionary attack for path discovery (requires creds)"],
                ["-w", "--paths-wordlist", "<file>", "Paths to test, one per line (required with -e)"],
                ["", "--enum-threads", "<n>", "Threads for path enumeration (default: 5)"],
                ["", "--base-path", "<path>", "Start directory for enumeration"],
                ["-h", "--help", "", "Show this help message and exit"],
                ["-vv", "--verbose", "", "Enable verbose mode"],
            ]}
        ]

    def add_subparser(self, name: str, subparsers) -> None:
        """Adds a subparser of FTP arguments"""

        examples = """example usage:
  ptsrvtester ftp -h
  ptsrvtester ftp --starttls -iAal 127.0.0.1
  ptsrvtester ftp -ie 127.0.0.1
  ptsrvtester ftp -Am 127.0.0.1
  ptsrvtester ftp -AM 127.0.0.1
  ptsrvtester ftp -A --active-audit-full 127.0.0.1
  ptsrvtester ftp -AC 127.0.0.1
  ptsrvtester ftp -u myuser -p mypass -C --cmd-audit-active 127.0.0.1
  ptsrvtester ftp -Aae -w paths.txt 127.0.0.1
  ptsrvtester ftp -AR 127.0.0.1
  ptsrvtester ftp -L 127.0.0.1
  ptsrvtester ftp -u user -p pass -J 127.0.0.1
  ptsrvtester ftp -AL --conn-limits-idle-pre-auth 120 127.0.0.1
  ptsrvtester -j ftp -u admin -P passwords.txt --brute-threads 20 127.0.0.1:21

Credentials:
  Known account: use -u USER -p PASS (one login; not only wordlists).
  Anonymous: -A. Optional read/write check: -a (with -A or after successful -u/-p)."""

        parser = subparsers.add_parser(
            name,
            epilog=examples,
            add_help=True,
            formatter_class=argparse.RawTextHelpFormatter,
        )

        if not isinstance(parser, argparse.ArgumentParser):
            raise TypeError  # IDE typing

        parser.add_argument(
            "target",
            type=valid_target_ftp,
            help="IP[:PORT] or HOST[:PORT] (e.g. 127.0.0.1 or ftp.example.com:21)",
        )

        parser.add_argument(
            "--active", action="store_true", help="use active mode (passive by default)"
        )
        tls = parser.add_mutually_exclusive_group()
        tls.add_argument("--tls", action="store_true", help="use implicit SSL/TLS")
        tls.add_argument("--starttls", action="store_true", help="use explicit SSL/TLS")

        recon = parser.add_argument_group("RECON")
        recon.add_argument(
            "-i",
            "--info",
            action="store_true",
            help="grab banner and inspect HELP, SYST and STAT commands",
        )
        recon.add_argument("-b", "--banner", action="store_true", help="grab banner + Service Identification (product, version, CPE)")
        recon.add_argument("-c", "--commands", action="store_true", help="grab HELP, SYST and STAT commands only")
        recon.add_argument(
            "-ie", "--is-encrypt", action="store_true", dest="isencrypt",
            help="test encryption options (plaintext, AUTH TLS, implicit TLS)"
        )
        recon.add_argument(
            "-A", "--anonymous", action="store_true", help="check anonymous authentication"
        )
        access_check = recon.add_mutually_exclusive_group()
        access_check.add_argument(
            "-a",
            "--access",
            action="store_true",
            help="check read/write access (needs credentials: combine with -A and/or -u/-p / wordlists)",
        )
        recon.add_argument(
            "-l",
            "--access-list",
            action="store_true",
            help="display root directory listing",
        )

        bounce = parser.add_argument_group("BOUNCE", "FTP bounce attack (requires valid login)")
        bounce.add_argument(
            "-B",
            "--bounce",
            type=valid_target_bounce,
            help="bounce to the specified IP:PORT or HOST:PORT service",
        )
        bounce.add_argument(
            "--bounce-file",
            type=str,
            help="file containing a request to be sent to the attacked service"
            + " (requires --access or --access-all with write permissions)",
        )

        path_enum = parser.add_argument_group(
            "PATH ENUMERATION",
            "Dictionary attack for discovering files and directories (requires valid credentials)",
        )
        path_enum.add_argument(
            "-e",
            "--enum-paths",
            action="store_true",
            dest="enum_paths",
            help="run path enumeration from wordlist (requires --access or -A or -u/-p / wordlists)",
        )
        path_enum.add_argument(
            "-w",
            "--paths-wordlist",
            type=str,
            dest="paths_wordlist",
            help="file with paths to test, one per line (required with -e)",
        )
        path_enum.add_argument(
            "--enum-threads",
            type=int,
            default=5,
            dest="enum_threads",
            help="threads for path enumeration (default: 5)",
        )
        path_enum.add_argument(
            "--base-path",
            type=str,
            default="",
            dest="base_path",
            help="starting directory for enumeration (default: login home)",
        )

        modes_grp = parser.add_argument_group(
            "DATA MODE",
            "Test passive and active mode availability (requires login)",
        )
        modes_grp.add_argument(
            "-m",
            "--modes",
            action="store_true",
            dest="modes",
            help="test passive/active data modes and PASV IP leakage",
        )
        modes_grp.add_argument(
            "-R",
            "--pasv-port-audit",
            action="store_true",
            dest="pasv_port_audit",
            help="repeated passive LIST: check whether data ports stay in a narrow range",
        )
        modes_grp.add_argument(
            "--pasv-port-audit-samples",
            type=int,
            default=8,
            dest="pasv_port_audit_samples",
            metavar="<n>",
            help="number of separate login sessions / LIST transfers for -R (default 8)",
        )
        modes_grp.add_argument(
            "--pasv-port-audit-max-span",
            type=int,
            default=8192,
            dest="pasv_port_audit_max_span",
            metavar="<n>",
            help="if max(dataPort)-min(dataPort) across successful -R samples exceeds this, flag wide range (default 8192)",
        )

        conn_grp = parser.add_argument_group(
            "CONNECTION LIMITS",
            "Bounded probes for concurrent sessions, PASV spam, optional idle/slow auth",
        )
        conn_grp.add_argument(
            "-L",
            "--conn-limits-audit",
            action="store_true",
            dest="conn_limits_audit",
            help="parallel + sequential connects, PASV without transfer; optional idle/slow-auth (use only on authorized targets)",
        )
        conn_grp.add_argument(
            "--conn-limits-parallel",
            type=int,
            default=12,
            dest="conn_limits_parallel",
            metavar="<n>",
            help="parallel pre-auth control connections in one burst (default 12, max 40)",
        )
        conn_grp.add_argument(
            "--conn-limits-sequential",
            type=int,
            default=24,
            dest="conn_limits_sequential",
            metavar="<n>",
            help="rapid sequential connects after parallel phase (default 24, max 80)",
        )
        conn_grp.add_argument(
            "--conn-limits-pasv-attempts",
            type=int,
            default=18,
            dest="conn_limits_pasv_attempts",
            metavar="<n>",
            help="PASV commands per control session without data transfer (default 18, max 60)",
        )
        conn_grp.add_argument(
            "--conn-limits-idle-pre-auth",
            type=float,
            default=0.0,
            dest="conn_limits_idle_pre_auth",
            metavar="<s>",
            help="after 220, wait N seconds and watch for 421/close (0 = skip; try 60–300 on lab)",
        )
        conn_grp.add_argument(
            "--conn-limits-slow-auth-gap",
            type=float,
            default=0.0,
            dest="conn_limits_slow_auth_gap",
            metavar="<s>",
            help="pause between USER and wrong PASS in seconds (0 = skip; try 45–120)",
        )
        conn_grp.add_argument(
            "--conn-limits-idle-post-auth",
            type=float,
            default=0.0,
            dest="conn_limits_idle_post_auth",
            metavar="<s>",
            help="after login, idle N seconds then NOOP (0 = skip; requires creds)",
        )

        chroot_grp = parser.add_argument_group(
            "USER ISOLATION / CHROOT",
            "CWD probes and .. chain after login; confirm on authorized targets",
        )
        chroot_grp.add_argument(
            "-J",
            "--chroot-audit",
            action="store_true",
            dest="chroot_audit",
            help="test whether account can reach host-style paths (/etc, /root, ..) or /home parent",
        )
        chroot_grp.add_argument(
            "--chroot-audit-paths",
            type=str,
            default="",
            dest="chroot_audit_paths",
            metavar="<list>",
            help="additional absolute paths to try with CWD (comma-separated), merged with built-in set",
        )

        audit_grp = parser.add_argument_group(
            "ACTIVE MODE POLICY",
            "PORT/PASV command policy and bounce-related checks",
        )
        audit_grp.add_argument(
            "-M",
            "--active-audit",
            action="store_true",
            dest="active_audit",
            help="Quick PORT/PASV policy audit",
        )
        audit_grp.add_argument(
            "--active-audit-full",
            action="store_true",
            dest="active_audit_full",
            help="full audit: pre-auth hints, D0 raw LIST, fresh connection per PORT+LIST, multiple low ports",
        )
        audit_grp.add_argument(
            "--active-audit-low-ports",
            type=str,
            default="80,443,21",
            dest="active_audit_low_ports",
            help="for --active-audit-full: comma-separated ports <1000 to test (default: 80,443,21)",
        )

        cmd_grp = parser.add_argument_group(
            "COMMAND SURFACE",
            "Dangerous or unnecessary FTP commands (HELP, FEAT, SITE HELP)",
        )
        cmd_grp.add_argument(
            "-C",
            "--cmd-audit",
            action="store_true",
            dest="cmd_audit",
            help="audit HELP, FEAT, SITE HELP/ALL; flag high-risk SITE extensions",
        )
        cmd_grp.add_argument(
            "--cmd-audit-active",
            action="store_true",
            dest="cmd_audit_active",
            help="after passive -C audit: login and send safe SITE probes (timeouts, DELE cleanup, 530 vs 550); needs -A or -u/-p or wordlists",
        )

        inv_grp = parser.add_argument_group(
            "INVALID COMMAND RESILIENCE",
            "Non-standard inputs on control channel; uses raw bytes on socket",
        )
        inv_grp.add_argument(
            "-iv",
            "--invalid-cmd-audit",
            action="store_true",
            dest="invalid_cmd_audit",
            help="invalid command resilience: raw/malformed control lines incl. USER…\\x00…; JSON resilienceRating",
        )

        ue_grp = parser.add_argument_group(
            "USERNAME ENUMERATION",
            "USER/PASS with fixed wrong password; distinct replies vs RFC 2577",
        )
        ue_grp.add_argument(
            "-eu",
            "--user-enum",
            action="store_true",
            dest="user_enum",
            help="run username enumeration probes (requires --user-enum-wordlist)",
        )
        ue_grp.add_argument(
            "--user-enum-wordlist",
            type=str,
            dest="user_enum_wordlist",
            metavar="<file>",
            help="usernames to test, one per line (required with -eu)",
        )
        ue_grp.add_argument(
            "--user-enum-password",
            type=str,
            default="PtsrvUEnumWrongPass!77~",
            dest="user_enum_password",
            metavar="<str>",
            help="fixed wrong password sent after 331/332 (default: built-in marker string)",
        )
        ue_grp.add_argument(
            "--user-enum-keep-alive",
            action="store_true",
            dest="user_enum_keep_alive",
            help="reuse one control connection for sequential USER/PASS (faster; IDS-visible; not with --user-enum-threads > 1)",
        )
        ue_grp.add_argument(
            "--user-enum-timing",
            action="store_true",
            dest="user_enum_timing",
            help="compare median PASS-phase latency (ms): wordlist vs control usernames",
        )
        ue_grp.add_argument(
            "--user-enum-threads",
            type=int,
            default=1,
            dest="user_enum_threads",
            metavar="<n>",
            help="parallel connections for -eu (default: 1). Ignored with --user-enum-keep-alive",
        )
        ue_grp.add_argument(
            "--user-enum-max",
            type=int,
            default=0,
            dest="user_enum_max",
            metavar="<n>",
            help="max usernames taken from wordlist after comments/blank skip (0 = no limit)",
        )

        add_bruteforce_args(parser)


# endregion


# region main module code


class FTP(BaseModule):
    @staticmethod
    def module_args():
        return FTPArgs()

    def __init__(self, args: BaseArgs, ptjsonlib: PtJsonLib):

        if not isinstance(args, FTPArgs):
            raise argparse.ArgumentError(
                None, f'module "{args.module}" received wrong arguments namespace'
            )

        if not args.access:
            if args.bounce_file:
                raise argparse.ArgumentError(None, "--bounce-file requires also --access")
            if args.access_list:
                raise argparse.ArgumentError(None, "--access-list requires also --access")

        enum_paths = getattr(args, "enum_paths", False)
        if enum_paths:
            if not getattr(args, "paths_wordlist", None):
                raise argparse.ArgumentError(None, "--enum-paths requires --paths-wordlist (-w)")
            if not args.access and not args.anonymous and not check_if_brute(args):
                raise argparse.ArgumentError(
                    None,
                    "--enum-paths requires credentials (--access with -A, or known account -u/-p, or wordlists -U/-P)",
                )

        if getattr(args, "modes", False):
            if not args.access and not args.anonymous and not check_if_brute(args):
                raise argparse.ArgumentError(
                    None,
                    "--modes requires credentials (--anonymous or known account -u/-p or wordlists)",
                )

        if getattr(args, "pasv_port_audit", False):
            if not args.access and not args.anonymous and not check_if_brute(args):
                raise argparse.ArgumentError(
                    None,
                    "--pasv-port-audit (-R) requires credentials (--anonymous or known account -u/-p or wordlists)",
                )
            ps = int(getattr(args, "pasv_port_audit_samples", 8) or 8)
            if ps < 4:
                raise argparse.ArgumentError(None, "--pasv-port-audit-samples must be >= 4")
            mx = int(getattr(args, "pasv_port_audit_max_span", 8192) or 8192)
            if mx < 256:
                raise argparse.ArgumentError(None, "--pasv-port-audit-max-span must be >= 256")

        if getattr(args, "conn_limits_audit", False):
            cp = int(getattr(args, "conn_limits_parallel", 12) or 12)
            if cp < 1 or cp > 40:
                raise argparse.ArgumentError(None, "--conn-limits-parallel must be between 1 and 40")
            cs = int(getattr(args, "conn_limits_sequential", 24) or 24)
            if cs < 0 or cs > 80:
                raise argparse.ArgumentError(None, "--conn-limits-sequential must be 0..80")
            pa = int(getattr(args, "conn_limits_pasv_attempts", 18) or 18)
            if pa < 0 or pa > 60:
                raise argparse.ArgumentError(None, "--conn-limits-pasv-attempts must be 0..60")
            idle_pre = float(getattr(args, "conn_limits_idle_pre_auth", 0) or 0)
            if idle_pre < 0 or idle_pre > 3600:
                raise argparse.ArgumentError(None, "--conn-limits-idle-pre-auth must be 0..3600 seconds")
            sg = float(getattr(args, "conn_limits_slow_auth_gap", 0) or 0)
            if sg < 0 or sg > 3600:
                raise argparse.ArgumentError(None, "--conn-limits-slow-auth-gap must be 0..3600 seconds")
            idle_post = float(getattr(args, "conn_limits_idle_post_auth", 0) or 0)
            if idle_post < 0 or idle_post > 3600:
                raise argparse.ArgumentError(None, "--conn-limits-idle-post-auth must be 0..3600 seconds")
            if idle_post > 0 and not args.access and not args.anonymous and not check_if_brute(args):
                raise argparse.ArgumentError(
                    None,
                    "--conn-limits-idle-post-auth > 0 requires credentials (--anonymous or -u/-p or wordlists)",
                )

        if getattr(args, "chroot_audit", False):
            if not args.access and not args.anonymous and not check_if_brute(args):
                raise argparse.ArgumentError(
                    None,
                    "--chroot-audit (-J) requires credentials (--anonymous or known account -u/-p or wordlists)",
                )
            cps = (getattr(args, "chroot_audit_paths", None) or "").strip()
            if len(cps) > 4000:
                raise argparse.ArgumentError(None, "--chroot-audit-paths string is too long (max 4000 chars)")

        if getattr(args, "cmd_audit_active", False):
            if not args.access and not args.anonymous and not check_if_brute(args):
                raise argparse.ArgumentError(
                    None,
                    "--cmd-audit-active requires credentials (--anonymous, --access, or -u/-p known account or -U/-P)",
                )

        if getattr(args, "user_enum", False):
            if not getattr(args, "user_enum_wordlist", None):
                raise argparse.ArgumentError(
                    None,
                    "--user-enum (-eu) requires --user-enum-wordlist",
                )
            ue_th = max(1, int(getattr(args, "user_enum_threads", 1) or 1))
            if getattr(args, "user_enum_keep_alive", False) and ue_th > 1:
                raise argparse.ArgumentError(
                    None,
                    "--user-enum-keep-alive cannot be combined with --user-enum-threads > 1",
                )
            ue_mx = int(getattr(args, "user_enum_max", 0) or 0)
            if ue_mx < 0:
                raise argparse.ArgumentError(None, "--user-enum-max must be >= 0")

        # Default port number
        if args.target.port == 0:
            if args.tls:
                args.target.port = 990
            else:
                args.target.port = 21

        self.do_brute = check_if_brute(args)
        self.use_json = getattr(args, "json", False)

        self.args = args
        self.ptjsonlib = ptjsonlib
        self.results: FTPResults
        self.ftp: ftplib.FTP
        self._output_lock = threading.Lock()
        self._streamed_banner = False
        self._streamed_encryption = False
        self._streamed_anonymous = False
        self._streamed_brute = False

    def _is_run_all_mode(self) -> bool:
        """True when only target is given (no test switches). Run all tests in sequence."""
        return not (
            self.args.info
            or self.args.banner
            or self.args.commands
            or getattr(self.args, "isencrypt", False)
            or self.args.anonymous
            or self.args.access
            or self.args.access_list
            or self.args.bounce
            or self.do_brute
            or getattr(self.args, "enum_paths", False)
            or getattr(self.args, "modes", False)
            or getattr(self.args, "pasv_port_audit", False)
            or getattr(self.args, "conn_limits_audit", False)
            or getattr(self.args, "chroot_audit", False)
            or getattr(self.args, "active_audit", False)
            or getattr(self.args, "active_audit_full", False)
            or getattr(self.args, "cmd_audit", False)
            or getattr(self.args, "cmd_audit_active", False)
            or getattr(self.args, "invalid_cmd_audit", False)
            or getattr(self.args, "user_enum", False)
        )

    def _ftp_any_primary_action(self) -> bool:
        """True if any test flag is set other than standalone -eu (used for user-enum-only fast path)."""
        a = self.args
        return bool(
            a.info
            or a.banner
            or a.commands
            or getattr(a, "isencrypt", False)
            or a.anonymous
            or a.access
            or a.access_list
            or a.bounce
            or self.do_brute
            or getattr(a, "enum_paths", False)
            or getattr(a, "modes", False)
            or getattr(a, "pasv_port_audit", False)
            or getattr(a, "conn_limits_audit", False)
            or getattr(a, "chroot_audit", False)
            or getattr(a, "active_audit", False)
            or getattr(a, "active_audit_full", False)
            or getattr(a, "cmd_audit", False)
            or getattr(a, "cmd_audit_active", False)
            or getattr(a, "invalid_cmd_audit", False)
        )

    def _fail(self, msg: str) -> None:
        """In run-all mode: raise TestFailedError. Otherwise: end_error + SystemExit."""
        if hasattr(self, 'run_all_mode') and self.run_all_mode:
            raise TestFailedError(msg)
        else:
            self.ptjsonlib.end_error(msg, self.use_json)
            raise SystemExit

    def run(self) -> None:
        """Executes FTP methods based on module configuration. Results streamed immediately."""
        self.results = FTPResults()
        self.run_all_mode = self._is_run_all_mode()
        isencrypt = getattr(self.args, "isencrypt", False)

        # -eu only: no shared self.ftp session required
        if getattr(self.args, "user_enum", False) and not self._ftp_any_primary_action():
            try:
                self.results.user_enum = self.test_user_enumeration()
            except Exception as e:
                self.results.user_enum_error = str(e)
            return

        # -ie only mode: encryption test and return
        if (
            isencrypt
            and not self.args.info
            and not self.args.banner
            and not self.args.commands
            and not self.args.anonymous
            and not self.args.access
            and not self.args.access_list
            and not self.args.bounce
            and not self.do_brute
            and not getattr(self.args, "user_enum", False)
        ):
            try:
                self.results.encryption = self.test_encryption()
            except Exception as e:
                self.results.encryption_error = str(e)
            self._stream_encryption_result()
            return

        if self.run_all_mode:
            self._run_all_tests()
            return

        # Normal mode: connect first, then run tests and stream immediately
        try:
            self.ftp = self.connect()
        except (TestFailedError, SystemExit):
            raise
        except Exception as e:
            self.results.info_error = str(e)
            return

        # Anonymous (info/STAT may need login; run before info when both requested)
        if self.args.anonymous:
            self.results.anonymous = self.anonymous()
            self._stream_anonymous_result()

        # Bruteforce (info/STAT may need creds for STAT when anonymous disabled)
        if self.do_brute:
            if not self.use_json:
                self.ptprint(
                    "FTP login (known account)" if self._ftp_is_single_known_login() else "Login bruteforce",
                    Out.INFO,
                )
            self.results.creds = simple_bruteforce(
                self._try_login,
                self.args.user,
                self.args.users,
                self.args.password,
                self.args.passwords,
                self.args.spray,
                self.args.threads,
                on_success=self._on_brute_success if not self.use_json else None,
            )
            self._stream_brute_result()

        # Info (banner + commands) - needs anonymous/creds for STAT
        if self.args.info or self.args.banner or self.args.commands:
            do_banner = self.args.banner or self.args.info
            do_commands = self.args.commands or self.args.info
            self.results.banner_requested = do_banner
            self.results.commands_requested = do_commands
            try:
                info = self.info(get_commands=do_commands)
                self.results.info = InfoResult(
                    info.banner if do_banner else None,
                    info.help_response if do_commands else None,
                    info.syst if do_commands else None,
                    info.stat if do_commands else None,
                )
                self._stream_banner_result()
            except Exception as e:
                self.results.info_error = str(e)

        # Encryption test (-ie)
        if isencrypt:
            try:
                self.results.encryption = self.test_encryption()
            except Exception as e:
                self.results.encryption_error = str(e)
            self._stream_encryption_result()

        # Access check
        if self.args.access:
            self.results.access = self.access_check()
            if self.args.bounce:
                self.results.bounce = self.bounce()

        # Path enumeration (dictionary attack)
        if getattr(self.args, "enum_paths", False):
            creds = self._get_path_enum_creds()
            if creds is not None:
                try:
                    paths_raw = text_or_file(None, self.args.paths_wordlist)
                    paths = [p.strip() for p in paths_raw if p.strip() and not p.strip().startswith("#")]
                    if not self.use_json:
                        self.ptprint("Path enumeration", Out.INFO)
                    self.results.path_enum = self.path_enumeration(creds, paths)
                except Exception as e:
                    self.results.path_enum_error = str(e)
            else:
                self.results.path_enum_error = "No valid credentials for path enumeration"

        # Data mode (passive/active) test
        if getattr(self.args, "modes", False):
            creds = self._get_path_enum_creds()
            if creds is not None:
                try:
                    self.results.modes = self.test_modes(creds)
                except Exception as e:
                    self.results.modes_error = str(e)
            else:
                self.results.modes_error = "No credentials for mode test (use --anonymous or -u/-p known account or wordlists)"

        # Passive data port spread (PTL-SVC-FTP-PASIVE)
        if getattr(self.args, "pasv_port_audit", False):
            creds = self._get_path_enum_creds()
            if creds is not None:
                try:
                    n = max(4, int(getattr(self.args, "pasv_port_audit_samples", 8) or 8))
                    mxsp = max(256, int(getattr(self.args, "pasv_port_audit_max_span", 8192) or 8192))
                    self.results.pasv_port_range = self.test_pasv_port_range_audit(creds, n, mxsp)
                except Exception as e:
                    self.results.pasv_port_range_error = str(e)
            else:
                self.results.pasv_port_range_error = (
                    "No credentials for passive port audit (use --anonymous or -u/-p known account or wordlists)"
                )

        # Connection / rate / idle limits (PTL-SVC-FTP-CONN)
        if getattr(self.args, "conn_limits_audit", False):
            try:
                creds_post = self._get_path_enum_creds()
                self.results.conn_limits = self.test_connection_limits_audit(creds_post)
            except Exception as e:
                self.results.conn_limits_error = str(e)

        # User isolation / chroot-style audit (PTL-SVC-FTP-CHROOT)
        if getattr(self.args, "chroot_audit", False):
            creds = self._get_path_enum_creds()
            if creds is not None:
                try:
                    self.results.chroot_audit = self.test_chroot_audit(creds)
                except Exception as e:
                    self.results.chroot_audit_error = str(e)
            else:
                self.results.chroot_audit_error = (
                    "No credentials for chroot audit (use --anonymous or -u/-p known account or wordlists)"
                )

        # PORT/PASV policy audit (PTL-SVC-FTP-ACTIVE)
        if getattr(self.args, "active_audit_full", False) or getattr(self.args, "active_audit", False):
            try:
                creds = self._get_path_enum_creds()
                if getattr(self.args, "active_audit_full", False):
                    low_s = getattr(self.args, "active_audit_low_ports", None) or "80,443,21"
                    self.results.active_audit = self.test_active_audit_full(creds, low_s)
                else:
                    self.results.active_audit = self.test_active_audit_quick(creds)
            except Exception as e:
                self.results.active_audit_error = str(e)

        # HELP/FEAT/SITE command surface (PTL-SVC-FTP-CMD)
        if getattr(self.args, "cmd_audit", False) or getattr(self.args, "cmd_audit_active", False):
            try:
                creds = self._get_path_enum_creds()
                self.results.cmd_audit = self.test_command_audit(creds)
            except Exception as e:
                self.results.cmd_audit_error = str(e)
            if getattr(self.args, "cmd_audit_active", False):
                ac = self._get_path_enum_creds()
                if ac is None:
                    self.results.cmd_audit_active_error = (
                        "Active command probes require credentials (successful --anonymous, --access, or -u/-p / wordlists)"
                    )
                elif self.results.cmd_audit_error:
                    self.results.cmd_audit_active_error = (
                        f"Skipped: passive cmd audit failed: {self.results.cmd_audit_error}"
                    )
                else:
                    try:
                        self.results.cmd_audit_active = self.test_command_audit_active(
                            ac, self.results.cmd_audit
                        )
                    except Exception as e:
                        self.results.cmd_audit_active_error = str(e)

        # Invalid / non-standard control-channel lines (PTL-SVC-FTP-INVCOMM)
        if getattr(self.args, "invalid_cmd_audit", False):
            try:
                creds = self._get_path_enum_creds()
                self.results.invalid_cmd_audit = self.test_invalid_command_audit(creds)
            except Exception as e:
                self.results.invalid_cmd_audit_error = str(e)

        if getattr(self.args, "user_enum", False):
            try:
                self.results.user_enum = self.test_user_enumeration()
            except Exception as e:
                self.results.user_enum_error = str(e)

    def _ftp_is_single_known_login(self) -> bool:
        """True when CLI supplies one username and one password (no -U/-P wordlists)."""
        u = getattr(self.args, "user", None)
        p = getattr(self.args, "password", None)
        uf = getattr(self.args, "users", None)
        pf = getattr(self.args, "passwords", None)
        return bool(u and p and not uf and not pf)

    def _get_path_enum_creds(self) -> Creds | None:
        """Get credentials: anonymous, or first successful login from -u/-p or wordlists."""
        if self.results.anonymous:
            return Creds("anonymous", "")
        if self.results.creds and len(self.results.creds) > 0:
            return next(iter(self.results.creds))
        return None

    def _run_all_tests(self) -> None:
        """Run all tests in sequence. On failure: print error, continue with next. Stream immediately."""
        # 1. Banner + commands (SYST, STAT)
        self.results.banner_requested = True
        self.results.commands_requested = True
        try:
            self.ftp = self.connect()
            self.results.info = self.info(get_commands=True)
            self._stream_banner_result()
        except TestFailedError as e:
            self.results.info_error = str(e)
            return
        except Exception as e:
            self.results.info_error = str(e)
            return

        # 2. Anonymous authentication
        try:
            self.results.anonymous = self.anonymous()
            self._stream_anonymous_result()
        except TestFailedError as e:
            self.results.anonymous_error = str(e)
        except Exception as e:
            self.results.anonymous_error = str(e)

        # 3. Access check (only if anonymous is enabled)
        if self.results.anonymous:
            try:
                self.results.access = self.access_check()
            except TestFailedError as e:
                self.results.access_error = str(e)
            except Exception as e:
                self.results.access_error = str(e)

        # 4. Data mode test (passive/active + PASV IP leakage; requires creds)
        creds = self._get_path_enum_creds()
        if creds is not None:
            try:
                self.results.modes = self.test_modes(creds)
            except TestFailedError:
                raise
            except Exception as e:
                self.results.modes_error = str(e)
        else:
            self.results.modes_error = "No credentials for mode test (use --anonymous or -u/-p known account or wordlists)"

    def connect(self) -> ftplib.FTP | ftplib.FTP_TLS | FTP_TLS_implicit:
        """
        Establishes a new FTP connection with the appropriate
        encryption mode according to module arguments

        Returns:
            ftplib.FTP | ftplib.FTP_TLS | FTP_TLS_implicit: new connection
        """
        timeout = 10
        try:
            if self.args.tls:
                ftp = FTP_TLS_implicit()
                ftp.connect(self.args.target.ip, self.args.target.port, timeout=timeout)
            elif self.args.starttls:
                ftp = ftplib.FTP_TLS()
                ftp.connect(self.args.target.ip, self.args.target.port, timeout=timeout)
                ftp.auth()
            else:
                ftp = ftplib.FTP()
                ftp.connect(self.args.target.ip, self.args.target.port, timeout=timeout)
        except Exception as e:
            msg = (
                f"Could not connect to the target server "
                + f"{self.args.target.ip}:{self.args.target.port} ({get_mode(self.args)}): {e}"
            )
            raise OSError(msg) from e

        # Passive/Active mode
        ftp.set_pasv(not self.args.active)
        return ftp

    def info(self, get_commands: bool = True) -> InfoResult:
        """Performs bannergrabbing; optionally HELP, SYST and STAT commands.

        Returns:
            InfoResult: (banner, help_response, syst, stat)
        """
        banner = self.ftp.welcome
        if banner is None:
            banner = ""

        help_response = None
        syst = None
        stat = None
        if get_commands:
            try:
                help_response = self.ftp.sendcmd("HELP")
                if help_response and help_response.strip():
                    help_response = help_response.strip()
                else:
                    help_response = None
            except Exception:
                pass
            try:
                syst = self.ftp.sendcmd("SYST")
                if re.match(r"[0-9]+ UNIX Type: L8", syst):
                    syst = None
            except Exception:
                pass
            try:
                if not self.results.anonymous and self.results.creds is not None:
                    for creds in self.results.creds:
                        self.ftp.login(creds.user, creds.passw)
                        break
                stat = self.ftp.sendcmd("STAT")
            except Exception:
                pass

        return InfoResult(banner, help_response, syst, stat)

    def anonymous(self) -> bool:
        """Attempts anonymous authentication

        Returns:
            bool: result
        """
        try:
            self.ftp.login()
            return True
        except ftplib.Error:
            return False

    def access_check(self) -> AccessCheckResult:
        """
        Attempts to login with all available valid credentials
        (including anonymous) and perform:
        - directory listing
        - file write
        - file read
        - file delete (just cleanup)

        Returns:
            AccessCheckResult: results
        """
        access_permissions: list[AccessPermissions] = []

        # Construct a list of all valid credentials
        all_creds: list[Creds] = []

        if self.results.anonymous:
            all_creds.append(Creds("anonymous", ""))

        if self.results.creds is not None:
            all_creds.extend(self.results.creds)

        if len(all_creds) == 0:
            return AccessCheckResult(["No valid credentials"], None)

        # Check all credentials
        errors: list[str] = []
        for creds in all_creds:
            ftp = self.connect()
            try:
                ftp.login(creds.user, creds.passw)
            except Exception as e:
                # Valid creds but server-side error
                errors.append(str(e))
                access_permissions.append(AccessPermissions(creds, None, None, None, None))
                continue

            write, read, delete = None, None, None
            ach = AccessCheckHelper()

            # Directory listing
            try:
                ftp.dir(ach.read_callback)
            except Exception as e:
                # Unexpected error, maybe timeout or similar
                errors.append(str(e))
                access_permissions.append(AccessPermissions(creds, None, None, None, None))
                continue

            # Root and top-level directories
            directories: list[str] = [""]
            if ach.lines_read is not None:
                for l in ach.lines_read:
                    # LIST response format is not standardised
                    # expecting and trying to parse the following format:
                    # drwxr-xr-x  2 root   root    4096 May  3 13:57 spaces in name

                    # Not a directory
                    if l[0] != "d":
                        continue

                    # Directory
                    try:
                        after_colon = l.split(":")[1:][0]
                        after_space = after_colon.split(" ")[1:]
                        dir_name = " ".join(after_space)
                        directories.append(dir_name)
                    except:
                        errors.append(f"Unknown response format: {l}")
                        access_permissions.append(
                            AccessPermissions(creds, ach.lines_read, None, None, None)
                        )

            text = BytesIO(b"FILE WRITE TEST")
            filename = "".join(random.choices(ascii_uppercase, k=15)) + ".txt"

            # Check permissions in parsed directories
            for dir in directories:
                # Record only the first successful hit
                if write is not None:
                    break

                text.seek(0)
                filepath = dir + "/" + filename

                # Write
                try:
                    ftp.storlines("STOR " + filepath, text)
                    write = filepath
                except ftplib.Error:
                    pass

                # Read
                if write:
                    try:
                        ftp.retrlines("RETR " + filepath, nop_callback)
                        read = filepath
                    except ftplib.Error:
                        pass

                # Delete
                if write:
                    try:
                        ftp.delete(filepath)
                        delete = filepath
                    except ftplib.Error:
                        pass

            access_permissions.append(
                AccessPermissions(
                    creds,
                    ach.lines_read,
                    write,
                    read,
                    delete,
                )
            )

        if len(errors) == 0:
            return AccessCheckResult(None, access_permissions)
        else:
            return AccessCheckResult(errors, access_permissions)

    def _on_brute_success(self, cred: Creds) -> None:
        """Callback for real-time streaming of found credentials (thread-safe).
        Streams login success immediately; permissions come from access_check() in output()."""
        with self._output_lock:
            self.ptprint(f"    user: {cred.user}, password: {cred.passw}", Out.TEXT)

    def _path_enum_worker(self, chunk: list[str], creds: Creds) -> list[PathEnumResult]:
        """Worker for path enumeration. Processes a chunk of paths with one FTP connection.
        Respects FTP sticky state: after each test returns to base_path to avoid false results."""
        results: list[PathEnumResult] = []
        ftp = self.connect()
        try:
            ftp.login(creds.user, creds.passw)
            base_path = getattr(self.args, "base_path", "") or ""
            # Resolve effective base: use pwd() if base_path empty (login home)
            if base_path:
                try:
                    ftp.cwd(base_path)
                except ftplib.Error:
                    pass  # server may not support, continue with current dir
                effective_base = base_path
            else:
                try:
                    effective_base = ftp.pwd()
                except (ftplib.Error, AttributeError):
                    effective_base = "/"

            def _reset_to_base() -> None:
                """Return to base to avoid sticky state affecting next path test."""
                try:
                    ftp.cwd(effective_base)
                except ftplib.Error:
                    pass

            for path in chunk:
                path = path.strip().lstrip("/")  # normalize: relative to effective_base
                if not path or path.startswith("#"):
                    continue
                _reset_to_base()
                # Try CWD first (directory) – 250 = exists
                try:
                    ftp.cwd(path)
                    results.append(
                        PathEnumResult(path=path, exists=True, is_directory=True, size=None)
                    )
                    continue  # _reset_to_base done at loop start
                except ftplib.error_perm as e:
                    err_str = str(e)
                    if "550" not in err_str and "550" not in str(e.args):
                        continue  # other permission error, skip
                except ftplib.Error:
                    continue
                # CWD failed (550) – try SIZE (file). Note: SIZE is RFC 3659; some older
                # servers may not support it and return error even when file exists.
                try:
                    size = ftp.size(path)
                    results.append(
                        PathEnumResult(path=path, exists=True, is_directory=False, size=size)
                    )
                except ftplib.Error:
                    pass  # path does not exist
        finally:
            try:
                ftp.close()
            except Exception:
                pass
        return results

    def path_enumeration(self, creds: Creds, paths: list[str]) -> list[PathEnumResult]:
        """Dictionary attack for path discovery. Each thread uses one connection and processes
        a chunk of paths, resetting to base_path after each test (FTP sticky state)."""
        if not paths:
            return []
        enum_threads = max(1, getattr(self.args, "enum_threads", 5))
        # Split paths into chunks (one per thread)
        k, m = divmod(len(paths), enum_threads)
        chunks = [
            paths[i * k + min(i, m) : (i + 1) * k + min(i + 1, m)]
            for i in range(enum_threads)
        ]
        chunks = [c for c in chunks if c]

        def worker(chunk: list[str]) -> list[PathEnumResult]:
            return self._path_enum_worker(chunk, creds)

        pt = ptthreads.PtThreads(print_errors=False)
        raw_returns = pt.threads(chunks, worker, min(len(chunks), enum_threads)) or []
        # Flatten and deduplicate by path
        seen: set[str] = set()
        flat: list[PathEnumResult] = []
        for r in raw_returns:
            if isinstance(r, list):
                for p in r:
                    if p.path not in seen:
                        seen.add(p.path)
                        flat.append(p)
        return flat

    @staticmethod
    def _norm_ftp_reply_text(s: str) -> str:
        if not s:
            return ""
        t = s.strip().lower()
        t = re.sub(r"\s+", " ", t)
        return t[:240]

    _FTP_USER_ENUM_TIMING_WARMUP = 3

    @staticmethod
    def _user_enum_reply_template(line: str) -> str:
        """Collapse quoted usernames / 'for user' style slots so e.g. User 'admin' vs User 'root' match template."""
        t = (line or "").strip()
        t = re.sub(r"\s+", " ", t).lower()
        t = re.sub(r"'[^'\n]{1,128}'", "'<u>'", t)
        t = re.sub(r'"[^"\n]{1,128}"', '"<u>"', t)
        t = re.sub(r"\bfor\s+[a-z0-9][a-z0-9._-]{0,63}\b", "for <u>", t)
        t = re.sub(r"\buser\s+[a-z0-9][a-z0-9._-]{0,63}\b", "user <u>", t)
        return t[:240]

    @staticmethod
    def _user_enum_timing_after_warmup(ms_ordered: list[float], max_drop: int) -> list[float]:
        """Drop first max_drop samples when cohort is long enough (TCP/TLS cold start, jitter)."""
        if len(ms_ordered) > max_drop:
            return ms_ordered[max_drop:]
        return list(ms_ordered)

    def _user_enum_keepalive_tarpitting_hint(self, ok_rows: list[FtpUserEnumProbeRow]) -> bool:
        """True when PASS-phase latency tends to grow across sequential probes (one session)."""
        ordered = sorted(ok_rows, key=lambda r: r.probe_index)
        seq = [
            float(r.pass_elapsed_ms)
            for r in ordered
            if r.pass_elapsed_ms is not None and r.user_reply_code in (331, 332)
        ]
        if len(seq) < 4:
            return False
        diffs = [seq[i + 1] - seq[i] for i in range(len(seq) - 1)]
        need = max(2, (len(diffs) + 1) // 2)
        return sum(1 for d in diffs if d > 35.0) >= need

    def _ftp_parse_reply_line(self, msg: str) -> tuple[int | None, str]:
        s = str(msg).strip()
        if len(s) >= 3 and s[:3].isdigit():
            return int(s[:3]), s
        return None, s

    def _ftp_user_pass_probe(
        self,
        ftp: ftplib.FTP | ftplib.FTP_TLS | FTP_TLS_implicit,
        username: str,
        wrong_pass: str,
        probe_kind: str,
        probe_index: int,
    ) -> FtpUserEnumProbeRow:
        ucode: int | None = None
        uline = ""
        try:
            uresp = ftp.sendcmd("USER " + username)
            ucode, uline = self._ftp_parse_reply_line(uresp)
        except ftplib.error_perm as e:
            raw = str(e.args[0]) if e.args else str(e)
            ucode, uline = self._ftp_parse_reply_line(raw)
        except Exception as e:
            return FtpUserEnumProbeRow(
                username, probe_kind, None, "", None, "", None, False, str(e), probe_index
            )

        pcode: int | None = None
        pline = ""
        pass_ms: float | None = None

        if ucode in (331, 332):
            t0 = time.perf_counter()
            try:
                presp = ftp.sendcmd("PASS " + wrong_pass)
                pcode, pline = self._ftp_parse_reply_line(presp)
            except ftplib.error_perm as e:
                raw = str(e.args[0]) if e.args else str(e)
                pcode, pline = self._ftp_parse_reply_line(raw)
            except Exception as e:
                pass_ms = (time.perf_counter() - t0) * 1000
                return FtpUserEnumProbeRow(
                    username, probe_kind, ucode, uline, None, "", pass_ms, False, str(e), probe_index
                )
            pass_ms = (time.perf_counter() - t0) * 1000
        else:
            pcode = ucode
            pline = uline

        conn_ok = True
        try:
            ftp.voidcmd("NOOP")
        except Exception:
            conn_ok = False

        return FtpUserEnumProbeRow(
            username, probe_kind, ucode, uline, pcode, pline, pass_ms, conn_ok, None, probe_index
        )

    def _user_enum_sequential_keepalive(
        self, work: list[tuple[str, str, int]], wrong_pass: str
    ) -> list[FtpUserEnumProbeRow]:
        rows: list[FtpUserEnumProbeRow] = []
        ftp: ftplib.FTP | ftplib.FTP_TLS | FTP_TLS_implicit | None = None
        for username, kind, pidx in work:
            if ftp is None:
                ftp = self.connect()
            row = self._ftp_user_pass_probe(ftp, username, wrong_pass, kind, pidx)
            rows.append(row)
            if row.error or not row.connection_ok_after:
                try:
                    ftp.close()
                except Exception:
                    pass
                ftp = None
        if ftp is not None:
            try:
                ftp.quit()
            except Exception:
                try:
                    ftp.close()
                except Exception:
                    pass
        return rows

    def _user_enum_worker_chunk(
        self, chunk: list[tuple[str, str, int]], wrong_pass: str
    ) -> list[FtpUserEnumProbeRow]:
        out: list[FtpUserEnumProbeRow] = []
        for username, kind, pidx in chunk:
            ftp = self.connect()
            try:
                out.append(self._ftp_user_pass_probe(ftp, username, wrong_pass, kind, pidx))
            finally:
                try:
                    ftp.quit()
                except Exception:
                    try:
                        ftp.close()
                    except Exception:
                        pass
        return out

    def _user_enum_parallel_or_serial(
        self, work: list[tuple[str, str, int]], wrong_pass: str, threads: int
    ) -> list[FtpUserEnumProbeRow]:
        if not work:
            return []
        th = max(1, threads)
        if th <= 1 or len(work) == 1:
            return self._user_enum_worker_chunk(work, wrong_pass)
        k, m = divmod(len(work), th)
        chunks: list[list[tuple[str, str, int]]] = [
            work[i * k + min(i, m) : (i + 1) * k + min(i + 1, m)] for i in range(th)
        ]
        chunks = [c for c in chunks if c]

        def worker(chunk: list[tuple[str, str, int]]) -> list[FtpUserEnumProbeRow]:
            return self._user_enum_worker_chunk(chunk, wrong_pass)

        pt = ptthreads.PtThreads(print_errors=False)
        raw_returns = pt.threads(chunks, worker, min(len(chunks), th)) or []
        flat: list[FtpUserEnumProbeRow] = []
        for r in raw_returns:
            if isinstance(r, list):
                flat.extend(r)
        flat.sort(key=lambda row: row.probe_index)
        return flat

    def _analyze_user_enum_result(
        self,
        rows: list[FtpUserEnumProbeRow],
        do_timing: bool,
        *,
        used_keep_alive: bool,
        parallel_threads: int,
    ) -> FtpUserEnumResult:
        ok_rows = [r for r in rows if r.error is None]
        user_codes = sorted({r.user_reply_code for r in ok_rows if r.user_reply_code is not None})
        tnotes: list[str] = []

        pass_norms: list[str] = []
        for r in ok_rows:
            if r.user_reply_code in (331, 332) and r.pass_reply_line:
                pass_norms.append(self._norm_ftp_reply_text(r.pass_reply_line))
        distinct_pass_norms = tuple(sorted(set(pass_norms)))

        user_line_norms = sorted(
            {self._norm_ftp_reply_text(r.user_reply_line) for r in ok_rows if r.user_reply_line}
        )
        user_line_norms = [u for u in user_line_norms if u]

        pass_lines = [
            r.pass_reply_line
            for r in ok_rows
            if r.user_reply_code in (331, 332) and r.pass_reply_line
        ]
        sim_min: float | None = None
        if len(pass_lines) >= 2:
            ratios: list[float] = []
            for i in range(len(pass_lines)):
                for j in range(i + 1, len(pass_lines)):
                    raw_r = SequenceMatcher(None, pass_lines[i], pass_lines[j]).ratio()
                    tpl_r = SequenceMatcher(
                        None,
                        self._user_enum_reply_template(pass_lines[i]),
                        self._user_enum_reply_template(pass_lines[j]),
                    ).ratio()
                    ratios.append(max(raw_r, tpl_r))
            sim_min = min(ratios) if ratios else None

        enumeration_suspected = False
        detail_parts: list[str] = []

        if len(user_codes) >= 2:
            enumeration_suspected = True
            detail_parts.append("Distinct USER-stage numeric codes across probes (RFC 2577 section 7 misalignment).")

        if len(user_codes) == 1 and len(user_line_norms) >= 2:
            enumeration_suspected = True
            detail_parts.append("Same USER-stage code but differing reply text (possible username oracle).")

        if len(distinct_pass_norms) >= 2:
            enumeration_suspected = True
            detail_parts.append("Distinct PASS-stage replies after 331/332 (wrong password path).")

        if sim_min is not None and sim_min < 0.92 and len(distinct_pass_norms) < 2 and len(pass_lines) >= 3:
            enumeration_suspected = True
            detail_parts.append(
                f"Low fuzzy similarity between PASS replies (min raw/template SequenceMatcher ratio {sim_min:.2f})."
            )

        timing_anomaly = False
        tarpit_hint = False
        if do_timing and used_keep_alive:
            tarpit_hint = self._user_enum_keepalive_tarpitting_hint(ok_rows)

        timing_control_median_ms: float | None = None
        timing_wordlist_median_ms: float | None = None
        slow_samples: list[tuple[str, float]] = []

        if do_timing:
            wu = self._FTP_USER_ENUM_TIMING_WARMUP
            cand_rows = [
                r
                for r in ok_rows
                if r.probe_kind == "wordlist"
                and r.pass_elapsed_ms is not None
                and r.user_reply_code in (331, 332)
            ]
            cand_rows.sort(key=lambda r: r.probe_index)
            cand_ms = [float(r.pass_elapsed_ms) for r in cand_rows]
            ctrl_rows = [
                r
                for r in ok_rows
                if r.probe_kind.startswith("control")
                and r.pass_elapsed_ms is not None
                and r.user_reply_code in (331, 332)
            ]
            ctrl_rows.sort(key=lambda r: r.probe_index)
            ctrl_ms = [float(r.pass_elapsed_ms) for r in ctrl_rows]

            would_time_anomaly = False
            time_detail = ""
            if len(cand_ms) >= 2 and len(ctrl_ms) >= 1:
                cand_adj = self._user_enum_timing_after_warmup(cand_ms, wu)
                ctrl_adj = self._user_enum_timing_after_warmup(ctrl_ms, wu)
                if len(cand_ms) > wu or len(ctrl_ms) > wu:
                    tnotes.append("timingMedianAfterWarmupDropFirst3PerCohort")
                if len(cand_adj) >= 1 and len(ctrl_adj) >= 1:
                    mc = float(statistics.median(ctrl_adj))
                    mw = float(statistics.median(cand_adj))
                    timing_control_median_ms = mc
                    timing_wordlist_median_ms = mw
                    thr = mc * 2.0 + 20.0
                    for r in cand_rows:
                        if r.pass_elapsed_ms is not None:
                            ms = float(r.pass_elapsed_ms)
                            if ms > thr:
                                slow_samples.append((r.username, ms))
                    if mw > mc * 2.0 + 20.0:
                        would_time_anomaly = True
                        time_detail = (
                            f"PASS-phase median latency (post-warmup): wordlist {mw:.1f} ms vs controls {mc:.1f} ms "
                            "(--user-enum-timing; median, not mean)."
                        )
            if parallel_threads > 1:
                tnotes.append("parallelConnectionsTimingComparedByGlobalProbeOrder")

            if would_time_anomaly and tarpit_hint:
                timing_anomaly = False
                slow_samples.clear()
                detail_parts.append(
                    "Timing comparison suppressed: sequential PASS latency grows like tarpitting/delay policy, "
                    "not a reliable user-oracle signal in --user-enum-keep-alive mode."
                )
                tnotes.append("timingSuppressedSuspectedTarpitting")
            elif would_time_anomaly:
                timing_anomaly = True
                detail_parts.append(time_detail)
                if used_keep_alive and not tarpit_hint:
                    tnotes.append("keepAliveMayStillTarpitWithoutMonotonicPattern")

        for r in ok_rows:
            if (
                r.user_reply_code in (331, 332)
                and r.pass_reply_code is not None
                and 200 <= r.pass_reply_code < 300
            ):
                enumeration_suspected = True
                detail_parts.append(
                    f"Unexpected 2xx after PASS for probe {r.username!r} (fixed wrong password) — verify manually."
                )

        if not detail_parts:
            detail_parts.append("No strong USER/PASS differentiation observed in this sample (heuristic).")

        return FtpUserEnumResult(
            probes=tuple(rows),
            fixed_password_marker="(fixed_wrong_password_sent)",
            distinct_user_reply_codes=tuple(user_codes),
            distinct_pass_reply_norms=distinct_pass_norms,
            enumeration_suspected=enumeration_suspected,
            timing_anomaly_suspected=timing_anomaly,
            pass_text_similarity_min=sim_min,
            detail=" ".join(detail_parts),
            timing_notes=tuple(tnotes),
            timing_control_median_ms=timing_control_median_ms,
            timing_wordlist_median_ms=timing_wordlist_median_ms,
            timing_slow_usernames_ms=tuple(slow_samples),
        )

    def test_user_enumeration(self) -> FtpUserEnumResult:
        """PTL-SVC-FTP-USRENUM: USER then fixed wrong PASS; control users + optional timing / keep-alive."""
        wl = getattr(self.args, "user_enum_wordlist", None)
        if not wl:
            raise ValueError("user_enum_wordlist is required")
        raw = text_or_file(None, wl)
        names = [ln.strip() for ln in raw if ln.strip() and not ln.strip().startswith("#")]
        ue_mx = int(getattr(self.args, "user_enum_max", 0) or 0)
        if ue_mx > 0:
            names = names[:ue_mx]
        hex8 = secrets.token_hex(4)
        work: list[tuple[str, str, int]] = []
        pidx = 0
        for n in names:
            work.append((n, "wordlist", pidx))
            pidx += 1
        work.append((f"enumtest_invalid_{hex8}", "control_invalid_random", pidx))
        pidx += 1
        work.append(("a" * 256, "control_long", pidx))
        pidx += 1
        work.append(("admin'", "control_special", pidx))
        pidx += 1
        work.append(("admin%", "control_special", pidx))

        pwd = getattr(self.args, "user_enum_password", None) or "PtsrvUEnumWrongPass!77~"
        keep_alive = bool(getattr(self.args, "user_enum_keep_alive", False))
        threads = max(1, int(getattr(self.args, "user_enum_threads", 1) or 1))
        do_timing = bool(getattr(self.args, "user_enum_timing", False))

        if keep_alive:
            rows = self._user_enum_sequential_keepalive(work, pwd)
        else:
            rows = self._user_enum_parallel_or_serial(work, pwd, threads)

        return self._analyze_user_enum_result(
            rows, do_timing, used_keep_alive=keep_alive, parallel_threads=threads
        )

    def _parse_pasv_ip(self, reply: str) -> str | None:
        """Extract IP from PASV 227 reply. RFC 1123: format varies, scan for digits."""
        m = re.search(r"(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)", reply)
        if m:
            return f"{m.group(1)}.{m.group(2)}.{m.group(3)}.{m.group(4)}"
        return None

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private ranges (10.x, 172.16-31.x, 192.168.x)."""
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private
        except ValueError:
            return False

    def test_modes(self, creds: Creds) -> ModesResult:
        """
        Test passive and active mode availability. Requires data transfer (LIST/NLST).
        Checks PASV response for IP leakage (internal IP advertised when connecting from outside).
        """
        passive_ok = False
        active_ok = False
        pasv_ip_leak: str | None = None
        target_ip = self.args.target.ip
        try:
            ipaddress.ip_address(target_ip)
        except ValueError:
            try:
                target_ip = socket.gethostbyname(target_ip)
            except Exception:
                target_ip = ""

        # Test passive mode + IP leakage
        ftp = self.connect()
        try:
            ftp.login(creds.user, creds.passw)
            ftp.set_pasv(True)
            # Get raw 227 reply for IP leakage check. ftplib processes PASV internally in
            # transfercmd(), but sendcmd("PASV") returns the raw response string for parsing.
            # voidcmd("PASV") would also return it for 2xx; we use sendcmd for explicitness.
            try:
                reply = ftp.sendcmd("PASV")
                pasv_ip = self._parse_pasv_ip(reply)
                # IP leak: PASV IP differs from target (e.g. internal IP exposed when connecting from outside)
                if pasv_ip and target_ip and pasv_ip != target_ip:
                    pasv_ip_leak = pasv_ip
            except ftplib.Error:
                pass
            # Actual passive data transfer test (sends new PASV, previous was for leak check)
            try:
                ach = AccessCheckHelper()
                ftp.dir(ach.read_callback)
                passive_ok = True
            except ftplib.Error:
                pass
        finally:
            try:
                ftp.close()
            except Exception:
                pass

        # Test active mode (new connection)
        ftp = self.connect()
        try:
            ftp.login(creds.user, creds.passw)
            ftp.set_pasv(False)
            try:
                ach = AccessCheckHelper()
                ftp.dir(ach.read_callback)
                active_ok = True
            except ftplib.Error:
                pass
        finally:
            try:
                ftp.close()
            except Exception:
                pass

        return ModesResult(passive_ok=passive_ok, active_ok=active_ok, pasv_ip_leak=pasv_ip_leak)

    def _pasv_list_data_port_once(self, ftp: ftplib.FTP) -> tuple[int | None, str | None]:
        """
        Force passive mode, open a real LIST data channel, return the server's TCP data port
        (client socket getpeername), then drain listing and complete the transfer.
        """
        ftp.set_pasv(True)
        to = 20.0
        old_to = None
        try:
            try:
                old_to = ftp.sock.gettimeout()
                ftp.sock.settimeout(to)
            except Exception:
                pass
            sock = ftp.transfercmd("LIST")
            port: int | None = None
            try:
                sock.settimeout(to)
                peer = sock.getpeername()
                if isinstance(peer, tuple) and len(peer) >= 2:
                    port = int(peer[1])
                while True:
                    chunk = sock.recv(8192)
                    if not chunk:
                        break
            finally:
                try:
                    sock.close()
                except Exception:
                    pass
            try:
                ftp.voidresp()
            except ftplib.Error as e:
                # Some servers still completed data; port observation remains useful
                if port is None:
                    return None, str(e).strip() or repr(e)
            return port, None
        except Exception as e:
            err = str(e).strip() or type(e).__name__
            try:
                ftp.close()
            except Exception:
                pass
            return None, err
        finally:
            try:
                if old_to is not None:
                    ftp.sock.settimeout(old_to)
            except Exception:
                pass

    def test_pasv_port_range_audit(
        self, creds: Creds, sample_count: int, max_span_threshold: int
    ) -> PasvPortRangeResult:
        """
        PTL-SVC-FTP-PASIVE: several separate control connections, each login + passive LIST;
        if observed port spread (max-min) exceeds max_span_threshold, flag wide passive range
        (firewall rule burden / larger attack surface).
        """
        min_for_verdict = 4
        probes: list[PasvPortRangeProbe] = []
        ports_ok: list[int] = []

        for i in range(sample_count):
            ftp = self.connect()
            err: str | None = None
            port: int | None = None
            try:
                ftp.login(creds.user, creds.passw)
                port, err = self._pasv_list_data_port_once(ftp)
                if port is not None:
                    ports_ok.append(port)
            except Exception as e:
                err = str(e).strip() or type(e).__name__
            finally:
                try:
                    ftp.close()
                except Exception:
                    pass
            probes.append(PasvPortRangeProbe(sample_index=i, data_port=port, error=err))

        ok_t = tuple(ports_ok)
        if len(ports_ok) < min_for_verdict:
            detail = (
                f"Only {len(ports_ok)}/{sample_count} passive LIST transfers yielded a data port; "
                "need at least 4 for a spread estimate. Check connectivity, TLS vs plaintext, or permissions."
            )
            return PasvPortRangeResult(
                probes=tuple(probes),
                successful_ports=ok_t,
                min_port=min(ports_ok) if ports_ok else None,
                max_port=max(ports_ok) if ports_ok else None,
                observed_span=(max(ports_ok) - min(ports_ok)) if len(ports_ok) >= 2 else None,
                max_span_threshold=max_span_threshold,
                min_samples_for_verdict=min_for_verdict,
                wide_passive_range=False,
                inconclusive=True,
                detail=detail,
            )

        lo, hi = min(ports_ok), max(ports_ok)
        span = hi - lo
        wide = span > max_span_threshold
        detail = (
            f"Observed data ports across {len(ports_ok)} successful sample(s): "
            f"min={lo}, max={hi}, span={span} (threshold maxSpan={max_span_threshold}). "
            + (
                "Spread is large in this run — firewall policies may need a very wide passive port allow-list."
                if wide
                else "Spread stays within the configured threshold (prefer also documenting the server's configured passive range in policy)."
            )
        )
        return PasvPortRangeResult(
            probes=tuple(probes),
            successful_ports=ok_t,
            min_port=lo,
            max_port=hi,
            observed_span=span,
            max_span_threshold=max_span_threshold,
            min_samples_for_verdict=min_for_verdict,
            wide_passive_range=wide,
            inconclusive=False,
            detail=detail,
        )

    def _conn_limits_read220_quit(self, sock: socket.socket) -> tuple[bool, str | None]:
        sock.settimeout(12.0)
        buf = b""
        try:
            while b"\n" not in buf and len(buf) < 8192:
                c = sock.recv(2048)
                if not c:
                    return False, "EOF before banner line"
                buf += c
                if b"220" in buf:
                    break
            if b"220" not in buf:
                return False, "no 220 in initial response"
            try:
                sock.sendall(b"QUIT\r\n")
            except OSError:
                pass
            return True, None
        except Exception as e:
            return False, str(e)

    def _conn_limits_drain_banner_raw(self, sock: socket.socket) -> tuple[bool, str | None]:
        sock.settimeout(12.0)
        buf = b""
        while b"220" not in buf and len(buf) < 16384:
            c = sock.recv(2048)
            if not c:
                return False, "EOF before 220"
            buf += c
        return True, None

    @staticmethod
    def _conn_limits_readline_socket(
        sock: socket.socket, buf: bytearray, timeout: float = 30.0
    ) -> tuple[str, bool]:
        sock.settimeout(timeout)
        while True:
            if b"\n" in buf:
                idx = buf.index(b"\n")
                raw = bytes(buf[: idx + 1])
                del buf[: idx + 1]
                return raw.decode(errors="replace").strip(), False
            chunk = sock.recv(4096)
            if not chunk:
                return "", True
            buf.extend(chunk)

    def _conn_limits_one_handshake(self) -> tuple[bool, str | None]:
        host = self.args.target.ip
        port = self.args.target.port
        try:
            if self.args.tls:
                ctx = ssl.create_default_context()
                raw = socket.create_connection((host, port), timeout=10)
                try:
                    ss = ctx.wrap_socket(raw, server_hostname=host)
                except Exception:
                    try:
                        raw.close()
                    except Exception:
                        pass
                    raise
                ok, err = self._conn_limits_read220_quit(ss)
                try:
                    ss.close()
                except Exception:
                    pass
                return ok, err
            if self.args.starttls:
                f = ftplib.FTP_TLS()
                f.connect(host, port, timeout=10)
                f.sock.settimeout(12.0)
                f.auth()
                try:
                    f.quit()
                except Exception:
                    try:
                        f.close()
                    except Exception:
                        pass
                return True, None
            raw = socket.create_connection((host, port), timeout=10)
            ok, err = self._conn_limits_read220_quit(raw)
            try:
                raw.close()
            except Exception:
                pass
            return ok, err
        except Exception as e:
            return False, f"{type(e).__name__}: {e}"

    def _conn_limits_parallel_phase(self, n: int) -> ConnLimitsParallelOutcome:
        errs: list[str] = []
        ok_c = 0
        fail_c = 0

        def _worker(_i: int) -> tuple[bool, str | None]:
            return self._conn_limits_one_handshake()

        with ThreadPoolExecutor(max_workers=max(1, n)) as ex:
            futures = [ex.submit(_worker, i) for i in range(n)]
            for fut in as_completed(futures):
                s_ok, err = fut.result()
                if s_ok:
                    ok_c += 1
                else:
                    fail_c += 1
                    if err and len(errs) < 5:
                        errs.append(err)
        return ConnLimitsParallelOutcome(
            attempted=n, succeeded=ok_c, failed=fail_c, error_samples=tuple(errs)
        )

    def _conn_limits_sequential_phase(self, n: int, delay_s: float) -> ConnLimitsSequentialOutcome:
        errs: list[str] = []
        ok_c = 0
        fail_c = 0
        for _ in range(n):
            s_ok, err = self._conn_limits_one_handshake()
            if s_ok:
                ok_c += 1
            else:
                fail_c += 1
                if err and len(errs) < 5:
                    errs.append(err)
            if delay_s > 0:
                time.sleep(delay_s)
        return ConnLimitsSequentialOutcome(
            attempts=n,
            succeeded=ok_c,
            failed=fail_c,
            inter_connect_delay_ms=delay_s * 1000.0,
            error_samples=tuple(errs),
        )

    def _conn_limits_pasv_pre_auth_session(self, attempts: int) -> ConnLimitsPasvSpam:
        if attempts <= 0:
            return ConnLimitsPasvSpam(0, 0, 0, 0, None, None)
        host = self.args.target.ip
        port = self.args.target.port
        n227 = n530 = nother = 0
        last: str | None = None
        err: str | None = None
        try:
            if self.args.starttls:
                ftp = ftplib.FTP_TLS()
                ftp.connect(host, port, timeout=10)
                ftp.sock.settimeout(25.0)
                ftp.auth()
                for _ in range(attempts):
                    r = ftp.sendcmd("PASV")
                    last = r[:200]
                    c = self._reply_code(r)
                    if c == 227:
                        n227 += 1
                    elif c == 530:
                        n530 += 1
                    else:
                        nother += 1
                try:
                    ftp.quit()
                except Exception:
                    ftp.close()
                return ConnLimitsPasvSpam(attempts, n227, n530, nother, last, None)

            if self.args.tls:
                ctx = ssl.create_default_context()
                raw = socket.create_connection((host, port), timeout=10)
                ss = ctx.wrap_socket(raw, server_hostname=host)
                okb, e = self._conn_limits_drain_banner_raw(ss)
                if not okb:
                    try:
                        ss.close()
                    except Exception:
                        pass
                    return ConnLimitsPasvSpam(0, 0, 0, 0, None, e or "banner")
                buf = bytearray()
                for _ in range(attempts):
                    ss.sendall(b"PASV\r\n")
                    line, eof = self._conn_limits_readline_socket(ss, buf, 25.0)
                    if eof and not line:
                        err = "EOF during PASV phase"
                        break
                    last = line[:200]
                    c = self._reply_code(line) if line else None
                    if c == 227:
                        n227 += 1
                    elif c == 530:
                        n530 += 1
                    else:
                        nother += 1
                try:
                    ss.sendall(b"QUIT\r\n")
                except Exception:
                    pass
                try:
                    ss.close()
                except Exception:
                    pass
                return ConnLimitsPasvSpam(attempts, n227, n530, nother, last, err)

            raw = socket.create_connection((host, port), timeout=10)
            okb, e = self._conn_limits_drain_banner_raw(raw)
            if not okb:
                try:
                    raw.close()
                except Exception:
                    pass
                return ConnLimitsPasvSpam(0, 0, 0, 0, None, e or "banner")
            buf = bytearray()
            for _ in range(attempts):
                raw.sendall(b"PASV\r\n")
                line, eof = self._conn_limits_readline_socket(raw, buf, 25.0)
                if eof and not line:
                    err = "EOF during PASV phase"
                    break
                last = line[:200]
                c = self._reply_code(line) if line else None
                if c == 227:
                    n227 += 1
                elif c == 530:
                    n530 += 1
                else:
                    nother += 1
            try:
                raw.sendall(b"QUIT\r\n")
            except Exception:
                pass
            try:
                raw.close()
            except Exception:
                pass
            return ConnLimitsPasvSpam(attempts, n227, n530, nother, last, err)
        except Exception as e:
            return ConnLimitsPasvSpam(attempts, n227, n530, nother, last, str(e))

    def _conn_limits_pasv_post_auth_session(self, creds: Creds, attempts: int) -> ConnLimitsPasvSpam:
        if attempts <= 0:
            return ConnLimitsPasvSpam(0, 0, 0, 0, None, None)
        n227 = n530 = nother = 0
        last: str | None = None
        ftp = self.connect()
        try:
            ftp.login(creds.user, creds.passw)
            ftp.sock.settimeout(25.0)
            for _ in range(attempts):
                r = ftp.sendcmd("PASV")
                last = r[:200]
                c = self._reply_code(r)
                if c == 227:
                    n227 += 1
                elif c == 530:
                    n530 += 1
                else:
                    nother += 1
            try:
                ftp.quit()
            except Exception:
                ftp.close()
            return ConnLimitsPasvSpam(attempts, n227, n530, nother, last, None)
        except Exception as e:
            try:
                ftp.close()
            except Exception:
                pass
            return ConnLimitsPasvSpam(attempts, n227, n530, nother, last, str(e))

    def _conn_limits_idle_pre_auth(self, wait_sec: float) -> ConnLimitsIdleProbe:
        if wait_sec <= 0:
            return ConnLimitsIdleProbe(False, 0.0, False, "skipped")
        kick = False
        note = ""
        ftp: ftplib.FTP | ftplib.FTP_TLS | FTP_TLS_implicit | None = None
        try:
            ftp = self.connect()
            sock = ftp.sock
            deadline = time.monotonic() + wait_sec
            while time.monotonic() < deadline:
                rem = deadline - time.monotonic()
                if rem <= 0:
                    break
                r, _, _ = select.select([sock], [], [], min(1.0, max(0.01, rem)))
                if r:
                    try:
                        d = sock.recv(8192)
                        if not d:
                            kick = True
                            note = "peer closed during idle"
                            break
                        if b"421" in d or b"426" in d:
                            kick = True
                            note = "421/426 during idle"
                            break
                    except OSError as e:
                        kick = True
                        note = str(e)
                        break
            if not kick:
                note = "no 421/close within idle window"
        except Exception as e:
            return ConnLimitsIdleProbe(True, wait_sec, False, str(e))
        finally:
            if ftp:
                try:
                    ftp.close()
                except Exception:
                    pass
        return ConnLimitsIdleProbe(True, wait_sec, kick, note)

    def _conn_limits_slow_auth(self, gap: float) -> ConnLimitsSlowAuth:
        if gap <= 0:
            return ConnLimitsSlowAuth(False, 0.0, None, None, "skipped")
        marker_user = "ptsrv_conn_slow_probe"
        marker_pass = "PtsrvWrongPass!9~"
        host = self.args.target.ip
        port = self.args.target.port
        try:
            if self.args.tls:
                ctx = ssl.create_default_context()
                raw = socket.create_connection((host, port), timeout=10)
                ss = ctx.wrap_socket(raw, server_hostname=host)
                okb, err = self._conn_limits_drain_banner_raw(ss)
                if not okb:
                    try:
                        ss.close()
                    except Exception:
                        pass
                    return ConnLimitsSlowAuth(True, gap, None, None, err or "no banner")
                buf = bytearray()
                ss.sendall(f"USER {marker_user}\r\n".encode())
                _line_u, eof = self._conn_limits_readline_socket(ss, buf, 15.0)
                if eof and not _line_u:
                    try:
                        ss.close()
                    except Exception:
                        pass
                    return ConnLimitsSlowAuth(True, gap, False, None, "EOF after USER")
                time.sleep(gap)
                ss.sendall(f"PASS {marker_pass}\r\n".encode())
                line_p, eof2 = self._conn_limits_readline_socket(ss, buf, 20.0)
                still = bool(line_p) or not eof2
                try:
                    ss.close()
                except Exception:
                    pass
                return ConnLimitsSlowAuth(True, gap, still, (line_p or "")[:180], "implicit TLS control")
            if self.args.starttls:
                f = ftplib.FTP_TLS()
                f.connect(host, port, timeout=10)
                f.sock.settimeout(25.0)
                f.auth()
                f.putcmd(f"USER {marker_user}")
                _ = f.getmultiline()
                time.sleep(gap)
                f.putcmd(f"PASS {marker_pass}")
                resp = f.getmultiline()
                snippet = resp[:180]
                try:
                    f.close()
                except Exception:
                    pass
                return ConnLimitsSlowAuth(True, gap, True, snippet, "STARTTLS control")
            raw = socket.create_connection((host, port), timeout=10)
            okb, err = self._conn_limits_drain_banner_raw(raw)
            if not okb:
                try:
                    raw.close()
                except Exception:
                    pass
                return ConnLimitsSlowAuth(True, gap, None, None, err or "no banner")
            buf = bytearray()
            raw.sendall(f"USER {marker_user}\r\n".encode())
            _line_u, eof = self._conn_limits_readline_socket(raw, buf, 15.0)
            if eof and not _line_u:
                try:
                    raw.close()
                except Exception:
                    pass
                return ConnLimitsSlowAuth(True, gap, False, None, "EOF after USER")
            time.sleep(gap)
            raw.sendall(f"PASS {marker_pass}\r\n".encode())
            line_p, eof2 = self._conn_limits_readline_socket(raw, buf, 20.0)
            still = bool(line_p) or not eof2
            try:
                raw.close()
            except Exception:
                pass
            return ConnLimitsSlowAuth(True, gap, still, (line_p or "")[:180], "plaintext control")
        except Exception as e:
            return ConnLimitsSlowAuth(True, gap, None, None, str(e))

    def _conn_limits_idle_post_auth(self, creds: Creds, wait_sec: float) -> ConnLimitsIdleProbe:
        if wait_sec <= 0:
            return ConnLimitsIdleProbe(False, 0.0, False, "skipped")
        kick = False
        note = ""
        ftp: ftplib.FTP | ftplib.FTP_TLS | FTP_TLS_implicit | None = None
        try:
            ftp = self.connect()
            ftp.login(creds.user, creds.passw)
            sock = ftp.sock
            deadline = time.monotonic() + wait_sec
            while time.monotonic() < deadline:
                rem = deadline - time.monotonic()
                if rem <= 0:
                    break
                r, _, _ = select.select([sock], [], [], min(1.0, max(0.01, rem)))
                if r:
                    try:
                        d = sock.recv(8192)
                        if not d:
                            kick = True
                            note = "peer closed during post-login idle"
                            break
                        if b"421" in d or b"426" in d:
                            kick = True
                            note = "421/426 during post-login idle"
                            break
                    except OSError as e:
                        kick = True
                        note = str(e)
                        break
            if not kick:
                try:
                    ftp.voidcmd("NOOP")
                    note = "NOOP succeeded after idle window (weak idle kick)"
                except ftplib.Error as e:
                    note = f"NOOP after idle: {e}"
                    if "421" in str(e):
                        kick = True
        except Exception as e:
            return ConnLimitsIdleProbe(True, wait_sec, False, str(e))
        finally:
            if ftp:
                try:
                    ftp.close()
                except Exception:
                    pass
        return ConnLimitsIdleProbe(True, wait_sec, kick, note)

    def test_connection_limits_audit(self, creds_post: Creds | None) -> ConnLimitsAuditResult:
        """PTL-SVC-FTP-CONN: bounded connection / PASV / optional idle & slow-auth probes."""
        par_n = max(1, int(getattr(self.args, "conn_limits_parallel", 12) or 12))
        seq_n = max(0, int(getattr(self.args, "conn_limits_sequential", 24) or 24))
        pasv_n = max(0, int(getattr(self.args, "conn_limits_pasv_attempts", 18) or 18))
        idle_pre = float(getattr(self.args, "conn_limits_idle_pre_auth", 0) or 0)
        slow_gap = float(getattr(self.args, "conn_limits_slow_auth_gap", 0) or 0)
        idle_post = float(getattr(self.args, "conn_limits_idle_post_auth", 0) or 0)

        if self.args.tls:
            crypto_mode = "implicit_tls"
        elif self.args.starttls:
            crypto_mode = "starttls"
        else:
            crypto_mode = "plain"

        parallel = self._conn_limits_parallel_phase(par_n)
        sequential = (
            self._conn_limits_sequential_phase(seq_n, 0.02)
            if seq_n > 0
            else ConnLimitsSequentialOutcome(0, 0, 0, 20.0, ())
        )
        pasv_pre = self._conn_limits_pasv_pre_auth_session(pasv_n)
        pasv_post = (
            self._conn_limits_pasv_post_auth_session(creds_post, pasv_n)
            if creds_post is not None and pasv_n > 0
            else None
        )
        idle_pre_r = self._conn_limits_idle_pre_auth(idle_pre)
        slow_r = self._conn_limits_slow_auth(slow_gap)
        idle_post_r = (
            self._conn_limits_idle_post_auth(creds_post, idle_post)
            if creds_post is not None and idle_post > 0
            else None
        )

        risk_factors: list[str] = []
        if _conn_limits_parallel_suspect(parallel):
            risk_factors.append(
                f"Parallel burst: all {parallel.attempted} simultaneous control sessions completed (220 + QUIT) with no refusal."
            )
        if _conn_limits_sequential_suspect(sequential):
            risk_factors.append(
                f"Sequential rapid connect: {sequential.succeeded} back-to-back control sessions succeeded without visible throttle."
            )
        if _conn_limits_pasv_pre_suspect(pasv_pre):
            risk_factors.append(
                "Pre-auth PASV spam: most PASV replies were 227 (many passive ports offered before login; 530 on some lines may still be login-gating, not flood control)."
            )
        if pasv_post is not None and _conn_limits_pasv_post_suspect(pasv_post):
            risk_factors.append(
                "Post-auth PASV spam: high rate of 227 replies on one session without error — passive allocations may be unbounded here."
            )
        if _conn_limits_idle_pre_suspect(idle_pre_r):
            risk_factors.append(
                f"Pre-login idle ~{int(idle_pre_r.wait_seconds)}s: no 421/close observed on control channel."
            )
        if _conn_limits_slow_auth_suspect(slow_r):
            risk_factors.append(
                "Slow authentication: long pause between USER and PASS did not drop the control connection before PASS reply."
            )
        if _conn_limits_idle_post_suspect(idle_post_r):
            risk_factors.append(
                "Post-login idle: NOOP still succeeded after long silence — authenticated idle timeout may be weak."
            )

        suspected = len(risk_factors) > 0
        detail = (
            f"cryptoMode={crypto_mode}; parallel {parallel.succeeded}/{parallel.attempted}; "
            f"sequential {sequential.succeeded}/{sequential.attempts}; "
            f"PASV pre 227/530/other={pasv_pre.reply227}/{pasv_pre.reply530}/{pasv_pre.reply_other}"
            + (
                f"; PASV post 227/530/other={pasv_post.reply227}/{pasv_post.reply530}/{pasv_post.reply_other}"
                if pasv_post
                else ""
            )
            + ". Heuristic only — tune probes and confirm on spare lab; not a full DoS test."
        )
        return ConnLimitsAuditResult(
            crypto_mode=crypto_mode,
            parallel=parallel,
            sequential=sequential,
            pasv_pre_auth=pasv_pre,
            pasv_post_auth=pasv_post,
            idle_pre_auth=idle_pre_r,
            slow_auth=slow_r,
            idle_post_auth=idle_post_r,
            limits_insufficient_suspected=suspected,
            risk_factors=tuple(risk_factors),
            detail=detail,
        )

    _CHROOT_STRONG_CWD_PATHS = frozenset(
        {
            "/etc",
            "/root",
            "/proc",
            "/sys",
            "/var/log",
            "/var/www",
            "/srv",
            "/dev",
            "/boot",
            "/bin",
            "/sbin",
            "/usr",
        }
    )
    _CHROOT_DOTDOT_MAX_STEPS = 32

    @staticmethod
    def _chroot_norm_pwd(p: str) -> str:
        s = (p or "").strip().strip('"').strip("'")
        if not s:
            return "/"
        return posixpath.normpath(s.replace("\\", "/"))

    @staticmethod
    def _chroot_strict_ancestor(ancestor: str, descendant: str) -> bool:
        a = FTP._chroot_norm_pwd(ancestor)
        d = FTP._chroot_norm_pwd(descendant)
        if a == d:
            return False
        if a == "/":
            return d != "/"
        base = a.rstrip("/")
        return d.startswith(base + "/")

    @staticmethod
    def _parse_chroot_extra_paths(spec: str) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for i, part in enumerate(spec.split(",")):
            p = part.strip()
            if p:
                out.append((f"extra_{i}", p))
        return out

    def _chroot_probe_cwd_fresh(self, creds: Creds, path: str, probe_id: str) -> ChrootCwdProbeRow:
        ftp = self.connect()
        try:
            ftp.login(creds.user, creds.passw)
            ftp.cwd(path)
            pa = ftp.pwd()
            return ChrootCwdProbeRow(probe_id, path, True, pa, None)
        except ftplib.error_perm as e:
            return ChrootCwdProbeRow(probe_id, path, False, None, str(e).strip()[:400])
        except Exception as e:
            return ChrootCwdProbeRow(probe_id, path, False, None, str(e).strip()[:400])
        finally:
            try:
                ftp.close()
            except Exception:
                pass

    def _chroot_probe_size_fresh(self, creds: Creds, remote_path: str) -> tuple[bool, str | None, int | None]:
        ftp = self.connect()
        try:
            ftp.login(creds.user, creds.passw)
            sz = ftp.size(remote_path)
            if isinstance(sz, int) and sz >= 0:
                return True, None, sz
            return False, None, None
        except Exception as e:
            return False, str(e).strip()[:240], None
        finally:
            try:
                ftp.close()
            except Exception:
                pass

    def _chroot_dotdot_chain(self, creds: Creds, max_steps: int | None = None) -> ChrootDotdotResult:
        """
        Repeated CWD ... Early exit: server rejects .., PWD stops changing (at chroot/top),
        or PWD read fails. max_steps is only a safety cap for abnormal symlink loops.
        """
        cap = max_steps if max_steps is not None else self._CHROOT_DOTDOT_MAX_STEPS
        ftp = self.connect()
        p0 = ""
        try:
            ftp.login(creds.user, creds.passw)
            p0 = ftp.pwd()
            last = p0
            steps = 0
            reason = "max_steps_cap"
            for _ in range(cap):
                try:
                    ftp.cwd("..")
                except ftplib.error_perm:
                    reason = "cwd_dotdot_rejected"
                    break
                except Exception as e:
                    reason = f"error:{type(e).__name__}"
                    break
                try:
                    pn = ftp.pwd()
                except Exception:
                    reason = "pwd_failed"
                    break
                if self._chroot_norm_pwd(pn) == self._chroot_norm_pwd(last):
                    reason = "pwd_unchanged"
                    break
                last = pn
                steps += 1
            return ChrootDotdotResult(steps, p0, last, reason)
        except Exception as e:
            return ChrootDotdotResult(0, p0 or "?", None, str(e)[:160])
        finally:
            try:
                ftp.close()
            except Exception:
                pass

    def test_chroot_audit(self, creds: Creds) -> ChrootAuditResult:
        """PTL-SVC-FTP-CHROOT: CWD to host-like paths, .. chain, SIZE on /etc/passwd."""
        ftp0 = self.connect()
        pwd_initial: str
        try:
            ftp0.login(creds.user, creds.passw)
            pwd_initial = ftp0.pwd()
        finally:
            try:
                ftp0.close()
            except Exception:
                pass

        base_probes: list[tuple[str, str]] = [
            ("slash", "/"),
            ("etc", "/etc"),
            ("root_dir", "/root"),
            ("home", "/home"),
            ("proc", "/proc"),
            ("sys", "/sys"),
            ("var_log", "/var/log"),
            ("var_www", "/var/www"),
            ("srv", "/srv"),
            ("dev", "/dev"),
            ("bin", "/bin"),
            ("tmp", "/tmp"),
        ]
        extra = self._parse_chroot_extra_paths(getattr(self.args, "chroot_audit_paths", "") or "")
        seen: set[str] = {p for _, p in base_probes}
        for eid, pth in extra:
            if pth not in seen:
                base_probes.append((eid, pth))
                seen.add(pth)

        rows: list[ChrootCwdProbeRow] = []
        for pid, pth in base_probes:
            rows.append(self._chroot_probe_cwd_fresh(creds, pth, pid))

        dot = self._chroot_dotdot_chain(creds)
        pwd0n = self._chroot_norm_pwd(pwd_initial)
        pwd_fn = self._chroot_norm_pwd(dot.pwd_final or pwd_initial)
        dotdot_escape = False
        if dot.pwd_final and pwd0n and pwd_fn:
            if self._chroot_strict_ancestor(pwd_fn, pwd0n) and pwd_fn != "/":
                dotdot_escape = True

        home_parent_ok = any(r.path == "/home" and r.success for r in rows)
        home_sibling = bool(
            home_parent_ok
            and pwd0n.startswith("/home/")
            and pwd0n.rstrip("/") != "/home"
        )

        strong_hits: list[str] = []
        for r in rows:
            if r.success and r.path in self._CHROOT_STRONG_CWD_PATHS:
                strong_hits.append(r.path)

        passwd_ok, _, passwd_sz = self._chroot_probe_size_fresh(creds, "/etc/passwd")
        shadow_ok, _, shadow_sz = self._chroot_probe_size_fresh(creds, "/etc/shadow")

        broken = (
            len(strong_hits) > 0
            or passwd_ok
            or shadow_ok
            or home_sibling
            or dotdot_escape
        )

        parts: list[str] = []
        if strong_hits:
            parts.append(f"CWD succeeded to sensitive path(s): {', '.join(sorted(set(strong_hits)))}.")
        if passwd_ok:
            parts.append("SIZE /etc/passwd succeeded (file visible to this account).")
        if shadow_ok:
            parts.append("SIZE /etc/shadow succeeded (highly anomalous — verify).")
        if home_sibling:
            parts.append("CWD /home succeeded while login PWD was under /home/<user> (possible cross-user directory access).")
        if dotdot_escape:
            parts.append(
                f"Repeated CWD .. reached strict parent of login directory (final PWD ~ {pwd_fn!r}, steps={dot.steps_ok})."
            )
        if not parts:
            parts.append(
                "No obvious host-level path breakout in this probe set; chroot may still use a synthetic '/' — confirm manually."
            )

        detail = " ".join(parts)
        return ChrootAuditResult(
            pwd_initial=pwd_initial,
            cwd_probes=tuple(rows),
            dotdot=dot,
            home_parent_accessible=home_parent_ok,
            system_paths_accessible=tuple(sorted(set(strong_hits))),
            passwd_size_ok=passwd_ok,
            shadow_size_ok=shadow_ok,
            dotdot_parent_escape_suspected=dotdot_escape,
            isolation_broken_suspected=broken,
            detail=detail,
            passwd_size_bytes=passwd_sz if passwd_ok else None,
            shadow_size_bytes=shadow_sz if shadow_ok else None,
        )

    @staticmethod
    def _reply_code(reply: str) -> int | None:
        r = reply.strip()
        if len(r) >= 3 and r[:3].isdigit():
            return int(r[:3])
        return None

    @staticmethod
    def _format_port_command(ip: str, port: int) -> str:
        octets = [int(x) for x in ip.split(".")]
        if len(octets) != 4 or any(x < 0 or x > 255 for x in octets):
            raise ValueError("IPv4 required for PORT")
        p1, p2 = port // 256, port % 256
        if p1 < 0 or p1 > 255 or p2 < 0 or p2 > 255:
            raise ValueError("port out of range for PORT encoding")
        return f"PORT {octets[0]},{octets[1]},{octets[2]},{octets[3]},{p1},{p2}"

    def _ftp_send_cmd(self, ftp: ftplib.FTP, cmd: str) -> str:
        try:
            return ftp.sendcmd(cmd)
        except ftplib.Error as e:
            s = str(e).strip()
            return s if s else repr(e)

    def _ftp_send_cmd_site_help_all_safe(self, ftp: ftplib.FTP) -> tuple[str | None, str | None]:
        """
        SITE HELP ALL can reset the TCP session or hang on some servers; never propagate.
        Returns (reply, None) on success, (None, error_message) on failure.
        """
        try:
            return self._ftp_send_cmd(ftp, "SITE HELP ALL"), None
        except (OSError, EOFError, socket.timeout, TimeoutError) as e:
            return None, f"{type(e).__name__}: {e}"
        except Exception as e:
            return None, f"{type(e).__name__}: {e}"

    def _local_control_ipv4(self, ftp: ftplib.FTP) -> str | None:
        try:
            sock = ftp.sock
            addr = sock.getsockname()[0]
            ipaddress.IPv4Address(addr)
            if str(addr) == "0.0.0.0":
                return None
            return addr
        except Exception:
            return None

    @staticmethod
    def _parse_active_audit_low_ports(spec: str) -> list[int]:
        ports: list[int] = []
        for part in spec.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                p = int(part, 10)
            except ValueError:
                continue
            if 1 <= p < 1000:
                ports.append(p)
        return ports or [80, 443, 21]

    @staticmethod
    def _hint_pasv_preauth(code: int | None) -> str | None:
        if code == 227:
            return (
                "PASV allowed before login (informational). Hardened servers often use 530; "
                "227 is not RFC-forbidden but expands pre-auth attack surface."
            )
        if code == 530:
            return "Login required before PASV (strict / preferred policy for access control)."
        if code == 502:
            return "PASV not implemented or disabled on server."
        if code == 421:
            return "Service unavailable or control connection closing."
        if code == 504:
            return "PASV parameter not implemented."
        return None

    @staticmethod
    def _hint_port_preauth_own(code: int | None) -> str | None:
        if code == 530:
            return "Login required before PORT (expected for hardened servers)."
        if code == 200:
            return "PORT accepted before login (unusual; review server policy)."
        if code in (500, 501, 502):
            return "PORT rejected or syntax error before login."
        if code == 504:
            return "PORT parameter rejected (RFC 2577 style for bad port)."
        return None

    @staticmethod
    def _hint_port_preauth_foreign(code: int | None) -> str | None:
        if code == 200:
            return "PORT to non-client IP accepted before login (FTP bounce risk)."
        if code in (530, 500, 501, 502, 504):
            return "PORT to third-party address rejected before login (bounce mitigation)."
        return None

    @staticmethod
    def _hint_d0_list(code: int | None) -> str | None:
        if code in (150, 125):
            return (
                "Server accepted LIST without prior PASV/PORT on control trace — data phase started; "
                "client did not use ftplib auto-PASV (raw LIST)."
            )
        if code == 226:
            return "Transfer complete without explicit PASV/PORT in our capture (unusual for single reply)."
        if code == 425:
            return "Cannot open data connection — server requires explicit PASV/PORT (strict RFC-style)."
        if code in (503, 501):
            return "Bad sequence or syntax — likely requires PASV/PORT first."
        if code == 530:
            return "Not logged in or command refused."
        return None

    def _active_audit_step_verdict(
        self, s: ActiveAuditStep, aa: ActiveAuditResult
    ) -> tuple[str | None, str | None]:
        """Terminal verdict (NOTVULN / VULN / WARNING) for one active-audit step; (None, None) = omit."""
        c = s.code
        name = s.name
        phase = s.phase
        reply_l = (s.reply or "").lower()
        cmd_s = s.command or ""

        if cmd_s == "(skipped)" or name in ("port_skipped", "port_sessions"):
            note_l = (s.note or "").lower()
            if "non-ipv4" in note_l or "ipv4" in note_l:
                return "WARNING", "IPv4 required for PORT tests; audit incomplete"
            return None, None

        if phase == "preAuth":
            if name == "pasv":
                if c == 530:
                    return "NOTVULN", "Login required before PASV (strict policy)"
                if c == 227:
                    return "WARNING", "PASV allowed before login (informational attack surface)"
                if c == 502:
                    return "NOTVULN", "PASV not implemented or disabled on server"
                if c in (501, 504):
                    return "NOTVULN", "PASV not available or parameter rejected"
            if name in ("port_own_high", "port_own_1930", "port_own"):
                if c == 530:
                    return "NOTVULN", "Login required before PORT (expected for hardened servers)"
                if c == 200:
                    return "VULN", "PORT accepted before login (unusual — review policy)"
            if name == "port_foreign":
                if c == 200:
                    return "VULN", "Third-party PORT accepted before login (FTP bounce risk)"
                if c in (530, 500, 501, 502, 504):
                    return "NOTVULN", "Third-party PORT rejected before login (bounce mitigation)"

        if phase == "postAuth":
            if name == "d0_list_raw":
                if c in (425, 503, 501):
                    return "NOTVULN", "Strict RFC-style state (PASV/PORT required first)"
                if c == 530:
                    return "NOTVULN", "Login or sequence required before data channel"
            if name == "pasv_list":
                if s.reply == "ok" or c == 226:
                    return "NOTVULN", "Passive data transfer OK"
                if s.reply == "failed":
                    return "WARNING", "Passive LIST failed (see reply)"
            if name == "pasv":
                if c == 227:
                    return "NOTVULN", "Passive mode available after login"
            if name == "list_active":
                if "ok" in reply_l:
                    return "NOTVULN", "Active-mode LIST completed (data path OK)"
                return "WARNING", "Active-mode LIST failed (NAT/firewall on tester side possible)"

            if name == "port_foreign_list":
                if c == 200:
                    return "VULN", "PORT 200 to foreign IP — bounce risk (verify with capture)"
                if c in (500, 501, 502, 504, 530):
                    return "NOTVULN", "Third-party PORT rejected (bounce risk mitigated)"

            if name.startswith("port_own_low_"):
                if c in (500, 501, 502, 504, 530):
                    return "NOTVULN", "Low data port (<1024) rejected"

            if name in ("port_own_high_list", "port_own_1930_list"):
                if c == 200:
                    return "WARNING", "PORT accepted — verify data path and policy"
                if c in (500, 501, 502, 504) and "illegal" in reply_l:
                    return "NOTVULN", "PORT rejected (active mode disabled or restricted)"
                if c == 530:
                    return "NOTVULN", "PORT refused (policy)"
                if c == 500 and "illegal" not in reply_l:
                    return "NOTVULN", "PORT rejected by server"

            if name in ("port_own_high", "port_foreign", "port_low") and c is not None:
                if c == 200 and name == "port_foreign":
                    return "VULN", "Third-party PORT accepted after login (bounce risk)"
                if c == 200:
                    return "WARNING", "PORT command accepted (check follow-up behaviour)"
                if c in (500, 501, 502, 504) and "illegal" in reply_l:
                    return "NOTVULN", "PORT rejected (active mode disabled or restricted)"
                if c == 530:
                    return "NOTVULN", "PORT refused or login required"

        return None, None

    def _print_active_audit_terminal(self, aa: ActiveAuditResult) -> None:
        """Structured terminal output for active mode policy audit (aligned with other FTP sections)."""
        fk = get_colored_text
        star_h = fk("[*]", color="INFO")
        bounce_header = False
        printed_pre = False
        post_header = False

        self.ptprint("Active mode policy", Out.INFO)

        for s in aa.steps:
            if s.phase == "preAuth" and not printed_pre:
                self.ptprint("Pre-authentication checks", Out.INFO)
                printed_pre = True
            if s.phase == "postAuth" and not post_header:
                self.ptprint("Post-authentication checks", Out.INFO)
                post_header = True
            if (
                s.phase == "postAuth"
                and s.name in ("port_foreign_list", "port_foreign")
                and not bounce_header
            ):
                self.ptprint("FTP bounce (foreign IP)", Out.INFO)
                bounce_header = True

            c = s.code
            code_s = f" [{c}]" if c is not None else ""
            cmd_s = s.command if s.command else "(no command)"
            self.ptprint(f"    [{s.phase}/{s.name}] {cmd_s}{code_s}", Out.TEXT)
            if s.reply:
                r = s.reply[:500] + ("…" if len(s.reply) > 500 else "")
                self.ptprint(f"        {r}", Out.TEXT)
            if s.list_reply:
                lc = s.list_code
                lc_s = f" [list {lc}]" if lc is not None else ""
                lr = s.list_reply[:400] + ("…" if len(s.list_reply or "") > 400 else "")
                self.ptprint(f"        list:{lc_s} {lr}", Out.TEXT)

            v_col, v_msg = self._active_audit_step_verdict(s, aa)
            if v_msg and v_col:
                icon = fk(
                    "[✓]" if v_col == "NOTVULN" else ("[✗]" if v_col == "VULN" else "[!]"),
                    color=v_col,
                )
                self.ptprint(f"        {icon} {v_msg}", Out.TEXT)
            elif s.interpretation:
                self.ptprint(f"        hint: {s.interpretation}", Out.TEXT)
            if s.note and not (cmd_s == "(skipped)" and v_msg):
                self.ptprint(f"        note: {s.note}", Out.TEXT)

        if not aa.post_auth_ran:
            warn = fk("[!]", color="WARNING")
            self.ptprint(
                f"    {warn} Post-login steps skipped (no credentials); use --anonymous or -u USER -p PASS (or wordlists)",
                Out.TEXT,
            )

        doc_net_ip = "192.0.2.1"
        if aa.foreign_ip_accepted:
            icon = fk("[✗]", color="VULN")
            self.ptprint(
                f"    {icon} PORT accepted for non-client IP (bounce risk; tested {doc_net_ip})",
                Out.TEXT,
            )
            self.ptprint(
                "    Verify with a packet capture whether the server opens TCP to the stated IP:port.",
                Out.TEXT,
            )
        if aa.low_port_accepted:
            icon = fk("[✗]", color="VULN")
            lp = ", ".join(str(p) for p in aa.low_ports_accepted) if aa.low_ports_accepted else "<1000"
            self.ptprint(
                f"    {icon} PORT accepted for low data port(s): {lp} (RFC 2577: suggest reject < 1024)",
                Out.TEXT,
            )
        if aa.list_after_own_port_ok is False:
            warn = fk("[!]", color="WARNING")
            self.ptprint(
                f"    {warn} Active-mode LIST failed; may be NAT/firewall on tester side",
                Out.TEXT,
            )

        self.ptprint("Summary", Out.INFO)
        passive_ok = any(
            (x.name == "pasv_list" and x.reply == "ok")
            or (x.name == "pasv" and x.code == 227)
            for x in aa.steps
        )
        passive_txt = (
            "Available / data transfer OK" if passive_ok else "Not verified or failed in this run"
        )
        self.ptprint(f"    {star_h} Passive mode:    {passive_txt}", Out.TEXT)

        if not aa.post_auth_ran:
            self.ptprint(
                f"    {star_h} Active mode:     {fk('[!]', color='WARNING')} Not assessed (no post-login audit)",
                Out.TEXT,
            )
            self.ptprint(
                f"    {star_h} Overall status:  {fk('[!]', color='WARNING')} Incomplete audit",
                Out.TEXT,
            )
            return

        active_vuln = aa.foreign_ip_accepted or aa.low_port_accepted
        port_rejected = any(
            x.name.endswith("_list")
            and x.code in (500, 501, 502, 504)
            and "illegal" in (x.reply or "").lower()
            for x in aa.steps
        )
        ipv4_skip = any(
            "non-ipv4" in (x.note or "").lower() for x in aa.steps if x.command == "(skipped)"
        )

        if active_vuln:
            active_txt = f"{fk('[✗]', color='VULN')} PORT policy risk (foreign or low port accepted)"
        elif ipv4_skip:
            active_txt = f"{fk('[!]', color='WARNING')} Not fully assessed (IPv4 required for PORT probes)"
        elif port_rejected and not aa.foreign_ip_accepted:
            active_txt = f"{fk('[✓]', color='NOTVULN')} Disabled / rejected (no 200 on bounce/low-port probes in this run)"
        else:
            active_txt = f"{fk('[✓]', color='NOTVULN')} No bounce/low-port PORT acceptance (200) observed"

        self.ptprint(f"    {star_h} Active mode:     {active_txt}", Out.TEXT)

        if active_vuln:
            overall = f"{fk('[✗]', color='VULN')} Review PORT policy (bounce / low port)"
        elif ipv4_skip:
            overall = f"{fk('[!]', color='WARNING')} Inconclusive (partial audit)"
        else:
            overall = f"{fk('[✓]', color='NOTVULN')} No bounce/low-port finding from this run"

        self.ptprint(f"    {star_h} Overall status:  {overall}", Out.TEXT)

    def _raw_list_without_pasv_port(self, ftp: ftplib.FTP) -> tuple[str, int | None]:
        """Send LIST on control channel without ftplib issuing PASV/PORT first (D0)."""
        try:
            ftp.putcmd("LIST")
            resp = ftp.getmultiline()
        except Exception as e:
            return str(e).strip() or repr(e), None
        code = self._reply_code(resp)
        if code == 150:
            try:
                ftp.putcmd("ABOR")
                _ = ftp.getmultiline()
            except Exception:
                pass
        return resp, code

    def _active_port_list_plaintext(
        self, ftp: ftplib.FTP, local_ip: str, data_port: int
    ) -> tuple[str, int | None, str, int | None, bool, str | None]:
        """
        After login: bind local data port, PORT command, LIST, accept server connection.
        Returns: port_reply, port_code, list_control_log, list_final_code, data_received, error_note
        """
        if self.args.tls or self.args.starttls:
            pcmd = self._format_port_command(local_ip, data_port)
            pr = self._ftp_send_cmd(ftp, pcmd)
            pc = self._reply_code(pr)
            return pr, pc, "", None, False, "TLS: active PORT+LIST not automated; use plaintext or packet capture"

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        to = 15.0
        try:
            listener.bind((local_ip, data_port))
            listener.listen(1)
            listener.settimeout(to)
        except OSError as e:
            try:
                listener.close()
            except Exception:
                pass
            return "", None, "", None, False, f"bind {local_ip}:{data_port} failed: {e}"

        try:
            pcmd = self._format_port_command(local_ip, data_port)
            port_reply = self._ftp_send_cmd(ftp, pcmd)
            pc = self._reply_code(port_reply)
            if pc != 200:
                return port_reply, pc, "", None, False, None

            ftp.putcmd("LIST")
            line1 = ftp.getmultiline()
            lc1 = self._reply_code(line1)
            if lc1 in (425, 500, 501, 502, 530, 503):
                return port_reply, pc, line1, lc1, False, None

            try:
                datasock, _ = listener.accept()
            except socket.timeout:
                return port_reply, pc, line1, lc1, False, "data connection accept timeout"

            datasock.settimeout(to)
            chunks: list[bytes] = []
            try:
                while True:
                    chunk = datasock.recv(8192)
                    if not chunk:
                        break
                    chunks.append(chunk)
            except socket.timeout:
                pass
            finally:
                try:
                    datasock.close()
                except Exception:
                    pass

            data_ok = len(b"".join(chunks)) > 0
            try:
                line2 = ftp.getmultiline()
            except Exception as e:
                line2 = str(e)
            lc2 = self._reply_code(line2)
            return port_reply, pc, f"{line1} || {line2}", lc2, data_ok, None
        finally:
            try:
                listener.close()
            except Exception:
                pass

    def _foreign_port_then_list(
        self, ftp: ftplib.FTP, foreign_ip: str, data_port: int
    ) -> tuple[str, int | None, str, int | None]:
        """PORT to documentation IP then LIST; observe control replies (no local listener on foreign IP)."""
        pcmd = self._format_port_command(foreign_ip, data_port)
        pr = self._ftp_send_cmd(ftp, pcmd)
        pc = self._reply_code(pr)
        if pc != 200:
            return pr, pc, "", None
        ftp.putcmd("LIST")
        try:
            line1 = ftp.getmultiline()
        except Exception as e:
            return pr, pc, str(e), None
        lc1 = self._reply_code(line1)
        try:
            old_to = ftp.sock.gettimeout()
        except Exception:
            old_to = None
        merged, lc2 = line1, lc1
        try:
            ftp.sock.settimeout(8.0)
            line2 = ftp.getmultiline()
            lc2 = self._reply_code(line2)
            merged = f"{line1} || {line2}"
        except Exception:
            pass
        finally:
            try:
                if old_to is not None:
                    ftp.sock.settimeout(old_to)
            except Exception:
                pass
        return pr, pc, merged, lc2

    def test_active_audit_full(self, creds: Creds | None, low_ports_spec: str) -> ActiveAuditResult:
        """
        Full PTL-SVC-FTP-ACTIVE methodology: isolated sessions, interpretation hints,
        D0 raw LIST, PORT+LIST per variant, multiple low ports.
        """
        doc_net_ip = "192.0.2.1"
        foreign_data_port = 7 * 256 + 138
        local_high_port = 40123
        low_ports = self._parse_active_audit_low_ports(low_ports_spec)

        steps: list[ActiveAuditStep] = []
        foreign_accepted = False
        low_accepted_ports: list[int] = []
        list_after_own_ok: bool | None = None

        # --- Pre-auth (single connection) ---
        pre = self.connect()
        try:
            pasv_r = self._ftp_send_cmd(pre, "PASV")
            pc = self._reply_code(pasv_r)
            steps.append(
                ActiveAuditStep(
                    "preAuth",
                    "pasv",
                    "PASV",
                    pasv_r,
                    pc,
                    None,
                    self._hint_pasv_preauth(pc),
                    None,
                    None,
                )
            )
            local_pre = self._local_control_ipv4(pre)
            if local_pre:
                for pname, port_n in (("port_own_high", local_high_port), ("port_own_1930", foreign_data_port)):
                    cmd = self._format_port_command(local_pre, port_n)
                    pr = self._ftp_send_cmd(pre, cmd)
                    c = self._reply_code(pr)
                    steps.append(
                        ActiveAuditStep(
                            "preAuth",
                            pname,
                            cmd,
                            pr,
                            c,
                            None,
                            self._hint_port_preauth_own(c),
                            None,
                            None,
                        )
                    )
            else:
                steps.append(
                    ActiveAuditStep(
                        "preAuth",
                        "port_own",
                        "(skipped)",
                        "",
                        None,
                        "non-IPv4 or 0.0.0.0 local control address",
                        None,
                        None,
                        None,
                    )
                )

            fcmd = self._format_port_command(doc_net_ip, foreign_data_port)
            fr = self._ftp_send_cmd(pre, fcmd)
            fc = self._reply_code(fr)
            steps.append(
                ActiveAuditStep(
                    "preAuth",
                    "port_foreign",
                    fcmd,
                    fr,
                    fc,
                    None,
                    self._hint_port_preauth_foreign(fc),
                    None,
                    None,
                )
            )
            if fc == 200:
                foreign_accepted = True
        finally:
            try:
                pre.close()
            except Exception:
                pass

        post_ran = False
        if creds is None:
            return ActiveAuditResult(
                tuple(steps),
                post_ran,
                foreign_accepted,
                len(low_accepted_ports) > 0,
                list_after_own_ok,
                tuple(low_accepted_ports),
                True,
            )

        post_ran = True

        def session_pasv_list() -> None:
            ftp = self.connect()
            try:
                ftp.login(creds.user, creds.passw)
                ftp.set_pasv(True)
                ach = AccessCheckHelper()
                try:
                    ftp.dir(ach.read_callback)
                    ok = True
                    lr = "directory listing completed (passive)"
                except ftplib.Error as e:
                    ok = False
                    lr = str(e).strip()
                steps.append(
                    ActiveAuditStep(
                        "postAuth",
                        "pasv_list",
                        "PASV + LIST (via dir, passive)",
                        "ok" if ok else "failed",
                        226 if ok else self._reply_code(lr),
                        None,
                        "Baseline passive data transfer after login.",
                        lr[:500] if lr else None,
                        self._reply_code(lr),
                    )
                )
            finally:
                try:
                    ftp.close()
                except Exception:
                    pass

        def session_d0() -> None:
            ftp = self.connect()
            try:
                ftp.login(creds.user, creds.passw)
                resp, code = self._raw_list_without_pasv_port(ftp)
                steps.append(
                    ActiveAuditStep(
                        "postAuth",
                        "d0_list_raw",
                        "LIST (raw, no prior PASV/PORT)",
                        resp[:800],
                        code,
                        None,
                        self._hint_d0_list(code),
                        None,
                        None,
                    )
                )
            finally:
                try:
                    ftp.close()
                except Exception:
                    pass

        session_d0()
        session_pasv_list()

        local = None
        s0 = self.connect()
        try:
            s0.login(creds.user, creds.passw)
            local = self._local_control_ipv4(s0)
        finally:
            try:
                s0.close()
            except Exception:
                pass

        if not local:
            steps.append(
                ActiveAuditStep(
                    "postAuth",
                    "port_sessions",
                    "(skipped)",
                    "",
                    None,
                    "non-IPv4 local socket; PORT+LIST sessions skipped",
                    None,
                    None,
                    None,
                )
            )
            return ActiveAuditResult(
                tuple(steps),
                post_ran,
                foreign_accepted,
                len(low_accepted_ports) > 0,
                list_after_own_ok,
                tuple(low_accepted_ports),
                True,
            )

        def run_port_list_session(step_name: str, data_port: int, foreign: bool) -> None:
            nonlocal foreign_accepted, list_after_own_ok
            ftp = self.connect()
            try:
                ftp.login(creds.user, creds.passw)
                if foreign:
                    pr, pc, lr, lc = self._foreign_port_then_list(ftp, doc_net_ip, data_port)
                    hint = self._hint_port_preauth_foreign(pc)
                    steps.append(
                        ActiveAuditStep(
                            "postAuth",
                            step_name,
                            self._format_port_command(doc_net_ip, data_port),
                            pr,
                            pc,
                            "Foreign IP: LIST may fail or timeout; 200 on PORT is still bounce risk.",
                            hint,
                            lr[:800] if lr else None,
                            lc,
                        )
                    )
                    if pc == 200:
                        foreign_accepted = True
                    return

                pr, pc, lr, lc, data_ok, err_note = self._active_port_list_plaintext(ftp, local, data_port)
                if step_name == "port_own_high_list" and data_ok:
                    list_after_own_ok = True
                hint = None
                tls_skip = bool(err_note and "TLS" in err_note)
                if (
                    pc == 200
                    and data_port < 1000
                    and not tls_skip
                    and data_port not in low_accepted_ports
                ):
                    hint = "PORT accepted for port <1000; RFC 2577 recommends rejecting <1024 (often 504)."
                    low_accepted_ports.append(data_port)
                inter = None
                if pc and pc != 200:
                    inter = "PORT or data phase rejected (see reply)."
                elif pc == 200 and data_port >= 1000 and data_ok:
                    inter = "Active PORT+LIST completed for high/ephemeral data port."
                elif pc == 200 and data_port >= 1000 and not data_ok:
                    inter = "PORT accepted but data transfer incomplete (timeout/NAT/firewall possible)."
                steps.append(
                    ActiveAuditStep(
                        "postAuth",
                        step_name,
                        self._format_port_command(local, data_port),
                        pr,
                        pc,
                        err_note,
                        inter or hint,
                        lr[:800] if lr else None,
                        lc,
                    )
                )
            finally:
                try:
                    ftp.close()
                except Exception:
                    pass

        run_port_list_session("port_own_high_list", local_high_port, False)
        run_port_list_session("port_own_1930_list", foreign_data_port, False)
        run_port_list_session("port_foreign_list", foreign_data_port, True)

        for lp in low_ports:
            run_port_list_session(f"port_own_low_{lp}", lp, False)

        return ActiveAuditResult(
            tuple(steps),
            post_ran,
            foreign_accepted,
            len(low_accepted_ports) > 0,
            list_after_own_ok,
            tuple(low_accepted_ports),
            True,
        )

    def test_active_audit_quick(self, creds: Creds | None) -> ActiveAuditResult:
        """
        PTL-SVC-FTP-ACTIVE: PASV/PORT policy (pre- and post-login), foreign IP and low-port PORT.
        Uses 192.0.2.1 (RFC 5737 TEST-NET-1) as non-client address for bounce-style checks.
        """
        # RFC 5737 documentation block — must not target real third parties
        doc_net_ip = "192.0.2.1"
        foreign_data_port = 7 * 256 + 138  # 1930, example from audit methodology
        local_high_port = 40123
        low_test_port = 80  # < 1000 per test spec; RFC 2577 recommends rejecting < 1024

        steps: list[ActiveAuditStep] = []
        foreign_accepted = False
        low_port_accepted = False
        list_after_own_port_ok: bool | None = None

        # --- Pre-authentication ---
        pre_ftp = self.connect()
        try:
            pasv_reply = self._ftp_send_cmd(pre_ftp, "PASV")
            steps.append(
                ActiveAuditStep(
                    "preAuth",
                    "pasv",
                    "PASV",
                    pasv_reply,
                    self._reply_code(pasv_reply),
                    None,
                )
            )
            local_pre = self._local_control_ipv4(pre_ftp)
            if local_pre:
                port_cmd = self._format_port_command(local_pre, local_high_port)
                pr = self._ftp_send_cmd(pre_ftp, port_cmd)
                code = self._reply_code(pr)
                steps.append(
                    ActiveAuditStep("preAuth", "port_own_high", port_cmd, pr, code, None)
                )
            else:
                steps.append(
                    ActiveAuditStep(
                        "preAuth",
                        "port_own_high",
                        "(skipped)",
                        "",
                        None,
                        "non-IPv4 or unknown local control address",
                    )
                )

            fcmd = self._format_port_command(doc_net_ip, foreign_data_port)
            fr = self._ftp_send_cmd(pre_ftp, fcmd)
            fc = self._reply_code(fr)
            steps.append(ActiveAuditStep("preAuth", "port_foreign", fcmd, fr, fc, None))
            if fc == 200:
                foreign_accepted = True
        finally:
            try:
                pre_ftp.close()
            except Exception:
                pass

        # --- Post-authentication ---
        post_ran = False
        if creds is None:
            return ActiveAuditResult(
                tuple(steps),
                post_ran,
                foreign_accepted,
                low_port_accepted,
                list_after_own_port_ok,
                (low_test_port,) if low_port_accepted else (),
                False,
            )

        post_ran = True

        def run_post(name: str, cmd: str) -> ActiveAuditStep:
            ftp = self.connect()
            try:
                ftp.login(creds.user, creds.passw)
                reply = self._ftp_send_cmd(ftp, cmd)
                return ActiveAuditStep(
                    "postAuth",
                    name,
                    cmd,
                    reply,
                    self._reply_code(reply),
                    None,
                )
            finally:
                try:
                    ftp.close()
                except Exception:
                    pass

        steps.append(run_post("pasv", "PASV"))

        local = None
        ftp_one = self.connect()
        try:
            ftp_one.login(creds.user, creds.passw)
            local = self._local_control_ipv4(ftp_one)
        finally:
            try:
                ftp_one.close()
            except Exception:
                pass

        if local:
            pcmd_own = self._format_port_command(local, local_high_port)
            st = run_post("port_own_high", pcmd_own)
            steps.append(st)

            pcmd_foreign = self._format_port_command(doc_net_ip, foreign_data_port)
            st_f = run_post("port_foreign", pcmd_foreign)
            steps.append(st_f)
            if self._reply_code(st_f.reply) == 200:
                foreign_accepted = True

            pcmd_low = self._format_port_command(local, low_test_port)
            st_l = run_post("port_low", pcmd_low)
            steps.append(st_l)
            if self._reply_code(st_l.reply) == 200:
                low_port_accepted = True

            ftp_l = self.connect()
            try:
                ftp_l.login(creds.user, creds.passw)
                ftp_l.set_pasv(False)
                ach = AccessCheckHelper()
                try:
                    ftp_l.dir(ach.read_callback)
                    list_after_own_port_ok = True
                except ftplib.Error:
                    list_after_own_port_ok = False
            finally:
                try:
                    ftp_l.close()
                except Exception:
                    pass
            steps.append(
                ActiveAuditStep(
                    "postAuth",
                    "list_active",
                    "LIST (dir, client active mode)",
                    "data transfer ok" if list_after_own_port_ok else "data transfer failed",
                    None,
                    "If failed: NAT/firewall on tester side is possible; not necessarily server-only",
                )
            )
        else:
            steps.append(
                ActiveAuditStep(
                    "postAuth",
                    "port_skipped",
                    "",
                    "",
                    None,
                    "non-IPv4 local socket; post-auth PORT tests skipped",
                )
            )

        return ActiveAuditResult(
            tuple(steps),
            post_ran,
            foreign_accepted,
            low_port_accepted,
            list_after_own_port_ok,
            (low_test_port,) if low_port_accepted else (),
            False,
        )

    _CMD_AUDIT_MAX = 65536
    _CMD_ACTIVE_PROBE_TIMEOUT = 12.0
    _CMD_ACTIVE_PATTERNS: dict[str, re.Pattern[str]] = {
        "chown": re.compile(r"\bSITE\s+CHOWN\b", re.I),
        "chmod": re.compile(r"\bSITE\s+CHMOD\b", re.I),
        "exec": re.compile(r"\bSITE\s+(EXEC|EXECUTE|RUN)\b", re.I),
        "cpfr": re.compile(r"\bSITE\s+CPFR\b", re.I),
        "cpto": re.compile(r"\bSITE\s+CPTO\b", re.I),
        "umask": re.compile(r"\bSITE\s+UMASK\b", re.I),
        "symlink": re.compile(r"\bSITE\s+(SYMLINK|LINK|LN)\b", re.I),
    }

    _INV_AUDIT_TIMEOUT = 8.0
    _INV_AUDIT_LONG_LEN = 4096
    _INV_AUDIT_REPLY_TEXT_MAX = 4096
    # 3xx on these probes is non‑RFC‑typical (RFC 959: USER→331/332 is normal; see _inv_2xx_counts_toward_vulnerable).
    _INV_3XX_CRITICAL_PROBE_IDS = frozenset({"long_buffer_cwd", "format_string_stat"})
    # RFC 959 §5.4: STAT replies are 211/212/213/214 (and 215 NAME); not a protocol anomaly.
    _INV_STAT_SUCCESS_CODES = frozenset({211, 212, 213, 214, 215})
    # Double-CRLF smuggle: read possible 2nd FTP reply without blocking the main probe timeout.
    _INV_SMUGGLE_FOLLOWUP_TIMEOUT = 0.75
    _INV_DRAIN_CHUNK_TIMEOUT = 0.2
    _INV_DRAIN_MAX_BYTES = 65536

    _CMD_AUDIT_CRITICAL: tuple[tuple[re.Pattern[str], str], ...] = (
        (re.compile(r"\bSITE\s+EXECUTE\b", re.I), "SITE EXECUTE"),
        (re.compile(r"\bSITE\s+EXEC\b", re.I), "SITE EXEC"),
        (re.compile(r"\bSITE\s+RUN\b", re.I), "SITE RUN"),
    )
    _CMD_AUDIT_HIGH: tuple[tuple[re.Pattern[str], str], ...] = (
        (re.compile(r"\bSITE\s+CHOWN\b", re.I), "SITE CHOWN"),
        (re.compile(r"\bSITE\s+CHMOD\b", re.I), "SITE CHMOD"),
        (re.compile(r"\bSITE\s+UMASK\b", re.I), "SITE UMASK"),
        (re.compile(r"\bSITE\s+SYMLINK\b", re.I), "SITE SYMLINK"),
        (re.compile(r"\bSITE\s+LINK\b", re.I), "SITE LINK"),
        (re.compile(r"\bSITE\s+LN\b", re.I), "SITE LN"),
        (re.compile(r"\bSITE\s+CPFR\b", re.I), "SITE CPFR"),
        (re.compile(r"\bSITE\s+CPTO\b", re.I), "SITE CPTO"),
    )
    _CMD_AUDIT_MEDIUM: tuple[tuple[re.Pattern[str], str], ...] = (
        (re.compile(r"\bSITE\s+WHO\b", re.I), "SITE WHO"),
        (re.compile(r"\bSITE\s+IDLE\b", re.I), "SITE IDLE"),
    )

    def _truncate_cmd_audit_reply(self, text: str) -> tuple[str, bool]:
        if len(text) <= self._CMD_AUDIT_MAX:
            return text, False
        return text[: self._CMD_AUDIT_MAX] + "\n... [truncated]", True

    @staticmethod
    def _parse_feat_feature_labels(feat_reply: str) -> tuple[str, ...]:
        """Parse FEAT (RFC 2389) response lines into feature labels."""
        ordered: list[str] = []
        seen: set[str] = set()
        for raw in feat_reply.splitlines():
            line = raw.rstrip("\r")
            if len(line) < 2 or line[0] != " " or line[1] == " ":
                continue
            part = line.strip()
            if not part:
                continue
            first = part.split(None, 1)[0].upper()
            if first in ("211", "END") or first.startswith("211-"):
                continue
            if first.endswith(":"):
                continue
            tok = part.split(None, 1)[0]
            u = tok.upper()
            if u not in seen:
                seen.add(u)
                ordered.append(tok)
        return tuple(ordered)

    def _cmd_audit_scan_text(self, text: str, source: str) -> list[CmdAuditRisk]:
        risks: list[CmdAuditRisk] = []
        if not text or not text.strip():
            return risks
        for pat, label in self._CMD_AUDIT_CRITICAL:
            if pat.search(text):
                risks.append(CmdAuditRisk("critical", label, source))
        for pat, label in self._CMD_AUDIT_HIGH:
            if pat.search(text):
                risks.append(CmdAuditRisk("high", label, source))
        for pat, label in self._CMD_AUDIT_MEDIUM:
            if pat.search(text):
                risks.append(CmdAuditRisk("medium", label, source))
        if source == "featResponse":
            for w in ("MDTM", "SIZE", "MLST", "MLSD"):
                if re.search(rf"\b{re.escape(w)}\b", text, re.I):
                    risks.append(CmdAuditRisk("medium", f"FEAT {w}", "featResponse"))
        return risks

    @staticmethod
    def _cmd_audit_merge_risks(items: list[CmdAuditRisk]) -> tuple[CmdAuditRisk, ...]:
        by_k: dict[tuple[str, str, str], CmdAuditRisk] = {}
        for r in items:
            k = (r.tier, r.token, r.source)
            if k not in by_k:
                by_k[k] = r
        order = {"critical": 0, "high": 1, "medium": 2}
        return tuple(sorted(by_k.values(), key=lambda x: (order.get(x.tier, 9), x.token, x.source)))

    _CMD_AUDIT_SOURCE_LABEL: dict[str, str] = {
        "helpPreAuth": "HELP (pre-auth)",
        "featResponse": "FEAT response",
        "siteHelpPreAuth": "SITE HELP (pre-auth)",
        "siteHelpAllPreAuth": "SITE HELP ALL (pre-auth)",
        "siteHelpPostAuth": "SITE HELP (post-auth)",
        "siteHelpAllPostAuth": "SITE HELP ALL (post-auth)",
    }

    def _cmd_audit_blob_for_source(self, ca: CommandAuditResult, source: str) -> str:
        m = {
            "helpPreAuth": ca.help_pre_auth,
            "featResponse": ca.feat_response,
            "siteHelpPreAuth": ca.site_help_pre or "",
            "siteHelpAllPreAuth": ca.site_help_all_pre or "",
            "siteHelpPostAuth": ca.site_help_post or "",
            "siteHelpAllPostAuth": ca.site_help_all_post or "",
        }
        return m.get(source, "") or ""

    def _cmd_audit_snippet_for_risk(self, ca: CommandAuditResult, risk: CmdAuditRisk) -> str:
        blob = self._cmd_audit_blob_for_source(ca, risk.source)
        if not blob.strip():
            return "(empty response for this source)"
        parts = risk.token.split()
        needle = None
        for kw in reversed(parts):
            ku = kw.upper()
            if ku in ("FEAT", "SITE"):
                continue
            needle = kw
            break
        if not needle and parts:
            needle = parts[-1]
        if not needle:
            needle = risk.token
        for line in blob.splitlines():
            if re.search(rf"\b{re.escape(needle)}\b", line, re.I):
                s = line.strip()
                return s[:400] + ("…" if len(s) > 400 else "")
        for line in blob.splitlines():
            if line.strip():
                s = line.strip()
                return s[:400] + ("…" if len(s) > 400 else "")
        s = blob.strip()
        return s[:400] + ("…" if len(s) > 400 else "")

    @staticmethod
    def _cmd_audit_risk_explain(risk: CmdAuditRisk) -> tuple[str | None, str, str | None]:
        tok = risk.token.upper()
        tier = risk.tier

        def t(vuln: str | None, risk_t: str, info: str | None = None) -> tuple[str | None, str, str | None]:
            return (vuln, risk_t, info)

        if tier == "critical":
            return t(
                "Server advertises SITE EXEC / EXECUTE / RUN (implementation-dependent).",
                "If callable by unprivileged users, may lead to remote command execution or full host compromise.",
                None,
            )

        if "SYMLINK" in tok or tok.endswith(" LINK") or tok.endswith(" LN"):
            return t(
                "Advertised capability to create symbolic links on the server side.",
                "High potential for path traversal or access to files outside the intended FTP root.",
                None,
            )
        if "CHOWN" in tok:
            return t(
                "Advertised SITE CHOWN (change file ownership).",
                "May allow privilege escalation or unauthorized ownership changes if not strictly restricted.",
                None,
            )
        if "CHMOD" in tok:
            return t(
                "Advertised SITE CHMOD (change file permissions).",
                "May allow weakening permissions or making sensitive files world-readable if abused.",
                None,
            )
        if "UMASK" in tok:
            return t(
                "Advertised SITE UMASK (default permission mask).",
                "May affect security of newly created files if misconfigured or abused.",
                None,
            )
        if "CPFR" in tok or "CPTO" in tok:
            return t(
                "Advertised SITE CPFR/CPTO (FTP “copy” / server-side file copy).",
                "Associated with historical FTP bounce / abuse scenarios; verify server policy and access control.",
                None,
            )
        if "WHO" in tok:
            return t(
                None,
                "SITE WHO can expose logged-in users or session metadata.",
                "Useful for reconnaissance; impact depends on daemon implementation.",
            )
        if "IDLE" in tok:
            return t(
                None,
                "SITE IDLE may allow tuning or probing idle timeouts.",
                "Minor information or DoS relevance depending on server.",
            )
        if "MDTM" in tok:
            return t(
                None,
                "Allows remote determination of exact file modification times.",
                "Useful for fingerprinting files or coordinating time-based attacks.",
            )
        if "SIZE" in tok:
            return t(
                None,
                "Allows remote determination of exact file sizes.",
                "Can confirm existence of sensitive files or support side-channel style analysis before exfiltration.",
            )
        if "MLST" in tok or "MLSD" in tok:
            return t(
                None,
                "Provides detailed filesystem metadata in a unified, machine-readable format (RFC 3659 style).",
                "Simplifies automated target enumeration and data gathering.",
            )

        return t(
            None,
            f"Capability matched in captured text ({risk.token}). Review whether it is required and properly restricted.",
            None,
        )

    def _print_cmd_audit_terminal(self, ca: CommandAuditResult) -> None:
        """Structured command-surface audit output (HELP/FEAT/SITE), aligned with other FTP sections."""
        fk = get_colored_text
        warn_b = fk("[!]", color="WARNING")
        # Same yellow as section headings (Out.INFO); detail lines are informational [i].
        head_style = fk("[*]", color="INFO")
        info_icon = fk("[i]", color="INFO")

        self.ptprint("Command surface audit", Out.INFO)
        if ca.response_truncated:
            self.ptprint(f"    {warn_b} At least one response was truncated (64 KiB cap)", Out.TEXT)
        if ca.site_help_all_pre_error:
            self.ptprint(
                f"    {warn_b} SITE HELP ALL (pre-auth): {ca.site_help_all_pre_error}",
                Out.TEXT,
            )
        if ca.site_help_all_post_error:
            self.ptprint(
                f"    {warn_b} SITE HELP ALL (post-auth): {ca.site_help_all_post_error}",
                Out.TEXT,
            )

        if not ca.matched_risks:
            self.ptprint(
                f"    {fk('[✓]', color='NOTVULN')} No high-risk SITE / EXEC patterns in captured HELP/FEAT/SITE output",
                Out.TEXT,
            )
            return

        for r in ca.matched_risks:
            col = "VULN" if r.tier in ("critical", "high") else "WARNING"
            head_icon = fk("[✗]" if r.tier in ("critical", "high") else "[!]", color=col)
            src_label = self._CMD_AUDIT_SOURCE_LABEL.get(r.source, r.source)
            self.ptprint(f"    {head_icon} [{r.tier}] {r.token} — {src_label}", Out.TEXT)

            snippet = self._cmd_audit_snippet_for_risk(ca, r)
            self.ptprint(f"        {head_style} Response: {snippet}", Out.TEXT)

            vuln_t, risk_t, info_t = self._cmd_audit_risk_explain(r)

            if vuln_t and r.tier in ("critical", "high"):
                self.ptprint(f"        {info_icon} VULNERABLE: {vuln_t}", Out.TEXT)
            self.ptprint(f"        {info_icon} RISK: {risk_t}", Out.TEXT)
            if info_t:
                self.ptprint(f"        {info_icon} INFO: {info_t}", Out.TEXT)

    def _inv_payload_terminal(self, p: InvalidCmdProbeResult) -> str:
        prev = p.line_sent_preview
        if p.probe_id in ("long_buffer_cwd", "long_buffer_user"):
            return f"{prev} ({self._INV_AUDIT_LONG_LEN}+ byte line)"
        return prev

    @staticmethod
    def _inv_verdict_label(classification: str) -> str:
        return {
            "no_reply_code": "NO_REPLY_CODE",
            "connection_lost": "CONNECTION_LOST",
            "reply_timeout": "REPLY_TIMEOUT",
            "positive_2xx_unexpected": "UNEXPECTED_2XX",
            "null_byte_possible_login_230": "NULL_BYTE_POSSIBLE_LOGIN",
        }.get(classification, classification.upper())

    def _inv_probe_detail_lines(self, p: InvalidCmdProbeResult, post_auth: bool) -> None:
        """Print one probe block for invalid-command audit (aligned with cmd/active terminal style)."""
        fk = get_colored_text
        star_h = fk("[*]", color="INFO")
        info_i = fk("[i]", color="INFO")
        ok_i = fk("[✓]", color="NOTVULN")
        bad_i = fk("[✗]", color="VULN")
        warn_i = fk("[!]", color="WARNING")

        self.ptprint(f"    [{p.probe_id}] {p.intent_label}", Out.TEXT)
        self.ptprint(f"        {star_h} Payload: {self._inv_payload_terminal(p)}", Out.TEXT)

        code_s = str(p.reply_code) if p.reply_code is not None else "—"
        resp_summary = f"{code_s} | {p.classification}"
        auth_note = "after login" if post_auth else "before login"

        cls = p.classification
        if cls in ("no_reply_code", "connection_lost", "reply_timeout"):
            self.ptprint(f"        {bad_i} Verdict: {self._inv_verdict_label(cls)}", Out.TEXT)
            if cls == "no_reply_code":
                self.ptprint(
                    f"        {info_i} RISK: No standard numeric FTP reply; server may have stalled or dropped the line.",
                    Out.TEXT,
                )
            elif cls == "connection_lost":
                self.ptprint(
                    f"        {info_i} RISK: Connection closed or reset after probe (service instability).",
                    Out.TEXT,
                )
                self.ptprint(
                    f"        {info_i} INFO: Possible Denial of Service (DoS) via malformed or oversized input.",
                    Out.TEXT,
                )
            else:
                self.ptprint(
                    f"        {info_i} RISK: Reply timed out; control channel may be slow or stuck.",
                    Out.TEXT,
                )
        elif cls == "positive_2xx_unexpected":
            self.ptprint(f"        {bad_i} Verdict: UNEXPECTED_2XX", Out.TEXT)
            self.ptprint(
                f"        {info_i} RISK: Server accepted garbage or probe with a success class reply (review manually).",
                Out.TEXT,
            )
        elif cls == "null_byte_possible_login_230":
            self.ptprint(f"        {bad_i} Verdict: NULL_BYTE_POSSIBLE_LOGIN", Out.TEXT)
            self.ptprint(
                f"        {info_i} RISK: USER with null byte may have produced login success (230); verify PWD/session.",
                Out.TEXT,
            )
        else:
            self.ptprint(f"        {ok_i} Response: {resp_summary}", Out.TEXT)
            # Informational "Result" for common benign cases
            if cls == "server_error_5xx":
                if p.probe_id == "unknown_hello":
                    msg = f"Unknown verb rejected with 5xx ({auth_note})."
                elif p.probe_id == "user_typo":
                    msg = f"Typo command rejected; no obvious syntax bypass ({auth_note})."
                elif p.probe_id == "user_null_byte":
                    msg = "Null-byte USER handled without accepting a full login in this reply."
                elif p.probe_id in ("long_buffer_cwd", "long_buffer_user"):
                    msg = f"Large buffer on {p.probe_id.split('_')[-1].upper()} rejected with an error response."
                elif p.probe_id == "format_string_stat":
                    msg = "Format-string STAT probe answered without unexpected 2xx success."
                else:
                    msg = f"Server returned 5xx for malformed input ({auth_note})."
            elif cls in ("null_byte_user_truncation_331",):
                msg = "331 after null-byte USER suggests truncation parsing (review for auth bypass)."
            elif cls == "double_crlf_probe_reply":
                msg = "Server replied to double-CRLF smuggle probe; check for response splitting."
            else:
                msg = f"Classification: {cls} ({auth_note})."
            self.ptprint(f"        {info_i} Result: {msg}", Out.TEXT)

        if p.null_byte_outcome:
            self.ptprint(f"        {warn_i} nullByteOutcome: {p.null_byte_outcome}", Out.TEXT)
        if p.error:
            self.ptprint(f"        {warn_i} error: {p.error}", Out.TEXT)
        if p.follow_up_command:
            fc = str(p.follow_up_reply_code) if p.follow_up_reply_code is not None else "—"
            sn = (p.follow_up_reply_snippet or "")[:180]
            if p.follow_up_reply_snippet and len(p.follow_up_reply_snippet) > 180:
                sn += "…"
            self.ptprint(
                f"        {info_i} follow-up {p.follow_up_command} → {fc}: {sn}",
                Out.TEXT,
            )

    def _print_invalid_cmd_audit_terminal(self, inv: InvalidCmdAuditResult) -> None:
        """Structured invalid-command (INVCOMM) terminal output."""
        fk = get_colored_text
        warn_b = fk("[!]", color="WARNING")
        vuln_b = fk("[!]", color="VULN")

        self.ptprint("Invalid command resilience (raw socket)", Out.INFO)

        if inv.setup_error:
            self.ptprint(f"    {fk('[✗]', color='VULN')} {inv.setup_error}", Out.TEXT)
            if inv.tls_handshake_hint:
                self.ptprint(f"    {warn_b} tlsHandshakeHint: {inv.tls_handshake_hint}", Out.TEXT)
            if inv.obsolete_tls_suspected:
                self.ptprint(
                    f"    {fk('[✗]', color='VULN')} Obsolete TLS: server likely requires obsolete TLS (<1.2); "
                    "see JSON tlsHandshakeHint / setupError.",
                    Out.TEXT,
                )
            return

        rating = inv.overall_resilience_rating
        ru = rating.upper()
        if rating == "Vulnerable":
            rb = "Unexpected 2xx, null-byte login suspicion, or no recovery after probe (see JSON)."
            ricon = vuln_b
        elif rating == "Degraded":
            rb = "Server stability issues during fuzzing (timeouts, drops, or suspicious replies)."
            ricon = warn_b
        else:
            rb = "Replies largely within expected error handling for this run."
            ricon = fk("[✓]", color="NOTVULN")

        self.ptprint(f"    {ricon} Rating: {ru} — {rb}", Out.TEXT)
        if inv.null_byte_truncation_suspected:
            self.ptprint(f"    {warn_b} nullByteTruncationSuspected=true", Out.TEXT)
        if inv.post_auth_login_error:
            self.ptprint(f"    {warn_b} post-auth login: {inv.post_auth_login_error}", Out.TEXT)
        if inv.tls_handshake_hint:
            self.ptprint(f"    {warn_b} tlsHandshakeHint: {inv.tls_handshake_hint}", Out.TEXT)
        if inv.obsolete_tls_suspected:
            self.ptprint(
                f"    {fk('[✗]', color='VULN')} Obsolete TLS: post-auth TLS suggests obsolete protocol.",
                Out.TEXT,
            )

        for label, sess, title_fn in (
            (
                "preAuth",
                inv.pre_auth,
                lambda sr: f"Pre-authentication resilience ({sr.resilience_rating})",
            ),
            (
                "postAuth",
                inv.post_auth,
                lambda sr: f"Post-authentication checks ({sr.resilience_rating})",
            ),
        ):
            if sess is None:
                continue
            self.ptprint(title_fn(sess), Out.INFO)
            if sess.null_byte_truncation_suspected:
                self.ptprint(f"    {warn_b} nullByteTruncationSuspected in {label}", Out.TEXT)
            if sess.had_connection_drop:
                self.ptprint(f"    {warn_b} Connection drop observed in {label}", Out.TEXT)
            post_auth = label == "postAuth"
            for p in sess.probes:
                self._inv_probe_detail_lines(p, post_auth)

    def test_command_audit(self, creds: Creds | None) -> CommandAuditResult:
        """
        PTL-SVC-FTP-CMD: passive enumeration via HELP, FEAT, SITE HELP / SITE HELP ALL.
        """
        trunc_flag = False
        site_all_pre_err: str | None = None
        site_all_post_err: str | None = None

        def take(raw: str) -> str:
            nonlocal trunc_flag
            out, t = self._truncate_cmd_audit_reply(raw)
            if t:
                trunc_flag = True
            return out

        pre = self.connect()
        try:
            help_r = take(self._ftp_send_cmd(pre, "HELP"))
            feat_r = take(self._ftp_send_cmd(pre, "FEAT"))
            site_pre: str | None = None
            site_all_pre: str | None = None
            if re.search(r"\bSITE\b", help_r, re.I):
                site_pre = take(self._ftp_send_cmd(pre, "SITE HELP"))
                raw_all, err = self._ftp_send_cmd_site_help_all_safe(pre)
                if err:
                    site_all_pre_err = err
                elif raw_all is not None:
                    site_all_pre = take(raw_all)
        finally:
            try:
                pre.close()
            except Exception:
                pass

        site_post: str | None = None
        site_all_post: str | None = None
        if creds is not None:
            post = self.connect()
            try:
                post.login(creds.user, creds.passw)
                site_post = take(self._ftp_send_cmd(post, "SITE HELP"))
                raw_all_p, err_p = self._ftp_send_cmd_site_help_all_safe(post)
                if err_p:
                    site_all_post_err = err_p
                elif raw_all_p is not None:
                    site_all_post = take(raw_all_p)
            finally:
                try:
                    post.close()
                except Exception:
                    pass

        feat_labels = self._parse_feat_feature_labels(feat_r)
        risks: list[CmdAuditRisk] = []
        risks.extend(self._cmd_audit_scan_text(help_r, "helpPreAuth"))
        risks.extend(self._cmd_audit_scan_text(feat_r, "featResponse"))
        if site_pre:
            risks.extend(self._cmd_audit_scan_text(site_pre, "siteHelpPreAuth"))
        if site_all_pre:
            risks.extend(self._cmd_audit_scan_text(site_all_pre, "siteHelpAllPreAuth"))
        if site_post:
            risks.extend(self._cmd_audit_scan_text(site_post, "siteHelpPostAuth"))
        if site_all_post:
            risks.extend(self._cmd_audit_scan_text(site_all_post, "siteHelpAllPostAuth"))

        merged = self._cmd_audit_merge_risks(risks)
        return CommandAuditResult(
            help_r,
            feat_r,
            site_pre,
            site_all_pre,
            site_post,
            site_all_post,
            feat_labels,
            merged,
            trunc_flag,
            site_all_pre_err,
            site_all_post_err,
        )

    def _cmd_passive_audit_blob(self, ca: CommandAuditResult | None) -> str:
        if ca is None:
            return ""
        parts = [
            ca.help_pre_auth,
            ca.feat_response,
            ca.site_help_pre or "",
            ca.site_help_all_pre or "",
            ca.site_help_post or "",
            ca.site_help_all_post or "",
        ]
        return "\n".join(parts)

    def _cmd_advertised_in_passive(self, ca: CommandAuditResult | None, key: str) -> bool:
        pat = self._CMD_ACTIVE_PATTERNS.get(key)
        if pat is None or ca is None:
            return False
        return bool(pat.search(self._cmd_passive_audit_blob(ca)))

    @staticmethod
    def _cmd_active_set_socket_timeout(ftp: ftplib.FTP, seconds: float) -> None:
        if getattr(ftp, "sock", None) is not None:
            ftp.sock.settimeout(seconds)

    def _cmd_active_reconnect_if_needed(self, creds: Creds, ftp: ftplib.FTP | None) -> ftplib.FTP:
        if ftp is not None:
            try:
                self._cmd_active_set_socket_timeout(ftp, 5.0)
                ftp.sendcmd("NOOP")
                return ftp
            except Exception:
                try:
                    ftp.close()
                except Exception:
                    pass
        n = self.connect()
        n.login(creds.user, creds.passw)
        n.set_pasv(not self.args.active)
        return n

    def _cmd_active_send_probe(self, ftp: ftplib.FTP, cmd: str) -> tuple[int | None, str, str | None]:
        try:
            self._cmd_active_set_socket_timeout(ftp, self._CMD_ACTIVE_PROBE_TIMEOUT)
            r = ftp.sendcmd(cmd)
            line = r.strip().split("\n")[0][:500]
            code = int(line[:3]) if len(line) >= 3 and line[:3].isdigit() else None
            return code, line, None
        except ftplib.error_perm as e:
            s = str(e).strip()
            line = s.split("\n")[0][:500]
            code = int(line[:3]) if len(line) >= 3 and line[:3].isdigit() else None
            return code, line, None
        except ftplib.error_temp as e:
            s = str(e).strip()
            line = s.split("\n")[0][:500]
            code = int(line[:3]) if len(line) >= 3 and line[:3].isdigit() else None
            return code, line, None
        except (TimeoutError, socket.timeout, OSError, EOFError) as e:
            err = f"{type(e).__name__}: {e}"
            return None, "", err
        except Exception as e:
            return None, "", f"{type(e).__name__}: {e}"

    @staticmethod
    def _cmd_active_classify_code(code: int | None, error: str | None) -> str:
        if error:
            el = error.lower()
            if "timeout" in el or "timed out" in el:
                return "timeout_or_connection_lost"
            if "reset" in el or "broken pipe" in el or "eof" in el:
                return "connection_reset_or_eof"
            return "probe_error"
        if code == 530:
            return "not_logged_in_or_insufficient_privilege"
        if code == 550:
            return "action_denied_or_file_unavailable"
        if code is not None and 200 <= code < 300:
            return "command_accepted"
        if code in (501, 502, 504, 421):
            return "not_implemented_bad_sequence_or_syntax"
        if code == 500:
            return "syntax_error_or_unknown_command"
        if code is None:
            return "no_numeric_reply_code"
        return f"ftp_reply_{code}"

    def test_command_audit_active(
        self, creds: Creds, passive: CommandAuditResult | None
    ) -> CommandAuditActiveResult:
        """
        Safe SITE probes (no system paths). Per-probe socket timeout; DELE cleanup; 530 vs 550 in classification.
        """
        timeout_s = self._CMD_ACTIVE_PROBE_TIMEOUT
        probe_name = f".ptsrvtester_probe_{secrets.token_hex(4)}"
        copy_name = f".ptsrvtester_probe_cp_{secrets.token_hex(4)}"
        link_name = f".ptsrvtester_probe_lnk_{secrets.token_hex(4)}"
        ftp: ftplib.FTP | None = None
        probes: list[CmdActiveProbeResult] = []
        probe_created = False
        cleanup_errs: list[str] = []

        def run_one(pid: str, cmd: str, adv_key: str) -> None:
            nonlocal ftp
            ftp = self._cmd_active_reconnect_if_needed(creds, ftp)
            code, line, err = self._cmd_active_send_probe(ftp, cmd)
            cls = self._cmd_active_classify_code(code, err)
            probes.append(
                CmdActiveProbeResult(
                    pid, cmd, code, line, cls, self._cmd_advertised_in_passive(passive, adv_key), err
                )
            )

        try:
            ftp = self.connect()
            ftp.login(creds.user, creds.passw)
            ftp.set_pasv(not self.args.active)
            self._cmd_active_set_socket_timeout(ftp, timeout_s)
            try:
                ftp.storbinary(f"STOR {probe_name}", BytesIO(b"PTS"))
            except Exception as e:
                return CommandAuditActiveResult(
                    timeout_s, None, True, None, tuple(), str(e)
                )
            probe_created = True

            run_one("umask", "SITE UMASK", "umask")
            run_one("chmod", f"SITE CHMOD 644 {probe_name}", "chmod")
            run_one("chown", f"SITE CHOWN __ptsrvtest_invalid_user__ {probe_name}", "chown")
            run_one("symlink", f"SITE SYMLINK {probe_name} {link_name}", "symlink")
            run_one("cpfr", f"SITE CPFR {probe_name}", "cpfr")
            run_one("cpto", f"SITE CPTO {copy_name}", "cpto")
            run_one("exec", "SITE EXEC", "exec")
        finally:
            if probe_created:
                try:
                    cf = self._cmd_active_reconnect_if_needed(creds, ftp)
                    self._cmd_active_set_socket_timeout(cf, timeout_s)
                    for victim in (link_name, copy_name, probe_name):
                        try:
                            cf.delete(victim)
                        except ftplib.Error as e:
                            cleanup_errs.append(f"{victim}: {e}")
                        except Exception as e:
                            cleanup_errs.append(f"{victim}: {type(e).__name__}: {e}")
                    try:
                        cf.close()
                    except Exception:
                        pass
                except Exception as e:
                    cleanup_errs.append(f"cleanup: {e}")
            else:
                if ftp is not None:
                    try:
                        ftp.close()
                    except Exception:
                        pass

        ce = "; ".join(cleanup_errs) if cleanup_errs else None
        return CommandAuditActiveResult(
            timeout_s, probe_name, len(cleanup_errs) == 0, ce, tuple(probes), None
        )

    @staticmethod
    def _inv_recv_one_line_raw(
        sock: socket.socket, timeout: float, max_len: int = 65536
    ) -> tuple[bytes, str | None]:
        sock.settimeout(timeout)
        buf = bytearray()
        try:
            while len(buf) < max_len:
                ch = sock.recv(1)
                if not ch:
                    return bytes(buf), "connection_closed" if not buf else None
                buf += ch
                if buf.endswith(b"\n"):
                    break
            return bytes(buf), None
        except socket.timeout:
            return bytes(buf), "timeout"
        except OSError as e:
            return bytes(buf), f"{type(e).__name__}: {e}"

    @classmethod
    def _inv_read_ftp_reply_raw(
        cls, sock: socket.socket, timeout: float
    ) -> tuple[int | None, str, str | None]:
        lines: list[str] = []
        code: int | None = None
        err: str | None = None
        max_lines = 64
        for _ in range(max_lines):
            raw, line_err = cls._inv_recv_one_line_raw(sock, timeout)
            if line_err and line_err != "connection_closed":
                err = line_err
            if not raw:
                if not lines:
                    return None, "", err or "connection_closed"
                break
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            lines.append(line)
            if len(line) >= 4 and line[0:3].isdigit():
                c = int(line[0:3])
                if line[3] == "-":
                    continue
                if line[3] == " ":
                    code = c
                    break
            elif len(line) >= 3 and line[0:3].isdigit() and len(line) == 3:
                code = int(line[0:3])
                break
            if line_err == "connection_closed":
                err = line_err
                break
            if err == "timeout":
                break
        else:
            err = err or "too_many_reply_lines"
        return code, "\n".join(lines), err

    @staticmethod
    def _inv_drain_control_socket(
        sock: socket.socket,
        max_bytes: int,
        chunk_timeout: float,
        restore_timeout: float | None,
    ) -> tuple[int, bytes]:
        """Read until idle timeout or EOF; avoids leaving tail bytes for a later session on same socket."""
        buf = bytearray()
        sock.settimeout(chunk_timeout)
        try:
            while len(buf) < max_bytes:
                try:
                    chunk = sock.recv(8192)
                except socket.timeout:
                    break
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
        finally:
            if restore_timeout is not None:
                try:
                    sock.settimeout(restore_timeout)
                except OSError:
                    pass
        return len(buf), bytes(buf)

    @staticmethod
    def _inv_audit_ssl_context() -> ssl.SSLContext:
        """
        Same idea as pentest/self-signed clients: wrap plain socket after implicit TLS or 234 (AUTH TLS).
        Uses create_default_context() (typically TLS 1.2+ only); handshake failure vs. old TLS 1.0/1.1-only
        servers may surface as connection/setup errors — see PTL-SVC-FTP-INVCOMM-implementation.md.
        """
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    @staticmethod
    def _inv_classify_ssl_handshake_error(exc: ssl.SSLError) -> tuple[bool, str]:
        """
        Returns (obsolete_tls_suspected_for_old_tls_finding, tls_handshake_hint).
        "Obsolete" branch: OpenSSL / Python wording for rejected legacy protocol version.
        """
        s = str(exc)
        sl = s.lower()
        sl_nospace = sl.replace(" ", "")
        definite = (
            "unsupported_protocol" in sl_nospace
            or "version_too_low" in sl_nospace
            or "wrong_version_number" in sl_nospace
            or "wrong version number" in sl
        )
        admin = (
            "The server likely requires obsolete TLS (e.g. 1.0/1.1) or offers an incompatible handshake; "
            "the client (Python ssl.create_default_context) typically requires TLS 1.2+. "
            "The invalid-command audit (-iv) over the encrypted channel could not complete. "
            "Obsolete protocol versions increase exposure to known protocol-level weaknesses "
            "(legacy stack — verify daemon version)."
        )
        if definite:
            return True, admin
        if any(
            x in sl
            for x in (
                "version",
                "protocol",
                "wrong alert",
                "alert handshake",
                "tlsv1",
                "sslv3",
            )
        ):
            return False, (
                "Potential TLS version/protocol mismatch (server may require TLS < 1.2). "
                "See setupError for OpenSSL/Python wording."
            )
        return False, f"TLS handshake error (see setupError): {s[:400]}"

    def _inv_wrap_tls_control_socket(
        self, ctx: ssl.SSLContext, raw_sock: socket.socket, host: str
    ) -> socket.socket:
        try:
            return ctx.wrap_socket(
                raw_sock, server_hostname=host if ssl.HAS_SNI else None
            )
        except ssl.SSLError as e:
            obsolete, hint = self._inv_classify_ssl_handshake_error(e)
            raise InvCmdAuditSetupError(
                f"TLS handshake failed: {e}",
                tls_handshake_hint=hint,
                obsolete_tls_suspected=obsolete,
            ) from e

    def _inv_open_control_socket_raw(self) -> socket.socket:
        """Raw control TCP (+ TLS); consume welcome. No ftplib makefile — safe for \\x00 on wire."""
        host = str(self.args.target.ip)
        port = self.args.target.port
        t = 10.0
        ctx = self._inv_audit_ssl_context()
        raw_sock = socket.create_connection((host, port), timeout=t)
        try:
            if self.args.tls:
                sock = self._inv_wrap_tls_control_socket(ctx, raw_sock, host)
                sock.settimeout(t)
                c, text, err = self._inv_read_ftp_reply_raw(sock, t)
                if c != 220:
                    sock.close()
                    raise OSError(f"Expected 220 after implicit TLS, got {c}: {text[:400]}")
                return sock

            if self.args.starttls:
                raw_sock.settimeout(t)
                c, text, err = self._inv_read_ftp_reply_raw(raw_sock, t)
                if c != 220:
                    raw_sock.close()
                    raise OSError(f"Expected 220 before STARTTLS, got {c}: {text[:400]}")
                raw_sock.sendall(b"AUTH TLS\r\n")
                c2, t2, err2 = self._inv_read_ftp_reply_raw(raw_sock, t)
                if c2 != 234:
                    raw_sock.close()
                    raise OSError(f"Expected 234 after AUTH TLS, got {c2}: {t2[:400]}")
                sock = self._inv_wrap_tls_control_socket(ctx, raw_sock, host)
                sock.settimeout(t)
                return sock

            raw_sock.settimeout(t)
            c, text, err = self._inv_read_ftp_reply_raw(raw_sock, t)
            if c != 220:
                raw_sock.close()
                raise OSError(f"Expected 220 welcome, got {c}: {text[:400]}")
            return raw_sock
        except Exception:
            try:
                raw_sock.close()
            except Exception:
                pass
            raise

    @staticmethod
    def _inv_line_preview(payload: bytes, limit: int = 120) -> str:
        p = payload.replace(b"\r", b"").replace(b"\n", b"")
        if b"\x00" in p:
            p = p.replace(b"\x00", b"\\x00")
        try:
            s = p.decode("utf-8", errors="replace")
        except Exception:
            s = repr(p[:limit])
        return s if len(s) <= limit else s[: limit - 3] + "..."

    def _inv_probe_definitions(self) -> tuple[tuple[str, str, bytes], ...]:
        n = self._INV_AUDIT_LONG_LEN
        return (
            ("unknown_hello", "unknown_verb", b"HELLO"),
            ("user_typo", "syntax_typo", b"USERR ptsrvtest"),
            ("user_null_byte", "null_byte_injection", b"USER root\x00admin"),
            ("long_buffer_cwd", "buffer_long_line", b"CWD " + b"A" * n),
            ("long_buffer_user", "buffer_long_line", b"USER " + b"A" * n),
            ("format_string_stat", "format_string_probe", b"STAT %n%s%p%s%n"),
            ("path_traversal_rnfr", "path_traversal", b"RNFR ../../etc/passwd"),
            ("cmd_injection_site", "command_injection_site", b"SITE CHMOD 777; id; whoami"),
            ("bad_port", "data_channel_malformed", b"PORT 999,999,999,999,999,999"),
            ("pasv_garbage", "data_channel_malformed", b"PASV x"),
            ("list_typo", "syntax_typo", b"LISTT"),
            ("cwd_utf8", "encoding_stress", b"CWD " + "\u00e9test".encode("utf-8")),
            (
                "unicode_invalid_cwd",
                "encoding_stress",
                b"CWD " + b"\xff\xfe\xfd\xfc",
            ),
            # Last: may leave extra protocol data on the wire if the server parses multiple lines.
            ("double_newline_smuggle", "request_smuggling", b"USER test\r\n\r\nPASS test"),
        )

    def _inv_classify_probe(self, probe_id: str, code: int | None, recv_err: str | None) -> str:
        if recv_err in ("connection_closed",) or (
            recv_err and "reset" in recv_err.lower()
        ):
            return "connection_lost"
        if recv_err == "timeout":
            return "reply_timeout"
        if code is None:
            return "no_reply_code"
        if 200 <= code < 300:
            if (
                probe_id == "format_string_stat"
                and code in self._INV_STAT_SUCCESS_CODES
            ):
                return "stat_success_rfc_2xx"
            return "positive_2xx_unexpected"
        if code == 331 and probe_id == "user_null_byte":
            return "null_byte_user_truncation_331"
        if code == 230 and probe_id == "user_null_byte":
            return "null_byte_possible_login_230"
        if probe_id == "double_newline_smuggle" and code is not None:
            return "double_crlf_probe_reply"
        if 300 <= code < 400:
            return "continuation_3xx"
        if 400 <= code < 500:
            return "client_error_4xx"
        if 500 <= code < 600:
            return "server_error_5xx"
        return "other_reply"

    @classmethod
    def _inv_2xx_counts_toward_vulnerable(cls, probe_id: str, code: int) -> bool:
        """RFC-aligned filter: some 2xx are defined success for the command under test."""
        if probe_id == "format_string_stat" and code in cls._INV_STAT_SUCCESS_CODES:
            return False
        return True

    def _inv_raw_login(self, sock: socket.socket, creds: Creds, timeout: float) -> tuple[bool, str | None]:
        user_b = creds.user.encode("utf-8", errors="replace")
        pass_b = creds.passw.encode("utf-8", errors="replace")
        sock.sendall(b"USER " + user_b + b"\r\n")
        c, text, err = self._inv_read_ftp_reply_raw(sock, timeout)
        if err == "connection_closed":
            return False, "connection closed after USER"
        if c == 331 or c == 332:
            sock.sendall(b"PASS " + pass_b + b"\r\n")
            c2, t2, e2 = self._inv_read_ftp_reply_raw(sock, timeout)
            if c2 == 230 or c2 == 202:
                return True, None
            return False, f"PASS reply {c2}: {t2[:200]}"
        if c == 230:
            return True, None
        return False, f"USER reply {c}: {text[:200]}"

    def _inv_rate_session(
        self,
        probes: tuple[InvalidCmdProbeResult, ...],
        had_drop: bool,
        reconnect_ok: bool,
        null_suspect: bool,
    ) -> str:
        if any(
            p.reply_code is not None
            and 200 <= p.reply_code < 300
            and self._inv_2xx_counts_toward_vulnerable(p.probe_id, p.reply_code)
            for p in probes
        ):
            return "Vulnerable"
        if any(
            p.reply_code is not None
            and 300 <= p.reply_code < 400
            and p.probe_id in self._INV_3XX_CRITICAL_PROBE_IDS
            for p in probes
        ):
            return "Vulnerable"
        if any(p.classification == "null_byte_possible_login_230" for p in probes):
            return "Vulnerable"
        if had_drop:
            return "Degraded" if reconnect_ok else "Vulnerable"
        if null_suspect:
            return "Degraded"
        if any(
            p.classification == "continuation_3xx"
            and p.probe_id not in ("user_null_byte",)
            for p in probes
        ):
            return "Degraded"
        return "Stable"

    def _inv_run_invalid_session(
        self, phase: str, sock: socket.socket, timeout: float
    ) -> InvalidCmdSessionResult:
        probes_out: list[InvalidCmdProbeResult] = []
        had_drop = False
        null_suspect = False
        stop = False
        for probe_id, intent_label, payload in self._inv_probe_definitions():
            if stop:
                break
            line_on_wire = payload if payload.endswith(b"\r\n") else payload + b"\r\n"
            hexl = line_on_wire.hex()
            preview = self._inv_line_preview(payload)
            code: int | None = None
            text = ""
            recv_err: str | None = None
            ok_after = True
            err: str | None = None
            classification = "skipped"
            fu_cmd: str | None = None
            fu_code: int | None = None
            fu_snip: str | None = None
            nb_outcome: str | None = None
            try:
                sock.sendall(line_on_wire)
                code, text, recv_err = self._inv_read_ftp_reply_raw(sock, timeout)
                if recv_err in ("connection_closed", "timeout") or (
                    recv_err and "Broken pipe" in recv_err
                ):
                    ok_after = False
                    had_drop = True
                    stop = True
                if recv_err and recv_err not in ("connection_closed", "timeout"):
                    err = recv_err
            except (BrokenPipeError, ConnectionResetError, OSError) as e:
                ok_after = False
                had_drop = True
                stop = True
                err = f"{type(e).__name__}: {e}"
            if probe_id == "double_newline_smuggle" and ok_after:
                t_fu = min(self._INV_SMUGGLE_FOLLOWUP_TIMEOUT, timeout)
                extra_blocks: list[str] = []
                for _ in range(4):
                    c2, t2, e2 = self._inv_read_ftp_reply_raw(sock, t_fu)
                    if e2 == "connection_closed":
                        ok_after = False
                        had_drop = True
                        stop = True
                        recv_err = recv_err or e2
                        err = err or e2
                        break
                    has_body = bool((t2 or "").strip()) or c2 is not None
                    if e2 == "timeout" and not has_body:
                        break
                    if has_body:
                        extra_blocks.append(
                            f"(code={c2}) {t2}" if c2 is not None else (t2 or "")
                        )
                    if e2 == "timeout":
                        break
                if extra_blocks:
                    text = (text or "") + "\n--- smuggle_followup ---\n" + (
                        "\n--- smuggle_followup ---\n".join(extra_blocks)
                    )
                if ok_after:
                    n_drain, _dr = self._inv_drain_control_socket(
                        sock,
                        self._INV_DRAIN_MAX_BYTES,
                        self._INV_DRAIN_CHUNK_TIMEOUT,
                        timeout,
                    )
                    if n_drain:
                        text = (text or "") + f"\n--- drained_after_smuggle_bytes={n_drain} ---\n"
            classification = self._inv_classify_probe(probe_id, code, recv_err or err)
            if probe_id == "user_null_byte" and code in (331, 230):
                null_suspect = True
            if probe_id == "user_null_byte" and code == 331:
                nb_outcome = "truncation_username_prompt_password_331"
            elif probe_id == "user_null_byte" and code == 230 and ok_after:
                fu_cmd = "PWD"
                try:
                    sock.sendall(b"PWD\r\n")
                    pc, pt, pe = self._inv_read_ftp_reply_raw(sock, timeout)
                    fu_code = pc
                    fu_snip = (pt or "")[:800]
                    tl = (pt or "").lower()
                    if pc in (257, 250):
                        if "root" in tl or "/root" in tl:
                            nb_outcome = "critical_suspected_root_context_after_null_user_pwd_ok"
                        else:
                            nb_outcome = "logged_in_after_null_user_verify_with_pwd_response"
                    else:
                        nb_outcome = "logged_in_230_pwd_follow_up_unexpected"
                    if pe in ("connection_closed", "timeout") or (
                        pe and "Broken pipe" in pe
                    ):
                        ok_after = False
                        had_drop = True
                        stop = True
                except (BrokenPipeError, ConnectionResetError, OSError) as e:
                    ok_after = False
                    had_drop = True
                    stop = True
                    fu_snip = str(e)[:200]
                    nb_outcome = "logged_in_230_pwd_follow_up_failed"
            probes_out.append(
                InvalidCmdProbeResult(
                    phase,
                    probe_id,
                    intent_label,
                    hexl,
                    preview,
                    code,
                    text[: self._INV_AUDIT_REPLY_TEXT_MAX] if text else "",
                    classification,
                    ok_after,
                    err,
                    fu_cmd,
                    fu_code,
                    fu_snip,
                    nb_outcome,
                )
            )

        reconnect_ok = False
        if had_drop:
            time.sleep(1.0)
            try:
                s2 = self._inv_open_control_socket_raw()
                s2.close()
                reconnect_ok = True
            except Exception:
                reconnect_ok = False

        rating = self._inv_rate_session(
            tuple(probes_out), had_drop, reconnect_ok, null_suspect
        )
        return InvalidCmdSessionResult(
            phase, tuple(probes_out), rating, null_suspect, had_drop
        )

    def _inv_overall_resilience(
        self, pre: InvalidCmdSessionResult | None, post: InvalidCmdSessionResult | None
    ) -> str:
        order = {"Stable": 0, "Degraded": 1, "Vulnerable": 2}
        best = "Stable"
        for s in (pre, post):
            if s is None:
                continue
            if order.get(s.resilience_rating, 0) > order[best]:
                best = s.resilience_rating
        return best

    def test_invalid_command_audit(
        self, creds: Creds | None
    ) -> InvalidCmdAuditResult:
        """
        PTL-SVC-FTP-INVCOMM: invalid / malformed control lines via raw socket (bytes on wire).
        Includes USER root\\x00… null-byte probe; resilienceRating Stable|Degraded|Vulnerable.
        """
        timeout = self._INV_AUDIT_TIMEOUT
        pre: InvalidCmdSessionResult | None = None
        post: InvalidCmdSessionResult | None = None
        try:
            s = self._inv_open_control_socket_raw()
        except InvCmdAuditSetupError as e:
            return InvalidCmdAuditResult(
                timeout,
                None,
                None,
                "Stable",
                False,
                str(e),
                None,
                tls_handshake_hint=e.tls_handshake_hint,
                obsolete_tls_suspected=e.obsolete_tls_suspected,
            )
        except Exception as e:
            return InvalidCmdAuditResult(timeout, None, None, "Stable", False, str(e), None)
        try:
            pre = self._inv_run_invalid_session("preAuth", s, timeout)
        finally:
            try:
                s.close()
            except Exception:
                pass

        post: InvalidCmdSessionResult | None = None
        post_login_err: str | None = None
        post_tls_hint: str | None = None
        post_obsolete_tls = False
        if creds is not None:
            try:
                s2 = self._inv_open_control_socket_raw()
            except InvCmdAuditSetupError as e:
                post_login_err = f"post-auth connection: {e}"
                post_tls_hint = e.tls_handshake_hint
                post_obsolete_tls = e.obsolete_tls_suspected
            except Exception as e:
                post_login_err = f"post-auth connection: {e}"
            else:
                try:
                    ok, lerr = self._inv_raw_login(s2, creds, timeout)
                    if ok:
                        post = self._inv_run_invalid_session("postAuth", s2, timeout)
                    else:
                        post_login_err = lerr or "login failed"
                finally:
                    try:
                        s2.close()
                    except Exception:
                        pass

        overall = self._inv_overall_resilience(pre, post)
        null_any = bool(
            (pre and pre.null_byte_truncation_suspected)
            or (post and post.null_byte_truncation_suspected)
        )
        return InvalidCmdAuditResult(
            timeout,
            pre,
            post,
            overall,
            null_any,
            None,
            post_login_err,
            tls_handshake_hint=post_tls_hint,
            obsolete_tls_suspected=post_obsolete_tls,
        )

    def test_encryption(self) -> EncryptionResult:
        """
        Test encryption options: plaintext (21), AUTH TLS (explicit), implicit TLS (990).
        Uses fresh connections; does not use self.args.tls/starttls.
        AUTH TLS sends AUTH TLS command then TLS handshake (RFC 2228).
        """
        host = self.args.target.ip
        port = self.args.target.port
        timeout = 10.0
        plaintext_ok = False
        auth_tls_ok = False
        tls_ok = False
        _ssl_ctx = ssl._create_unverified_context()
        tls_only_port = port == 990

        if not tls_only_port:
            # 1. Plaintext (no TLS)
            try:
                ftp = ftplib.FTP()
                ftp.connect(host, port, timeout=timeout)
                _ = ftp.welcome
                plaintext_ok = True
                ftp.close()
            except Exception:
                pass

            # 2. AUTH TLS (explicit: plain connect, then AUTH TLS + TLS handshake)
            try:
                ftp = ftplib.FTP_TLS()
                ftp.connect(host, port, timeout=timeout)
                _ = ftp.welcome
                ftp.auth()
                auth_tls_ok = True
                ftp.close()
            except Exception:
                pass

        # 3. Implicit TLS (port 990)
        _connect_timeout = 15.0 if tls_only_port else timeout

        def _try_implicit_tls(sni):
            ftp = FTP_TLS_implicit()
            ftp.context = _ssl_ctx
            try:
                ftp.connect(host, port, timeout=_connect_timeout)
                _ = ftp.welcome
                return True
            except Exception:
                return False
            finally:
                try:
                    ftp.close()
                except Exception:
                    pass

        try:
            try:
                ipaddress.ip_address(host)
                _sni_first, _sni_fallback = None, host
            except ValueError:
                _sni_first, _sni_fallback = host, None
            for _sni in (_sni_first, _sni_fallback):
                if _sni is None and _sni_fallback is None:
                    continue
                try:
                    if _try_implicit_tls(_sni):
                        tls_ok = True
                        break
                except Exception:
                    pass
        except Exception:
            pass

        return EncryptionResult(plaintext_ok, auth_tls_ok, tls_ok)

    def _stream_banner_result(self) -> None:
        if self.use_json or not (info := self.results.info) or info.banner is None:
            return
        with self._output_lock:
            self.ptprint("Banner", Out.INFO)
            sid = identify_service(info.banner)
            if sid is None:
                icon = get_colored_text("[✓]", color="NOTVULN")
            elif sid.version is not None:
                icon = get_colored_text("[✗]", color="VULN")
            else:
                icon = get_colored_text("[!]", color="WARNING")
            self.ptprint(f"    {icon} {info.banner}", Out.TEXT)
            if sid is not None:
                self.ptprint("Service Identification", Out.INFO)
                self.ptprint(f"    Product:  {sid.product}", Out.TEXT)
                self.ptprint(
                    f"    Version:  {sid.version if sid.version else 'unknown'}",
                    Out.TEXT,
                )
                self.ptprint(f"    CPE:      {sid.cpe}", Out.TEXT)
        self._streamed_banner = True

    def _stream_encryption_result(self) -> None:
        if self.use_json:
            return
        with self._output_lock:
            self.ptprint("Encryption", Out.INFO)
            if (err := self.results.encryption_error) is not None:
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} Encryption test failed: {err}", Out.TEXT)
                self._streamed_encryption = True
                return
            enc = self.results.encryption
            if enc is None:
                return
            plaintext_only = enc.plaintext_ok and not enc.auth_tls_ok and not enc.tls_ok
            any_ok = enc.plaintext_ok or enc.auth_tls_ok or enc.tls_ok
            if plaintext_only:
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} Plaintext only", Out.TEXT)
            elif any_ok:
                if enc.plaintext_ok:
                    icon = (
                        get_colored_text("[!]", color="WARNING")
                        if (enc.auth_tls_ok or enc.tls_ok)
                        else get_colored_text("[✓]", color="NOTVULN")
                    )
                    self.ptprint(f"    {icon} Plaintext", Out.TEXT)
                if enc.auth_tls_ok:
                    icon = get_colored_text("[✓]", color="NOTVULN")
                    self.ptprint(f"    {icon} AUTH TLS", Out.TEXT)
                if enc.tls_ok:
                    icon = get_colored_text("[✓]", color="NOTVULN")
                    self.ptprint(f"    {icon} Implicit TLS", Out.TEXT)
            else:
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(
                    f"    {icon} No connection mode available (plaintext, AUTH TLS, implicit TLS failed)",
                    Out.TEXT,
                )
        self._streamed_encryption = True

    def _stream_anonymous_result(self) -> None:
        if self.use_json or (anonymous := self.results.anonymous) is None:
            return
        with self._output_lock:
            self.ptprint("Anonymous authentication", Out.INFO)
            if anonymous:
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} Enabled", Out.TEXT)
                # Basic permissions from access if available (anon + access in run-all)
                if (access := self.results.access) and access.results:
                    try:
                        anon_p = next(p for p in access.results if p.creds.user == "anonymous")
                        perm_str = (
                            f"    (Directory listing: {anon_p.dirlist is not None}, "
                            + f"Write: {anon_p.write}, Read: {anon_p.read}, Delete: {anon_p.delete})"
                        )
                        self.ptprint(perm_str, Out.TEXT)
                    except StopIteration:
                        pass
            else:
                icon = get_colored_text("[✓]", color="NOTVULN")
                self.ptprint(f"    {icon} Disabled", Out.TEXT)
        self._streamed_anonymous = True

    def _stream_brute_result(self) -> None:
        creds = self.results.creds
        if creds is None:
            return
        if not self.use_json and len(creds) > 0:
            with self._output_lock:
                self.ptprint(f"    Found {len(creds)} valid credentials", Out.INFO)
        self._streamed_brute = True

    def _try_login(self, creds: Creds) -> Creds | None:
        """Login attempt function for bruteforce

        Args:
            creds (Creds): Creds to use for login

        Returns:
            Creds | None: Creds if success, None if failed
        """
        ftp = self.connect()
        try:
            ftp.login(creds.user, creds.passw)
            result = creds
        except Exception as e:
            # Valid creds but server-side error?
            if e.args and len(e.args) > 0:
                if "cannot change directory" in str(e.args[0]).lower():
                    result = creds
                else:
                    result = None
            else:
                result = None
        finally:
            ftp.close()
            return result

    def bounce(self) -> BounceResult:
        """
        Attempts to login (anonymous or valid bruteforce creds) and
        perform an FTP bounce attack, either for port scan or
        request via file upload.

        Returns:
            BounceResult: results
        """

        creds: Creds | None = None
        write_path: str | None = None

        # Choose valid creds (any for --bounce, write-permitted for --bounce-file)
        if not self.args.bounce_file:
            # Any creds for port scan
            if self.results.anonymous:
                creds = Creds("anonymous", "")
            elif self.results.creds is not None and len(self.results.creds) > 0:
                for c in self.results.creds:
                    creds = c
                    break
        elif (access := self.results.access) is not None and access.results:
            # Write & Read creds for bounced request
            for p in access.results:
                if p.write is None or p.read is None:
                    continue
                else:
                    creds = p.creds
                    write_path = p.write

        if creds is None:
            return BounceResult(self.args.bounce, None, None, None, None)

        # Use the appropriate creds to connect to the service
        ftp = self.connect()
        ftp.login(creds.user, creds.passw)

        # Bounce setup attempt
        if not self._bounce_setup(ftp, self.args.bounce):
            return BounceResult(self.args.bounce, creds, False, None, None)

        if self.args.bounce_file and write_path is not None:
            # Full bounced request
            stored, uploaded, cleaned = False, False, False
            filename = write_path + ".txt"

            try:
                # Upload request file onto FTP server
                with open(self.args.bounce_file, "rb") as f:
                    # reusing previous filename, with doubled .txt extension
                    p = ftp.storbinary("STOR " + filename, f)
                    stored = True

                # Refresh bounce setup after STOR
                self._bounce_setup(ftp, self.args.bounce)

                # Upload request to bounce target
                # TODO timeout for unreachable ports?
                ftp.sendcmd("RETR " + filename)
                uploaded = True
            except FileNotFoundError:
                raise argparse.ArgumentError(None, f"File not found: '{self.args.bounce_file}'")
            except PermissionError:
                raise argparse.ArgumentError(
                    None, f"Cannot read file (permission denied): '{self.args.bounce_file}'"
                )
            except OSError as e:
                raise argparse.ArgumentError(None, f"Cannot read file '{self.args.bounce_file}': {e}")
            except ftplib.Error:
                pass
            finally:
                if stored:
                    # Cleanup the uploaded request file
                    try:
                        ftp.delete(filename)
                        cleaned = True
                    except ftplib.Error as e:
                        # 226 is success, but ftplib does not account for that
                        if e.args and len(e.args) > 0 and len(str(e.args[0])) >= 3:
                            if str(e.args[0])[:3] == "226":
                                cleaned = True

            return BounceResult(
                self.args.bounce,
                creds,
                True,
                None,
                BounceRequestResult(
                    filename,
                    stored,
                    uploaded,
                    cleaned,
                ),
            )
        else:
            # Just port scan
            try:
                ftp.sendcmd("LIST")

                port_ok = True
            except:
                port_ok = False

            return BounceResult(self.args.bounce, creds, True, port_ok, None)

    def _bounce_setup(self, ftp: ftplib.FTP, target: Target) -> bool:
        """Attempts to negotiate an FTP bounce configuration

        Args:
            ftp (ftplib.FTP): FTP connection
            target (Target): bounce target

        Returns:
            bool: negotiation result
        """
        try:
            ftp.sendport(target.ip, target.port)
        except:
            try:
                ftp.sendeprt(target.ip, target.port)
            except:
                return False

        return True

    def _print_conn_limits_audit_terminal(self, cl: ConnLimitsAuditResult) -> None:
        """Structured terminal report for connection limits audit (aligned with SMTP-style ptprint nesting).

        Icon semantics: [*] = block titles; [i] = neutral facts; [✓] / [✗] = verdicts (RISK lines use [✗]).
        Audit summary: one primary verdict line + one [i] caveat (heuristic / not DoS).
        """
        fk = get_colored_text
        d1 = "    "
        d2 = "        "
        d3 = "            "  # Under each PASV "Phase:" — metrics & verdicts visually nested under the phase line.
        star = fk("[*]", color="INFO")
        info_i = fk("[i]", color="INFO")
        tick = fk("[✓]", color="NOTVULN")
        cross = fk("[✗]", color="VULN")

        self.ptprint("Connection limits audit", Out.INFO)

        self.ptprint(f"{d1}{star} Connectivity & session burst", Out.TEXT)
        self.ptprint(
            f"{d2}{info_i} Setup: cryptoMode={cl.crypto_mode} | parallel {cl.parallel.succeeded}/{cl.parallel.attempted}"
            f" | sequential {cl.sequential.succeeded}/{cl.sequential.attempts}",
            Out.TEXT,
        )
        if cl.parallel.error_samples:
            self.ptprint(
                f"{d2}{info_i} Parallel errors (sample): {cl.parallel.error_samples[0][:120]}",
                Out.TEXT,
            )
        if cl.sequential.error_samples and cl.sequential.failed:
            self.ptprint(
                f"{d2}{info_i} Sequential errors (sample): {cl.sequential.error_samples[0][:120]}",
                Out.TEXT,
            )

        if _conn_limits_parallel_suspect(cl.parallel):
            self.ptprint(
                f"{d2}{info_i} Parallel burst: All {cl.parallel.attempted} simultaneous control sessions completed "
                f"(220 + QUIT) with no refusal.",
                Out.TEXT,
            )
            self.ptprint(
                f"{d2}{cross} RISK: No observed concurrency cap on this probe; many simultaneous clients could stress resources.",
                Out.TEXT,
            )
        elif cl.parallel.attempted >= 10 and (cl.parallel.failed > 0 or cl.parallel.succeeded < cl.parallel.attempted):
            self.ptprint(
                f"{d2}{tick} Parallel burst: {cl.parallel.succeeded}/{cl.parallel.attempted} sessions completed; "
                f"{cl.parallel.failed} failed or refused — possible concurrency or policy limits.",
                Out.TEXT,
            )
        else:
            self.ptprint(
                f"{d2}{info_i} Parallel burst: {cl.parallel.succeeded}/{cl.parallel.attempted} sessions completed "
                f"(probe volume below the N≥10 parallel heuristic threshold).",
                Out.TEXT,
            )

        if cl.sequential.attempts <= 0:
            self.ptprint(f"{d2}{info_i} Sequential rapid connect: skipped (0 attempts)", Out.TEXT)
        elif _conn_limits_sequential_suspect(cl.sequential):
            self.ptprint(
                f"{d2}{info_i} Sequential rapid connect: {cl.sequential.succeeded} back-to-back control sessions "
                f"succeeded without visible throttle.",
                Out.TEXT,
            )
            self.ptprint(
                f"{d2}{cross} RISK: No visible new-connection throttle in this rapid series.",
                Out.TEXT,
            )
        elif cl.sequential.attempts >= 20 and (
            cl.sequential.failed > 0 or cl.sequential.succeeded < cl.sequential.attempts
        ):
            self.ptprint(
                f"{d2}{tick} Sequential rapid connect: {cl.sequential.succeeded}/{cl.sequential.attempts} succeeded; "
                f"{cl.sequential.failed} failed — possible rate or policy limiting.",
                Out.TEXT,
            )
        else:
            self.ptprint(
                f"{d2}{info_i} Sequential rapid connect: {cl.sequential.succeeded}/{cl.sequential.attempts} sessions "
                f"(probe volume below the N≥20 sequential heuristic threshold).",
                Out.TEXT,
            )

        self.ptprint(f"{d1}{star} Idle & control timing (optional probes)", Out.TEXT)
        ipr = cl.idle_pre_auth
        if not ipr.performed:
            self.ptprint(
                f"{d2}{info_i} Idle pre-login: not probed (set --conn-limits-idle-pre-auth > 0)",
                Out.TEXT,
            )
        elif _conn_limits_idle_pre_suspect(ipr):
            self.ptprint(
                f"{d2}{info_i} Idle pre-login ~{ipr.wait_seconds:.0f}s: no 421/426/close observed — weak pre-auth idle limit suspected.",
                Out.TEXT,
            )
            self.ptprint(
                f"{d2}{cross} RISK: Long-lived anonymous control sessions may be possible before login.",
                Out.TEXT,
            )
        elif ipr.kick_observed:
            self.ptprint(
                f"{d2}{tick} Idle pre-login ~{ipr.wait_seconds:.0f}s: server closed or sent kick — {ipr.note[:120]}",
                Out.TEXT,
            )
        else:
            self.ptprint(
                f"{d2}{info_i} Idle pre-login ~{ipr.wait_seconds:.0f}s: no kick in window — {ipr.note[:120]}",
                Out.TEXT,
            )

        sa = cl.slow_auth
        if not sa.performed:
            self.ptprint(
                f"{d2}{info_i} Slow USER→PASS gap: not probed (set --conn-limits-slow-auth-gap > 0)",
                Out.TEXT,
            )
        elif _conn_limits_slow_auth_suspect(sa):
            self.ptprint(
                f"{d2}{info_i} Slow authentication: {sa.gap_seconds:.0f}s gap before PASS did not drop the session before reply.",
                Out.TEXT,
            )
            self.ptprint(
                f"{d2}{cross} RISK: Slowloris-style pacing on the control channel may be tolerated.",
                Out.TEXT,
            )
        elif sa.still_connected_after_pass is False:
            self.ptprint(
                f"{d2}{tick} Slow USER→PASS gap {sa.gap_seconds:.0f}s: connection dropped or hard-failed — possible anti-slow-auth policy.",
                Out.TEXT,
            )
        else:
            self.ptprint(
                f"{d2}{info_i} Slow USER→PASS gap {sa.gap_seconds:.0f}s: still_connected_after_pass={sa.still_connected_after_pass}",
                Out.TEXT,
            )

        ipo = cl.idle_post_auth
        if ipo is None:
            self.ptprint(
                f"{d2}{info_i} Idle post-login: skipped (no credentials or --conn-limits-idle-post-auth=0)",
                Out.TEXT,
            )
        elif not ipo.performed:
            self.ptprint(f"{d2}{info_i} Idle post-login: not probed", Out.TEXT)
        elif _conn_limits_idle_post_suspect(ipo):
            self.ptprint(
                f"{d2}{info_i} Idle post-login ~{ipo.wait_seconds:.0f}s: NOOP still succeeded — weak authenticated idle timeout suspected.",
                Out.TEXT,
            )
            self.ptprint(
                f"{d2}{cross} RISK: Authenticated sessions may linger without timely disconnect.",
                Out.TEXT,
            )
        elif ipo.kick_observed:
            self.ptprint(
                f"{d2}{tick} Idle post-login ~{ipo.wait_seconds:.0f}s: kick observed — {ipo.note[:120]}",
                Out.TEXT,
            )
        else:
            self.ptprint(
                f"{d2}{info_i} Idle post-login ~{ipo.wait_seconds:.0f}s: {ipo.note[:120]}",
                Out.TEXT,
            )

        self.ptprint(f"{d1}{star} Passive port allocation (PASV spam)", Out.TEXT)
        pp = cl.pasv_pre_auth
        self.ptprint(f"{d2}{star} Phase: Pre-authentication", Out.TEXT)
        err_bit = f" | err: {pp.error}" if pp.error else ""
        self.ptprint(
            f"{d3}{info_i} 227 (Ready): {pp.reply227} | 530 (Rejected): {pp.reply530} | Other: {pp.reply_other}{err_bit}",
            Out.TEXT,
        )
        if _conn_limits_pasv_pre_suspect(pp):
            self.ptprint(
                f"{d3}{cross} Pre-auth PASV: high 227 rate — passive data ports may be allocated before authentication.",
                Out.TEXT,
            )
        elif pp.error and pp.reply227 > 0:
            self.ptprint(
                f"{d3}{info_i} Result: PASV phase ended with an error after some 227 replies — inconclusive for pre-auth spam.",
                Out.TEXT,
            )
        elif pp.error:
            self.ptprint(
                f"{d3}{tick} Result: No pre-login 227 flood observed; session ended early ({pp.error[:100]}).",
                Out.TEXT,
            )
        elif pp.reply227 == 0:
            self.ptprint(
                f"{d3}{tick} Result: Server rejects or gates PASV before login (no 227 Ready flood in this run).",
                Out.TEXT,
            )
        else:
            self.ptprint(
                f"{d3}{info_i} Result: PASV pre-auth replies did not match the high–227 spam heuristic.",
                Out.TEXT,
            )

        po = cl.pasv_post_auth
        if po is None:
            self.ptprint(f"{d2}{star} Phase: Post-authentication — skipped (no credentials)", Out.TEXT)
        else:
            self.ptprint(f"{d2}{star} Phase: Post-authentication", Out.TEXT)
            err_po = f" | err: {po.error}" if po.error else ""
            self.ptprint(
                f"{d3}{info_i} 227 (Ready): {po.reply227} | 530 (Rejected): {po.reply530} | Other: {po.reply_other}{err_po}",
                Out.TEXT,
            )
            if _conn_limits_pasv_post_suspect(po):
                self.ptprint(
                    f"{d3}{cross} Post-auth PASV: high 227 rate on one session — passive allocations may be unbounded "
                    f"or weakly capped.",
                    Out.TEXT,
                )
            elif po.error:
                self.ptprint(
                    f"{d3}{info_i} Result: PASV phase ended with an error — inconclusive for post-auth spam.",
                    Out.TEXT,
                )
            else:
                self.ptprint(
                    f"{d3}{info_i} Result: PASV post-auth replies did not match the unbounded-227 heuristic.",
                    Out.TEXT,
                )

        self.ptprint(f"{d1}{star} Audit summary & heuristics", Out.TEXT)
        if cl.limits_insufficient_suspected:
            self.ptprint(
                f"{d2}{cross} LIMITS_INSUFFICIENT — bounded probes matched patterns associated with weak FTP limits "
                f"(connections, rate, PASV, and/or idle).",
                Out.TEXT,
            )
        else:
            self.ptprint(
                f"{d2}{tick} LIMITS_OK — bounded probes did not match insufficient-limit patterns in this run.",
                Out.TEXT,
            )
        self.ptprint(
            f"{d2}{info_i} Heuristic-only ({cl.parallel.attempted} parallel / {cl.sequential.attempts} sequential); "
            f"tune --conn-limits-* on a lab target — not a full DoS test; confirm in a controlled, authorized environment.",
            Out.TEXT,
        )

    def _print_pasv_port_range_terminal(self, ppr: PasvPortRangeResult) -> None:
        """Structured terminal report for passive port spread audit (aligned with connection limits / SMTP-style nesting)."""
        fk = get_colored_text
        d1 = "    "
        d2 = "        "
        star = fk("[*]", color="INFO")
        info_i = fk("[i]", color="INFO")
        warn_bang = fk("[!]", color="WARNING")
        tick = fk("[✓]", color="NOTVULN")
        cross = fk("[✗]", color="VULN")

        if self.args.tls:
            crypto_mode = "implicit_tls"
        elif self.args.starttls:
            crypto_mode = "starttls"
        else:
            crypto_mode = "plain"

        self.ptprint("Passive port range audit", Out.INFO)

        self.ptprint(f"{d1}{star} Port sampling & analysis", Out.TEXT)
        self.ptprint(
            f"{d2}{info_i} Setup: samples {len(ppr.probes)} | threshold {ppr.max_span_threshold} | cryptoMode={crypto_mode}",
            Out.TEXT,
        )
        n_ok = len(ppr.successful_ports)
        n_all = len(ppr.probes)
        if n_ok < n_all:
            self.ptprint(f"{d2}{info_i} Successful data channels: {n_ok}/{n_all}", Out.TEXT)

        ports_csv = ", ".join(str(p) for p in ppr.successful_ports) if ppr.successful_ports else "(none)"
        self.ptprint(f"{d2}{info_i} Collected ports: {ports_csv}", Out.TEXT)

        if ppr.min_port is not None and ppr.max_port is not None and ppr.observed_span is not None:
            self.ptprint(
                f"{d2}{info_i} Observed range: {ppr.min_port} - {ppr.max_port} (span: {ppr.observed_span})",
                Out.TEXT,
            )
        elif ppr.min_port is not None and ppr.max_port is not None:
            self.ptprint(
                f"{d2}{info_i} Observed range: {ppr.min_port} - {ppr.max_port}",
                Out.TEXT,
            )
        else:
            self.ptprint(
                f"{d2}{info_i} Observed range: n/a (insufficient data ports for min/max)",
                Out.TEXT,
            )

        if ppr.inconclusive:
            self.ptprint(
                f"{d2}{warn_bang} Result: Inconclusive (need ≥{ppr.min_samples_for_verdict} successful passive LIST samples).",
                Out.TEXT,
            )
        elif ppr.wide_passive_range:
            self.ptprint(
                f"{d2}{cross} Result: Wide passive range detected (span {ppr.observed_span} > {ppr.max_span_threshold}).",
                Out.TEXT,
            )
        else:
            self.ptprint(
                f"{d2}{tick} Result: Narrow passive range detected (span {ppr.observed_span} <= {ppr.max_span_threshold}).",
                Out.TEXT,
            )

        self.ptprint(f"{d1}{star} Audit summary & heuristics", Out.TEXT)
        if ppr.inconclusive:
            self.ptprint(f"{d2}{info_i} Status: PASSIVE_RANGE_INCONCLUSIVE", Out.TEXT)
            self.ptprint(
                f"{d2}{info_i} Finding: Not enough successful samples to judge passive port spread against threshold.",
                Out.TEXT,
            )
            self.ptprint(f"{d2}{info_i} Note: {ppr.detail}", Out.TEXT)
        elif ppr.wide_passive_range:
            self.ptprint(f"{d2}{cross} Status: PASSIVE_RANGE_WIDE", Out.TEXT)
            self.ptprint(
                f"{d2}{cross} Finding: Wide passive port range detected.",
                Out.TEXT,
            )
            self.ptprint(
                f"{d2}{cross} RISK: Excessive port exposure complicates firewall filtering and increases attack surface.",
                Out.TEXT,
            )
            self.ptprint(
                f"{d2}{info_i} Note: Configure 'pasv_min_port' and 'pasv_max_port' to a smaller range (e.g., 100-200 ports).",
                Out.TEXT,
            )
        else:
            self.ptprint(f"{d2}{tick} Status: PASSIVE_RANGE_OK", Out.TEXT)
            self.ptprint(
                f"{d2}{tick} Finding: Server appears to use a restricted passive port range.",
                Out.TEXT,
            )
            self.ptprint(
                f"{d2}{info_i} Note: Observed span ({ppr.observed_span}) is well within the security threshold ({ppr.max_span_threshold}).",
                Out.TEXT,
            )

    def _print_chroot_audit_terminal(self, ch: ChrootAuditResult) -> None:
        """Structured user-isolation report (aggregate CWD stats + highlighted breaches; matches pasv/conn-limits style)."""
        fk = get_colored_text
        d1 = "    "
        d2 = "        "
        star = fk("[*]", color="INFO")
        info_i = fk("[i]", color="INFO")
        tick = fk("[✓]", color="NOTVULN")
        cross = fk("[✗]", color="VULN")

        dd = ch.dotdot
        pwd0n = self._chroot_norm_pwd(ch.pwd_initial)
        home_sibling = bool(
            ch.home_parent_accessible
            and pwd0n.startswith("/home/")
            and pwd0n.rstrip("/") != "/home"
        )

        self.ptprint("User isolation audit", Out.INFO)

        self.ptprint(f"{d1}{star} Path traversal & system access probes", Out.TEXT)
        self.ptprint(f"{d2}{info_i} Login PWD: {ch.pwd_initial!r}", Out.TEXT)

        paths = [r.path for r in ch.cwd_probes]
        n = len(paths)
        preview_n = 5
        paths_preview = ", ".join(paths[:preview_n]) + (", ..." if n > preview_n else "")
        self.ptprint(f"{d2}{info_i} System paths: {n} tested ({paths_preview})", Out.TEXT)

        allowed_rows = [r for r in ch.cwd_probes if r.success]
        n_ok = len(allowed_rows)
        n_rej = n - n_ok
        allowed_q = ", ".join(repr(r.path) for r in allowed_rows) if allowed_rows else "(none)"
        self.ptprint(
            f"{d2}{info_i} Path results: {n_rej}/{n} rejected, {n_ok}/{n} allowed ({allowed_q})",
            Out.TEXT,
        )

        for r in ch.cwd_probes:
            if r.success and r.path in self._CHROOT_STRONG_CWD_PATHS:
                pwd_bit = f" (PWD: {r.pwd_after!r})" if r.pwd_after else ""
                self.ptprint(
                    f"{d2}{cross} Critical path accessible: CWD {r.path!r} succeeded{pwd_bit}",
                    Out.TEXT,
                )
        if home_sibling:
            self.ptprint(
                f"{d2}{cross} Cross-user exposure: CWD '/home' succeeded while login PWD is under '/home/<account>' "
                "(possible sibling home access).",
                Out.TEXT,
            )
        if ch.dotdot_parent_escape_suspected:
            self.ptprint(
                f"{d2}{cross} Directory traversal: '..' chain suggests escape above the post-login directory root.",
                Out.TEXT,
            )
        if ch.passwd_size_ok:
            sz = ch.passwd_size_bytes
            sz_bit = f" ({sz} bytes)" if sz is not None else ""
            self.ptprint(f"{d2}{cross} Sensitive file found: SIZE '/etc/passwd'{sz_bit}", Out.TEXT)
        if ch.shadow_size_ok:
            sz = ch.shadow_size_bytes
            sz_bit = f" ({sz} bytes)" if sz is not None else ""
            self.ptprint(f"{d2}{cross} Sensitive file found: SIZE '/etc/shadow'{sz_bit}", Out.TEXT)

        self.ptprint(
            f"{d2}{info_i} Directory traversal: up to {self._CHROOT_DOTDOT_MAX_STEPS} × '..' attempted "
            f"({dd.steps_ok} successful step(s); final PWD ~ {dd.pwd_final!r}, {dd.stopped_reason})",
            Out.TEXT,
        )

        if ch.isolation_broken_suspected:
            self.ptprint(
                f"{d2}{cross} Result: Isolation breach suspected; host paths visible.",
                Out.TEXT,
            )
        else:
            self.ptprint(
                f"{d2}{tick} Result: No host filesystem breakout detected.",
                Out.TEXT,
            )

        self.ptprint(f"{d1}{star} Audit summary & heuristics", Out.TEXT)
        if ch.isolation_broken_suspected:
            self.ptprint(f"{d2}{cross} Status: CHROOT_BROKEN_SUSPECTED", Out.TEXT)
            self.ptprint(
                f"{d2}{cross} Finding: Insecure configuration; account can access host system paths.",
                Out.TEXT,
            )
            self.ptprint(
                f"{d2}{info_i} Note: {ch.detail}",
                Out.TEXT,
            )
        else:
            self.ptprint(f"{d2}{tick} Status: CHROOT_OK", Out.TEXT)
            self.ptprint(
                f"{d2}{tick} Finding: Account appears properly isolated within a chroot/jail.",
                Out.TEXT,
            )
            self.ptprint(
                f"{d2}{info_i} Note: No obvious host-level path breakout; chroot may still use a synthetic '/'.",
                Out.TEXT,
            )
            self.ptprint(
                f"{d2}{info_i} Note: Heuristic check only — confirm manually in critical environments.",
                Out.TEXT,
            )

    def _user_enum_probe_signature(self, r: FtpUserEnumProbeRow) -> tuple[int | None, str]:
        """Comparable (code, normalized text) for USER/PASS outcome (wordlist vs control probes)."""
        if r.error:
            return (None, "")
        if r.user_reply_code in (331, 332):
            return (r.pass_reply_code, self._norm_ftp_reply_text(r.pass_reply_line or ""))
        return (r.user_reply_code, self._norm_ftp_reply_text(r.user_reply_line or ""))

    @staticmethod
    def _user_enum_format_probe_reply(r: FtpUserEnumProbeRow) -> str:
        if r.error:
            return f"(probe error: {r.error[:100]})"
        if r.user_reply_code in (331, 332):
            c = r.pass_reply_code
            line = (r.pass_reply_line or "").strip()
        else:
            c = r.user_reply_code
            line = (r.user_reply_line or "").strip()
        line = re.sub(r"\s+", " ", line)
        return f"{c} {line}"[:160].strip()

    def _print_user_enum_terminal(self, ue: FtpUserEnumResult) -> None:
        """Structured username enumeration report (aggregate responses + highlighted outliers; RFC 2577)."""
        fk = get_colored_text
        d1 = "    "
        d2 = "        "
        star = fk("[*]", color="INFO")
        info_i = fk("[i]", color="INFO")
        warn_bang = fk("[!]", color="WARNING")
        tick = fk("[✓]", color="NOTVULN")
        cross = fk("[✗]", color="VULN")

        do_timing = bool(getattr(self.args, "user_enum_timing", False))
        keep_alive = bool(getattr(self.args, "user_enum_keep_alive", False))
        threads = max(1, int(getattr(self.args, "user_enum_threads", 1) or 1))
        n_word = sum(1 for p in ue.probes if p.probe_kind == "wordlist")
        n_ctrl = sum(1 for p in ue.probes if p.probe_kind.startswith("control"))
        n_err = sum(1 for p in ue.probes if p.error)

        if keep_alive:
            mode = "keep-alive"
        elif threads > 1:
            mode = f"multi-session ({threads} threads)"
        else:
            mode = "multi-session"

        self.ptprint("Username enumeration audit (-eu / PTL-SVC-FTP-USRENUM)", Out.INFO)

        self.ptprint(f"{d1}{star} Probe configuration & heuristics", Out.TEXT)
        strat = (
            "USER then wrong PASS (timing-aware, RFC 2577)"
            if do_timing
            else "USER then fixed bad PASS (RFC 2577)"
        )
        self.ptprint(f"{d2}{info_i} Strategy: {strat}", Out.TEXT)
        self.ptprint(
            f"{d2}{info_i} Wordlist: {n_word} entries + {n_ctrl} controls | threads: {threads} | mode: {mode}",
            Out.TEXT,
        )
        analysis_bits = "Response codes, fuzzy text matching, sequence behavior"
        if do_timing:
            analysis_bits += ", PASS-phase latency (--user-enum-timing)"
        self.ptprint(f"{d2}{info_i} Analysis: {analysis_bits}", Out.TEXT)
        if n_err:
            self.ptprint(f"{d2}{info_i} Probes with errors: {n_err} (see JSON)", Out.TEXT)

        self.ptprint(f"{d1}{star} Enumeration findings", Out.TEXT)

        wl_ok = [r for r in ue.probes if r.probe_kind == "wordlist" and r.error is None]
        ctr = collections.Counter()
        dominant_sig: tuple[int | None, str] | None = None
        dom_count = 0
        dom_row: FtpUserEnumProbeRow | None = None
        if wl_ok:
            sigs = [self._user_enum_probe_signature(r) for r in wl_ok]
            ctr = collections.Counter(sigs)
            dominant_sig, dom_count = ctr.most_common(1)[0]
            dom_code, _norm_dom = dominant_sig
            n_wl = len(wl_ok)
            if len(ctr) == 1:
                self.ptprint(
                    f"{d2}{info_i} Response consistency: {n_wl}/{n_wl} wordlist probes share code {dom_code} "
                    f"with identical normalized message.",
                    Out.TEXT,
                )
            else:
                n_diff = n_wl - dom_count
                self.ptprint(
                    f"{d2}{info_i} Response consistency: {dom_count}/{n_wl} wordlist probes share the dominant pattern "
                    f"(code {dom_code}); {n_diff} differ.",
                    Out.TEXT,
                )
            dom_row = next((r for r in wl_ok if self._user_enum_probe_signature(r) == dominant_sig), None)
            dominant_phrase = self._user_enum_format_probe_reply(dom_row) if dom_row else "n/a"
            for r in wl_ok:
                if self._user_enum_probe_signature(r) != dominant_sig:
                    self.ptprint(
                        f"{d2}{cross} Differentiation: User {r.username!r} returned "
                        f"{self._user_enum_format_probe_reply(r)!r} instead of {dominant_phrase!r}",
                        Out.TEXT,
                    )
        elif n_word:
            self.ptprint(
                f"{d2}{info_i} Response consistency: no successful wordlist probes (all had errors).",
                Out.TEXT,
            )

        ctrl_ok = [r for r in ue.probes if r.probe_kind.startswith("control") and r.error is None]
        if ctrl_ok and wl_ok and len(ctr) == 1 and dominant_sig is not None and dom_row is not None:
            ctrl_match = sum(1 for r in ctrl_ok if self._user_enum_probe_signature(r) == dominant_sig)
            self.ptprint(
                f"{d2}{info_i} Control probes: {ctrl_match}/{len(ctrl_ok)} matched the wordlist response pattern.",
                Out.TEXT,
            )
            for r in ctrl_ok:
                if self._user_enum_probe_signature(r) != dominant_sig:
                    self.ptprint(
                        f"{d2}{cross} Differentiation: Control user {r.username!r} returned "
                        f"{self._user_enum_format_probe_reply(r)!r} instead of "
                        f"{self._user_enum_format_probe_reply(dom_row)!r}",
                        Out.TEXT,
                    )

        if do_timing:
            if ue.timing_control_median_ms is not None:
                self.ptprint(
                    f"{d2}{info_i} Control baseline: median {ue.timing_control_median_ms:.1f} ms "
                    f"for control usernames (PASS phase, post-warmup cohort where applicable).",
                    Out.TEXT,
                )
                if ue.timing_wordlist_median_ms is not None:
                    self.ptprint(
                        f"{d2}{info_i} Wordlist cohort median: {ue.timing_wordlist_median_ms:.1f} ms.",
                        Out.TEXT,
                    )
            else:
                self.ptprint(
                    f"{d2}{info_i} Timing: insufficient PASS timings for median comparison "
                    f"(need ≥2 wordlist and ≥1 control with 331/332).",
                    Out.TEXT,
                )
            if ue.timing_slow_usernames_ms:
                parts = ", ".join(f"{u!r} ({ms:.1f}ms)" for u, ms in ue.timing_slow_usernames_ms[:12])
                if len(ue.timing_slow_usernames_ms) > 12:
                    parts += ", …"
                self.ptprint(
                    f"{d2}{warn_bang} Timing anomaly (per user vs control threshold): {parts}",
                    Out.TEXT,
                )
            if "timingSuppressedSuspectedTarpitting" in ue.timing_notes:
                self.ptprint(
                    f"{d2}{info_i} Timing: cohort comparison suppressed (possible tarpitting / delay policy in keep-alive run).",
                    Out.TEXT,
                )

        if ue.enumeration_suspected:
            self.ptprint(
                f"{d2}{cross} Result: Response differentiation suggests a username enumeration oracle (RFC 2577).",
                Out.TEXT,
            )
        elif ue.timing_anomaly_suspected:
            self.ptprint(
                f"{d2}{tick} Result: No obvious code/message leakage detected.",
                Out.TEXT,
            )
        else:
            self.ptprint(
                f"{d2}{tick} Result: No differentiation in server responses detected.",
                Out.TEXT,
            )

        self.ptprint(f"{d1}{star} Audit summary & heuristics", Out.TEXT)
        if ue.enumeration_suspected and ue.timing_anomaly_suspected:
            self.ptprint(f"{d2}{cross} Status: USER_ENUM_SUSPECTED", Out.TEXT)
            self.ptprint(
                f"{d2}{cross} Finding: Server responses and/or timing differ in ways that may enable username guessing.",
                Out.TEXT,
            )
        elif ue.enumeration_suspected:
            self.ptprint(f"{d2}{cross} Status: USER_ENUM_SUSPECTED", Out.TEXT)
            self.ptprint(
                f"{d2}{cross} Finding: Server responses appear to differentiate between tested usernames.",
                Out.TEXT,
            )
        elif ue.timing_anomaly_suspected:
            self.ptprint(f"{d2}{warn_bang} Status: USER_ENUM_SUSPECTED (via timing)", Out.TEXT)
            self.ptprint(
                f"{d2}{cross} Finding: Server timing differs significantly for certain usernames.",
                Out.TEXT,
            )
        else:
            self.ptprint(f"{d2}{tick} Status: USER_ENUM_OK", Out.TEXT)
            self.ptprint(
                f"{d2}{tick} Finding: Server responses appear consistent for all tested usernames.",
                Out.TEXT,
            )

        codes_s = ", ".join(str(c) for c in ue.distinct_user_reply_codes) if ue.distinct_user_reply_codes else "n/a"
        if not ue.enumeration_suspected and not ue.timing_anomaly_suspected:
            if wl_ok and len(ctr) == 1 and dominant_sig is not None:
                dc = dominant_sig[0]
                self.ptprint(
                    f"{d2}{info_i} Note: Response codes ({codes_s}) and messages were uniform across "
                    f"{len(wl_ok)} wordlist probes (terminal code {dc}).",
                    Out.TEXT,
                )
            elif wl_ok:
                self.ptprint(
                    f"{d2}{info_i} Note: USER-stage code set: {codes_s}; see differentiation lines and JSON.",
                    Out.TEXT,
                )

        if not do_timing:
            self.ptprint(
                f"{d2}{info_i} Note: Timing analysis was skipped (use --user-enum-timing for latency audit).",
                Out.TEXT,
            )
        elif ue.timing_control_median_ms is not None and ue.timing_slow_usernames_ms:
            slow = ue.timing_slow_usernames_ms[0]
            self.ptprint(
                f"{d2}{info_i} Note: Control median was {ue.timing_control_median_ms:.1f} ms; "
                f"example slow candidate {slow[0]!r} took {slow[1]:.1f} ms.",
                Out.TEXT,
            )
        elif do_timing and ue.timing_control_median_ms is not None and not ue.timing_anomaly_suspected:
            self.ptprint(
                f"{d2}{info_i} Note: PASS-phase medians within expected range for this sample (no timing flag).",
                Out.TEXT,
            )

        if ue.enumeration_suspected or ue.timing_anomaly_suspected:
            self.ptprint(f"{d2}{info_i} Note: {ue.detail}", Out.TEXT)

    # region output

    def output(self) -> None:
        """Formats and outputs module results. Skips streamed sections in text mode; JSON always complete."""
        properties = {
            "software_type": None,
            "name": "ftp",
            "version": None,
            "vendor": None,
            "description": None,
        }
        deferred_vulns = []

        # Connection error: use unified error format (status=error, empty nodes)
        if (info_error := getattr(self.results, "info_error", None)) is not None:
            if self.use_json:
                self.ptjsonlib.end_error(info_error, self.use_json)
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} {info_error}", Out.TEXT)
            properties.update({"infoError": info_error})
            ftp_node = self.ptjsonlib.create_node_object("software", None, None, properties)
            self.ptjsonlib.add_node(ftp_node)
            node_key = ftp_node["key"]
            for v in deferred_vulns:
                self.ptjsonlib.add_vulnerability(node_key=node_key, **v)
            self.ptjsonlib.set_status("finished", "")
            self.ptprint(self.ptjsonlib.get_result_json(), json=True)
            return

        # Banner (skip terminal if streamed; always add to properties for JSON)
        if (info := self.results.info) and info.banner is not None:
            sid = identify_service(info.banner)
            vendor = vendor_from_cpe(sid.cpe) if sid else None
            version = sid.version if sid else None
            properties.update(
                {
                    "description": f"Banner: {info.banner}",
                    "version": version,
                    "vendor": vendor,
                }
            )
            if sid is not None:
                if sid.version is not None:
                    deferred_vulns.append({"vuln_code": "PTV-SVC-BANNER"})
                properties.update({"cpe": sid.cpe})
            if not self.use_json and not self._streamed_banner:
                self.ptprint("Banner", Out.INFO)
                if sid is None:
                    icon = get_colored_text("[✓]", color="NOTVULN")
                elif sid.version is not None:
                    icon = get_colored_text("[✗]", color="VULN")
                else:
                    icon = get_colored_text("[!]", color="WARNING")
                self.ptprint(f"    {icon} {info.banner}", Out.TEXT)
                if sid is not None:
                    self.ptprint("Service Identification", Out.INFO)
                    self.ptprint(f"    Product:  {sid.product}", Out.TEXT)
                    self.ptprint(
                        f"    Version:  {sid.version if sid.version else 'unknown'}",
                        Out.TEXT,
                    )
                    self.ptprint(f"    CPE:      {sid.cpe}", Out.TEXT)

        # HELP, SYST and STAT commands (separate section)
        if self.results.commands_requested:
            if (info := self.results.info) and (info.help_response is not None or info.syst is not None or info.stat is not None):
                if info.help_response is not None:
                    self.ptprint("HELP command", Out.INFO)
                    for line in info.help_response.splitlines():
                        self.ptprint(f"    {line}", Out.TEXT)
                    properties.update({"helpCommand": info.help_response})
                if info.syst is not None:
                    self.ptprint("SYST command", Out.INFO)
                    self.ptprint(f"    {info.syst}")
                    properties.update({"systCommand": info.syst})
                if info.stat is not None:
                    self.ptprint("STAT command", Out.INFO)
                    self.ptprint(f"    {info.stat}")
                    properties.update({"statCommand": info.stat})

        # Encryption (skip terminal if streamed; always add to properties for JSON)
        if (encryption_error := self.results.encryption_error) is not None:
            properties.update({"encryptionError": encryption_error})
            if not self.use_json and not self._streamed_encryption:
                self.ptprint("Encryption", Out.INFO)
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} Encryption test failed: {encryption_error}", Out.TEXT)
        elif (enc := self.results.encryption) is not None:
            properties.update(
                {
                    "encryption": {
                        "plaintext": enc.plaintext_ok,
                        "authTls": enc.auth_tls_ok,
                        "tls": enc.tls_ok,
                    }
                }
            )
            if not self.use_json and not self._streamed_encryption:
                self.ptprint("Encryption", Out.INFO)
                plaintext_only = enc.plaintext_ok and not enc.auth_tls_ok and not enc.tls_ok
                any_ok = enc.plaintext_ok or enc.auth_tls_ok or enc.tls_ok
                if plaintext_only:
                    icon = get_colored_text("[✗]", color="VULN")
                    self.ptprint(f"    {icon} Plaintext only", Out.TEXT)
                elif any_ok:
                    if enc.plaintext_ok:
                        icon = (
                            get_colored_text("[!]", color="WARNING")
                            if (enc.auth_tls_ok or enc.tls_ok)
                            else get_colored_text("[✓]", color="NOTVULN")
                        )
                        self.ptprint(f"    {icon} Plaintext", Out.TEXT)
                    if enc.auth_tls_ok:
                        icon = get_colored_text("[✓]", color="NOTVULN")
                        self.ptprint(f"    {icon} AUTH TLS", Out.TEXT)
                    if enc.tls_ok:
                        icon = get_colored_text("[✓]", color="NOTVULN")
                        self.ptprint(f"    {icon} Implicit TLS", Out.TEXT)
                else:
                    icon = get_colored_text("[✗]", color="VULN")
                    self.ptprint(
                        f"    {icon} No connection mode available (plaintext, AUTH TLS, implicit TLS failed)",
                        Out.TEXT,
                    )

        # Anonymous authentication and access permissions (skip terminal if streamed)
        if (anonymous_error := self.results.anonymous_error) is not None:
            properties.update({"anonymousError": anonymous_error})
            if not self.use_json and not self._streamed_anonymous:
                self.ptprint("Authentication", Out.INFO)
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} Anonymous test failed: {anonymous_error}", Out.TEXT)
        elif (access_error := self.results.access_error) is not None:
            properties.update({"accessError": access_error})
            if not self.use_json and not self._streamed_anonymous:
                self.ptprint("Authentication", Out.INFO)
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} Anonymous authentication is enabled", Out.TEXT)
                self.ptprint(f"    {icon} Access check failed: {access_error}", Out.TEXT)
        elif (anon := self.results.anonymous) is not None:
            if not self.use_json and not self._streamed_anonymous:
                self.ptprint("Authentication", Out.INFO)
                if anon:
                    icon = get_colored_text("[✗]", color="VULN")
                    self.ptprint(f"    {icon} Anonymous authentication is enabled", Out.TEXT)
                else:
                    icon = get_colored_text("[✓]", color="NOTVULN")
                    self.ptprint(f"    {icon} Anonymous authentication is disabled", Out.TEXT)
            if anon:
                response_str = ""
                if (access := self.results.access) is not None:
                    if access.errors is None and access.results is not None:
                        try:
                            anon_p = next(p for p in access.results if p.creds.user == "anonymous")
                            response_str = (
                                f"(Directory listing: {anon_p.dirlist is not None}, "
                                + f"Write: {anon_p.write}, "
                                + f"Read: {anon_p.read}, "
                                + f"Delete: {anon_p.delete})"
                            )
                            if not self.use_json and not self._streamed_anonymous:
                                self.ptprint(f"    {response_str}", Out.TEXT)
                        except StopIteration:
                            pass
                    else:
                        response_str = "Encountered errors during access enumeration:"
                        if not self.use_json and not self._streamed_anonymous:
                            self.ptprint(f"    {response_str}", Out.ERROR)
                            for e in access.errors or []:
                                self.ptprint(f"        {e}", Out.ERROR)
                        if access.errors:
                            response_str += "\n" + "\n".join(access.errors)

                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.Anonymous.value,
                        "vuln_request": "anonymous login",
                        "vuln_response": response_str,
                    }
                )

        # --access without working anonymous: access_check still ran but UI above skipped (anonymous unset or False)
        if (
            self.args.access
            and (access := self.results.access) is not None
            and access.errors
            and self.results.anonymous is not True
        ):
            properties.update({"accessCheckErrors": list(access.errors)})
            if not self.use_json:
                self.ptprint("Access check", Out.INFO)
                warn = get_colored_text("[!]", color="WARNING")
                for e in access.errors:
                    self.ptprint(f"    {warn} {e}", Out.TEXT)
                self.ptprint(
                    f"    {warn} Use --anonymous (-A), or -u USER -p PASS, or wordlists (-U/-P).",
                    Out.TEXT,
                )

        # Bruteforced credentials and their access permissions (skip terminal if streamed)
        if (creds := self.results.creds) is not None:
            if not self.use_json and not self._streamed_brute and len(creds) > 0:
                login_label = (
                    "FTP login (known account)"
                    if self._ftp_is_single_known_login() and len(creds) == 1
                    else "Login bruteforce"
                )
                self.ptprint(f"{login_label}: {len(creds)} valid credentials", Out.INFO)

            if len(creds) > 0:
                json_lines: list[str] = []
                for cred in creds:
                    cred_str = f"user: {cred.user}, password: {cred.passw}"

                    if (access := self.results.access) is not None:
                        if access.errors is None and access.results is not None:
                            try:
                                cred_p = next(p for p in access.results if p.creds == cred)
                                perm_str = (
                                    f" (Directory listing: {cred_p.dirlist is not None}, "
                                    + f"Write: {cred_p.write}, "
                                    + f"Read: {cred_p.read}, "
                                    + f"Delete: {cred_p.delete})"
                                )
                            except StopIteration:
                                perm_str = ""
                        else:
                            perm_str = " Encountered errors during access enumeration:"
                            if not self.use_json and not self._streamed_brute:
                                self.ptprint(f"    {perm_str}", Out.ERROR)
                            for e in access.errors or []:
                                if not self.use_json and not self._streamed_brute:
                                    self.ptprint(f"        {e}", Out.ERROR)
                                perm_str += f"\n{e}"
                    else:
                        perm_str = ""

                    if not self.use_json and not self._streamed_brute:
                        self.ptprint(f"    {cred_str + perm_str}", Out.TEXT)
                    json_lines.append(cred_str + perm_str)

                if self.args.user is not None:
                    user_str = f"username: {self.args.user}"
                else:
                    user_str = f"usernames: {self.args.users}"

                if self.args.password is not None:
                    passw_str = f"password: {self.args.password}"
                else:
                    passw_str = f"passwords: {self.args.passwords}"

                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.WeakCreds.value,
                        "vuln_request": f"{user_str}\n{passw_str}",
                        "vuln_response": "\n".join(json_lines),
                    }
                )

        # Directory listing
        if (
            self.args.access_list
            and (access := self.results.access) is not None
            and access.results is not None
        ):
            try:
                p = next(p for p in access.results if p.dirlist is not None and len(p.dirlist) > 0)
                self.ptprint("Directory listing", Out.INFO)

                out_str = "\n".join(p.dirlist)
                self.ptprint(f"    {out_str}")
                properties.update({"directoryListing": out_str})
            except StopIteration:
                self.ptprint("Directory listing failed (no access or empty listing)", Out.INFO)
                properties.update({"directoryListing": "no access or empty"})

        # Path enumeration (dictionary attack results)
        if path_enum_error := getattr(self.results, "path_enum_error", None):
            properties.update({"pathEnumError": path_enum_error})
            if not self.use_json:
                self.ptprint("Path enumeration", Out.INFO)
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} {path_enum_error}", Out.TEXT)
        elif (path_list := getattr(self.results, "path_enum", None)) is not None:
            path_enum_json = [
                {
                    "path": p.path,
                    "exists": p.exists,
                    "isDirectory": p.is_directory,
                    "size": p.size,
                }
                for p in path_list
            ]
            properties.update({"pathEnum": path_enum_json})
            if not self.use_json and len(path_list) > 0:
                self.ptprint("Path enumeration", Out.INFO)
                self.ptprint(f"    Found {len(path_list)} path(s)", Out.TEXT)
                for p in path_list:
                    kind = "dir" if p.is_directory else "file"
                    size_str = f" ({p.size} B)" if p.size is not None else ""
                    self.ptprint(f"    [{kind}] {p.path}{size_str}", Out.TEXT)

        # Data mode (passive/active)
        if modes_error := getattr(self.results, "modes_error", None):
            properties.update({"dataModesError": modes_error})
            if not self.use_json:
                self.ptprint("Data mode", Out.INFO)
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} {modes_error}", Out.TEXT)
        elif (modes := getattr(self.results, "modes", None)) is not None:
            modes_json: dict = {"passive": modes.passive_ok, "active": modes.active_ok}
            if modes.pasv_ip_leak:
                modes_json["pasvIpLeak"] = modes.pasv_ip_leak
            properties.update({"dataModes": modes_json})
            if not self.use_json:
                self.ptprint("Data mode", Out.INFO)
                icon_p = get_colored_text("[✓]", color="NOTVULN") if modes.passive_ok else get_colored_text("[✗]", color="VULN")
                icon_a = get_colored_text("[✓]", color="NOTVULN") if modes.active_ok else get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon_p} Passive: {'available' if modes.passive_ok else 'not available'}", Out.TEXT)
                self.ptprint(f"    {icon_a} Active: {'available' if modes.active_ok else 'not available'}", Out.TEXT)
                if not modes.active_ok:
                    warn_icon = get_colored_text("[!]", color="WARNING")
                    self.ptprint(
                        f"    {warn_icon} If active failed: tester may be behind NAT/firewall, not necessarily server error. "
                        "For 100% objective result, tester needs public IP and no local firewall.",
                        Out.TEXT,
                    )
                if modes.pasv_ip_leak:
                    icon = get_colored_text("[✗]", color="VULN")
                    self.ptprint(f"    {icon} PASV Internal IP Leak: server advertised {modes.pasv_ip_leak}", Out.TEXT)

        # Passive data port spread (PTL-SVC-FTP-PASIVE)
        if ppr_err := getattr(self.results, "pasv_port_range_error", None):
            properties.update({"ftpPasvPortRangeError": ppr_err})
            if not self.use_json:
                self.ptprint("Passive port range audit", Out.INFO)
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} {ppr_err}", Out.TEXT)
        elif (ppr := getattr(self.results, "pasv_port_range", None)) is not None:
            ppr_json = {
                "sampleCount": len(ppr.probes),
                "successfulSamples": len(ppr.successful_ports),
                "dataPorts": list(ppr.successful_ports),
                "minPort": ppr.min_port,
                "maxPort": ppr.max_port,
                "observedSpan": ppr.observed_span,
                "maxSpanThreshold": ppr.max_span_threshold,
                "minSamplesForVerdict": ppr.min_samples_for_verdict,
                "widePassiveRange": ppr.wide_passive_range,
                "inconclusive": ppr.inconclusive,
                "detail": ppr.detail,
                "probes": [
                    {
                        "sampleIndex": pr.sample_index,
                        "dataPort": pr.data_port,
                        "error": pr.error,
                    }
                    for pr in ppr.probes
                ],
            }
            properties.update({"ftpPasvPortRange": ppr_json})
            if not self.use_json:
                self._print_pasv_port_range_terminal(ppr)
            if ppr.wide_passive_range and not ppr.inconclusive:
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.FtpPassivePortRange.value,
                        "vuln_request": "Repeated PASV + LIST (--pasv-port-audit / -R)",
                        "vuln_response": ppr.detail,
                    }
                )

        # Connection limits audit (PTL-SVC-FTP-CONN)
        if cl_err := getattr(self.results, "conn_limits_error", None):
            properties.update({"ftpConnLimitsError": cl_err})
            if not self.use_json:
                self.ptprint("Connection limits audit", Out.INFO)
                ii = get_colored_text("[i]", color="INFO")
                self.ptprint(f"    {ii} Audit failed: {cl_err}", Out.TEXT)
        elif (cl := getattr(self.results, "conn_limits", None)) is not None:
            pp = cl.pasv_pre_auth
            po = cl.pasv_post_auth
            cl_json: dict = {
                "cryptoMode": cl.crypto_mode,
                "parallel": {
                    "attempted": cl.parallel.attempted,
                    "succeeded": cl.parallel.succeeded,
                    "failed": cl.parallel.failed,
                    "errorSamples": list(cl.parallel.error_samples),
                },
                "sequential": {
                    "attempts": cl.sequential.attempts,
                    "succeeded": cl.sequential.succeeded,
                    "failed": cl.sequential.failed,
                    "interConnectDelayMs": cl.sequential.inter_connect_delay_ms,
                    "errorSamples": list(cl.sequential.error_samples),
                },
                "pasvPreAuth": {
                    "attempts": pp.attempts,
                    "reply227": pp.reply227,
                    "reply530": pp.reply530,
                    "replyOther": pp.reply_other,
                    "lastReplySnippet": pp.last_reply_snippet,
                    "error": pp.error,
                },
                "pasvPostAuth": None
                if po is None
                else {
                    "attempts": po.attempts,
                    "reply227": po.reply227,
                    "reply530": po.reply530,
                    "replyOther": po.reply_other,
                    "lastReplySnippet": po.last_reply_snippet,
                    "error": po.error,
                },
                "idlePreAuth": {
                    "performed": cl.idle_pre_auth.performed,
                    "waitSeconds": cl.idle_pre_auth.wait_seconds,
                    "kickObserved": cl.idle_pre_auth.kick_observed,
                    "note": cl.idle_pre_auth.note,
                },
                "slowAuth": {
                    "performed": cl.slow_auth.performed,
                    "gapSeconds": cl.slow_auth.gap_seconds,
                    "stillConnectedAfterPass": cl.slow_auth.still_connected_after_pass,
                    "passReplySnippet": cl.slow_auth.pass_reply_snippet,
                    "note": cl.slow_auth.note,
                },
                "idlePostAuth": None
                if cl.idle_post_auth is None
                else {
                    "performed": cl.idle_post_auth.performed,
                    "waitSeconds": cl.idle_post_auth.wait_seconds,
                    "kickObserved": cl.idle_post_auth.kick_observed,
                    "note": cl.idle_post_auth.note,
                },
                "limitsInsufficientSuspected": cl.limits_insufficient_suspected,
                "riskFactors": list(cl.risk_factors),
                "detail": cl.detail,
            }
            properties.update({"ftpConnLimitsAudit": cl_json})
            if not self.use_json:
                self._print_conn_limits_audit_terminal(cl)
            if cl.limits_insufficient_suspected:
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.FtpConnectionLimits.value,
                        "vuln_request": "Connection / rate / idle / PASV probes (--conn-limits-audit / -L)",
                        "vuln_response": "; ".join(cl.risk_factors) if cl.risk_factors else cl.detail,
                    }
                )

        # Chroot / user isolation audit (PTL-SVC-FTP-CHROOT)
        if ch_err := getattr(self.results, "chroot_audit_error", None):
            properties.update({"ftpChrootAuditError": ch_err})
            if not self.use_json:
                self.ptprint("User isolation audit", Out.INFO)
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} {ch_err}", Out.TEXT)
        elif (ch := getattr(self.results, "chroot_audit", None)) is not None:
            dd = ch.dotdot
            ch_json = {
                "pwdInitial": ch.pwd_initial,
                "cwdProbes": [
                    {
                        "probeId": r.probe_id,
                        "path": r.path,
                        "success": r.success,
                        "pwdAfter": r.pwd_after,
                        "errorOrReply": r.error_or_reply,
                    }
                    for r in ch.cwd_probes
                ],
                "dotdot": {
                    "stepsOk": dd.steps_ok,
                    "pwdInitial": dd.pwd_initial,
                    "pwdFinal": dd.pwd_final,
                    "stoppedReason": dd.stopped_reason,
                },
                "homeParentAccessible": ch.home_parent_accessible,
                "systemPathsAccessible": list(ch.system_paths_accessible),
                "passwdSizeOk": ch.passwd_size_ok,
                "shadowSizeOk": ch.shadow_size_ok,
                "dotdotParentEscapeSuspected": ch.dotdot_parent_escape_suspected,
                "isolationBrokenSuspected": ch.isolation_broken_suspected,
                "detail": ch.detail,
                "passwdSizeBytes": ch.passwd_size_bytes,
                "shadowSizeBytes": ch.shadow_size_bytes,
            }
            properties.update({"ftpChrootAudit": ch_json})
            if not self.use_json:
                self._print_chroot_audit_terminal(ch)
            if ch.isolation_broken_suspected:
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.FtpChrootIsolation.value,
                        "vuln_request": "CWD / .. / SIZE probes (--chroot-audit / -J)",
                        "vuln_response": ch.detail,
                    }
                )

        # Active mode policy audit (PTL-SVC-FTP-ACTIVE)
        if active_audit_error := getattr(self.results, "active_audit_error", None):
            properties.update({"activeAuditError": active_audit_error})
            if not self.use_json:
                self.ptprint("Active mode policy", Out.INFO)
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} {active_audit_error}", Out.TEXT)
        elif (aa := getattr(self.results, "active_audit", None)) is not None:
            doc_net_ip = "192.0.2.1"
            steps_json = [
                {
                    "phase": s.phase,
                    "name": s.name,
                    "command": s.command,
                    "reply": s.reply,
                    "code": s.code,
                    "note": s.note,
                    "interpretation": s.interpretation,
                    "listReply": s.list_reply,
                    "listCode": s.list_code,
                }
                for s in aa.steps
            ]
            audit_props: dict = {
                "steps": steps_json,
                "postAuthComplete": aa.post_auth_ran,
                "foreignIpPortAccepted": aa.foreign_ip_accepted,
                "lowPortAccepted": aa.low_port_accepted,
                "listActiveOk": aa.list_after_own_port_ok,
                "fullAudit": aa.full_audit,
            }
            if aa.low_ports_accepted:
                audit_props["lowPortsAccepted"] = list(aa.low_ports_accepted)
            properties.update({"activeAudit": audit_props})
            if not self.use_json:
                self._print_active_audit_terminal(aa)

            if aa.foreign_ip_accepted or aa.low_port_accepted:
                parts = []
                if aa.foreign_ip_accepted:
                    parts.append(
                        f"Server returned 200 for PORT to documentation address {doc_net_ip} (FTP bounce / third-party data connection risk per RFC 2577)."
                    )
                if aa.low_port_accepted:
                    lp = ", ".join(str(p) for p in aa.low_ports_accepted) if aa.low_ports_accepted else ""
                    parts.append(
                        "Server returned 200 for PORT with data port < 1000"
                        + (f" (ports: {lp})" if lp else "")
                        + " (RFC 2577 recommends rejecting < 1024, often 504)."
                    )
                req = "PASV/PORT policy audit (--active-audit-full)" if aa.full_audit else "PASV/PORT policy audit (-M / --active-audit)"
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.FtpActivePolicy.value,
                        "vuln_request": req,
                        "vuln_response": " ".join(parts),
                    }
                )

        # Command surface audit (PTL-SVC-FTP-CMD)
        if cmd_audit_error := getattr(self.results, "cmd_audit_error", None):
            properties.update({"ftpCommandAuditError": cmd_audit_error})
            if not self.use_json:
                self.ptprint("Command surface audit", Out.INFO)
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} {cmd_audit_error}", Out.TEXT)
        elif (ca := getattr(self.results, "cmd_audit", None)) is not None:
            audit_json = {
                "helpPreAuth": ca.help_pre_auth,
                "featResponse": ca.feat_response,
                "siteHelpPreAuth": ca.site_help_pre,
                "siteHelpAllPreAuth": ca.site_help_all_pre,
                "siteHelpPostAuth": ca.site_help_post,
                "siteHelpAllPostAuth": ca.site_help_all_post,
                "siteHelpAllPreAuthError": ca.site_help_all_pre_error,
                "siteHelpAllPostAuthError": ca.site_help_all_post_error,
                "featFeatures": list(ca.feat_features),
                "matchedRisks": [
                    {"tier": r.tier, "token": r.token, "source": r.source} for r in ca.matched_risks
                ],
                "responseTruncated": ca.response_truncated,
            }
            properties.update({"ftpCommandAudit": audit_json})
            if not self.use_json:
                self._print_cmd_audit_terminal(ca)
            vuln_risks = [r for r in ca.matched_risks if r.tier in ("critical", "high")]
            if vuln_risks:
                parts = [f"{r.tier}: {r.token} ({r.source})" for r in vuln_risks]
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.FtpCmdSurface.value,
                        "vuln_request": "HELP/FEAT/SITE HELP (cmd audit -C)",
                        "vuln_response": (
                            "Server advertises risky capabilities: "
                            + "; ".join(parts)
                            + ". Listing in HELP/SITE does not prove unprivileged execution; use --cmd-audit-active for safe SITE probes after login."
                        ),
                    }
                )

        # Active SITE probes (--cmd-audit-active)
        if cmd_audit_active_error := getattr(self.results, "cmd_audit_active_error", None):
            properties.update({"ftpCommandAuditActiveError": cmd_audit_active_error})
            if not self.use_json:
                self.ptprint("Command surface audit (active SITE probes)", Out.INFO)
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} {cmd_audit_active_error}", Out.TEXT)
        elif (caa := getattr(self.results, "cmd_audit_active", None)) is not None:
            active_json = {
                "probeTimeoutSeconds": caa.probe_timeout_seconds,
                "probeFile": caa.probe_file,
                "cleanupOk": caa.cleanup_ok,
                "cleanupError": caa.cleanup_error,
                "setupError": caa.setup_error,
                "probes": [
                    {
                        "probeId": p.probe_id,
                        "commandSent": p.command_sent,
                        "replyCode": p.reply_code,
                        "replyLine": p.reply_line,
                        "classification": p.classification,
                        "advertisedInPassiveAudit": p.advertised_in_passive_audit,
                        "error": p.error,
                    }
                    for p in caa.probes
                ],
            }
            properties.update({"ftpCommandAuditActive": active_json})
            if not self.use_json:
                self.ptprint("Command surface audit (active SITE probes)", Out.INFO)
                if caa.setup_error:
                    self.ptprint(f"    [✗] Setup failed: {caa.setup_error}", Out.TEXT)
                else:
                    if caa.probe_file:
                        self.ptprint(f"    Probe file (cleaned up): {caa.probe_file}", Out.TEXT)
                    ok_icon = get_colored_text("[✓]", color="NOTVULN")
                    bad_icon = get_colored_text("[!]", color="WARNING")
                    self.ptprint(
                        f"    {ok_icon if caa.cleanup_ok else bad_icon} Cleanup (DELE): "
                        + ("ok" if caa.cleanup_ok else (caa.cleanup_error or "failed")),
                        Out.TEXT,
                    )
                    for p in caa.probes:
                        code_s = str(p.reply_code) if p.reply_code is not None else "—"
                        self.ptprint(
                            f"    [{p.probe_id}] {p.command_sent!r} → {code_s} | {p.classification}"
                            + (f" | passive_advertised={p.advertised_in_passive_audit}" if p.advertised_in_passive_audit else ""),
                            Out.TEXT,
                        )
                        if p.reply_line and p.error is None:
                            self.ptprint(f"        {p.reply_line[:200]}{'…' if len(p.reply_line) > 200 else ''}", Out.TEXT)
                        if p.error:
                            self.ptprint(f"        error: {p.error}", Out.TEXT)

        # Invalid / non-standard command audit (PTL-SVC-FTP-INVCOMM)
        if inv_err := getattr(self.results, "invalid_cmd_audit_error", None):
            properties.update({"ftpInvalidCommandAuditError": inv_err})
            if not self.use_json:
                self.ptprint("Invalid command resilience (raw socket)", Out.INFO)
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} {inv_err}", Out.TEXT)
        elif (inv := getattr(self.results, "invalid_cmd_audit", None)) is not None:
            def _inv_session_to_json(sess: InvalidCmdSessionResult | None) -> dict | None:
                if sess is None:
                    return None
                return {
                    "phase": sess.phase,
                    "resilienceRating": sess.resilience_rating,
                    "nullByteTruncationSuspected": sess.null_byte_truncation_suspected,
                    "hadConnectionDrop": sess.had_connection_drop,
                    "probes": [
                        {
                            "probeId": p.probe_id,
                            "intentLabel": p.intent_label,
                            "bytesLineHex": p.bytes_line_hex,
                            "lineSentPreview": p.line_sent_preview,
                            "replyCode": p.reply_code,
                            "replyText": p.reply_text,
                            "classification": p.classification,
                            "connectionOkAfter": p.connection_ok_after,
                            "error": p.error,
                            "followUpCommand": p.follow_up_command,
                            "followUpReplyCode": p.follow_up_reply_code,
                            "followUpReplySnippet": p.follow_up_reply_snippet,
                            "nullByteOutcome": p.null_byte_outcome,
                        }
                        for p in sess.probes
                    ],
                }

            def _inv_null_byte_critical(inv_a: InvalidCmdAuditResult) -> bool:
                for s in (inv_a.pre_auth, inv_a.post_auth):
                    if s is None:
                        continue
                    for p in s.probes:
                        if p.null_byte_outcome and "critical_suspected" in p.null_byte_outcome:
                            return True
                return False

            inv_json = {
                "probeTimeoutSeconds": inv.probe_timeout_seconds,
                "overallResilienceRating": inv.overall_resilience_rating,
                "nullByteTruncationSuspected": inv.null_byte_truncation_suspected,
                "nullByteCriticalContextSuspected": _inv_null_byte_critical(inv),
                "setupError": inv.setup_error,
                "postAuthLoginError": inv.post_auth_login_error,
                "tlsHandshakeHint": inv.tls_handshake_hint,
                "obsoleteTlsSuspected": inv.obsolete_tls_suspected,
                "preAuth": _inv_session_to_json(inv.pre_auth),
                "postAuth": _inv_session_to_json(inv.post_auth),
            }
            properties.update({"ftpInvalidCommandAudit": inv_json})
            if not self.use_json:
                self._print_invalid_cmd_audit_terminal(inv)
            if inv.overall_resilience_rating == "Vulnerable":
                vuln_extra = ""
                if _inv_null_byte_critical(inv):
                    vuln_extra = (
                        " Null-byte USER returned 230 and PWD suggests root/high-privilege context — "
                        "treat as possible auth-bypass / truncation; verify manually."
                    )
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.FtpInvalidCommandHandling.value,
                        "vuln_request": "Invalid / malformed FTP control lines (-iv / --invalid-cmd-audit)",
                        "vuln_response": (
                            "overallResilienceRating=Vulnerable: unexpected 2xx on garbage command, "
                            "null-byte USER may have logged in (230), or service did not recover after probe."
                            + vuln_extra
                            + " See ftpInvalidCommandAudit in JSON (intentLabel, nullByteOutcome)."
                        ),
                    }
                )
            if inv.obsolete_tls_suspected:
                hint = inv.tls_handshake_hint or ""
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.FtpObsoleteTls.value,
                        "vuln_request": "Invalid-command audit (-iv) TLS handshake (implicit or AUTH TLS)",
                        "vuln_response": (
                            "Critical (protocol hygiene): Python SSL (create_default_context) refused to complete "
                            "handshake — typical when the server offers only TLS 1.0/1.1 or otherwise incompatible "
                            "legacy TLS. INVCOMM over encrypted channel could not run; treat as obsolete "
                            "infrastructure / protocol downgrade risk. "
                            + (hint if hint else "See ftpInvalidCommandAudit.setupError and tlsHandshakeHint in JSON.")
                        ),
                    }
                )

        # Username enumeration (PTL-SVC-FTP-USRENUM)
        if ue_err := getattr(self.results, "user_enum_error", None):
            properties.update({"ftpUserEnumerationError": ue_err})
            if not self.use_json:
                self.ptprint("Username enumeration audit (-eu / PTL-SVC-FTP-USRENUM)", Out.INFO)
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} {ue_err}", Out.TEXT)
        elif (ue := getattr(self.results, "user_enum", None)) is not None:
            ue_json = {
                "fixedPasswordMarker": ue.fixed_password_marker,
                "wordlistMaxApplied": int(getattr(self.args, "user_enum_max", 0) or 0),
                "distinctUserReplyCodes": list(ue.distinct_user_reply_codes),
                "distinctPassReplyNorms": list(ue.distinct_pass_reply_norms),
                "enumerationSuspected": ue.enumeration_suspected,
                "timingAnomalySuspected": ue.timing_anomaly_suspected,
                "timingNotes": list(ue.timing_notes),
                "timingControlMedianMs": ue.timing_control_median_ms,
                "timingWordlistMedianMs": ue.timing_wordlist_median_ms,
                "timingSlowUsernamesMs": [{"username": u, "passElapsedMs": ms} for u, ms in ue.timing_slow_usernames_ms],
                "passTextSimilarityMin": ue.pass_text_similarity_min,
                "detail": ue.detail,
                "probes": [
                    {
                        "probeIndex": p.probe_index,
                        "username": p.username,
                        "probeKind": p.probe_kind,
                        "userReplyCode": p.user_reply_code,
                        "userReplyLine": p.user_reply_line,
                        "passReplyCode": p.pass_reply_code,
                        "passReplyLine": p.pass_reply_line,
                        "passElapsedMs": p.pass_elapsed_ms,
                        "connectionOkAfter": p.connection_ok_after,
                        "error": p.error,
                    }
                    for p in ue.probes
                ],
            }
            properties.update({"ftpUserEnumeration": ue_json})
            if not self.use_json:
                self._print_user_enum_terminal(ue)
            if ue.enumeration_suspected or ue.timing_anomaly_suspected:
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.FtpUserEnumeration.value,
                        "vuln_request": "USER/PASS with fixed wrong password (-eu / --user-enum)",
                        "vuln_response": (
                            ue.detail
                            + " See ftpUserEnumeration in JSON (per-probe codes, lines, passElapsedMs, connectionOkAfter)."
                        ),
                    }
                )

        # Bounce attack
        if bounce := self.results.bounce:
            if (creds := bounce.used_creds) is None:
                self.ptprint(f"Bounce attack failed (no valid credentials)", Out.INFO)
                properties.update({"bounceStatus": "no valid credentials"})
            else:
                self.ptprint("Bounce attack", Out.INFO)
                self.ptprint(f"    Creds used: {creds.user}:{creds.passw}", Out.INFO)

                if bounce.bounce_accepted:
                    icon = get_colored_text("[✗]", color="VULN")
                    self.ptprint(f"    {icon} Bounce is allowed", Out.TEXT)
                else:
                    icon = get_colored_text("[✓]", color="NOTVULN")
                    self.ptprint(f"    {icon} Bounce is denied", Out.TEXT)

                if not bounce.bounce_accepted:
                    properties.update({"bounceStatus": "rejected"})
                else:
                    properties.update({"bounceStatus": "ok"})

                    if (r := bounce.request) is None:
                        out_str = f"Target port reachable: {bounce.port_accessible}"
                        self.ptprint(f"        {out_str}", Out.INFO)
                        deferred_vulns.append(
                            {
                                "vuln_code": VULNS.Bounce.value,
                                "vuln_request": f"Bounce port scan target: {bounce.target.ip}:{bounce.target.port}\nCreds used: {creds.user}:{creds.passw}",
                                "vuln_response": out_str,
                            }
                        )
                    else:
                        res = f"Yes ({r.ftpserver_filepath})" if r.stored else "No"
                        stored_str = "Stored on FTP server: " + res
                        self.ptprint(f"        {stored_str}", Out.INFO)

                        res = "Yes" if r.uploaded else "No"
                        sent_str = "Sent to bounce target: " + res
                        self.ptprint(f"        {sent_str}", Out.INFO)

                        res = "Yes" if r.cleaned else "No"
                        clean_str = "Cleaned up: " + res
                        self.ptprint(f"        {clean_str}", Out.INFO)

                        deferred_vulns.append(
                            {
                                "vuln_code": VULNS.Bounce.value,
                                "vuln_request": f"Bounce request target: {bounce.target.ip}:{bounce.target.port}\nCreds used: {creds.user}:{creds.passw}\nRequest file: {self.args.bounce_file}",
                                "vuln_response": "\n".join([stored_str, sent_str, clean_str]),
                            }
                        )

        # Create node at the end with all collected properties and bind vulnerabilities
        ftp_node = self.ptjsonlib.create_node_object(
            "software",
            None,
            None,
            properties,
        )
        self.ptjsonlib.add_node(ftp_node)
        node_key = ftp_node["key"]
        for v in deferred_vulns:
            self.ptjsonlib.add_vulnerability(node_key=node_key, **v)

        self.ptjsonlib.set_status("finished", "")
        self.ptprint(self.ptjsonlib.get_result_json(), json=True)


# endregion
