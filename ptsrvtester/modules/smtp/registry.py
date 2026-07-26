import argparse


try:
    from ntlm_auth.ntlm import NtlmContext
except ImportError:
    NtlmContext = None

from ..utils.helpers import ArgsWithBruteforce, check_if_brute

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False


from .helpers import *
from .results import *

__all__ = ['_smtp_users_file_supplies_name_list', '_rcpt_limit_active', '_rcpt_limit_send_mode', '_rcpt_limit_max_attempts', '_normalize_smtp_role', '_TS_COMMON_MSG', 'SMTP_TEST_GROUPS', 'SMTP_TESTS', 'SMTP_SEND_REQUIRED', 'SMTP_TEST_DESTS', 'SMTP_VALUE_DESTS', '_smtp_parse_test_codes', '_apply_smtp_tests', '_smtp_test_help']


# region arguments


def _smtp_users_file_supplies_name_list(args: ArgsWithBruteforce) -> bool:
    """True when -U/--users should populate the in-memory name list (not bruteforce-credentials only)."""
    if not getattr(args, "users", None):
        return False
    if getattr(args, "enumerate", None) is not None:
        return True
    if getattr(args, "auth_enum", False):
        return True
    if _rcpt_limit_active(args):
        return True
    return False


def _rcpt_limit_active(args) -> bool:
    """True when ``-rl`` / RCPTLIM is active."""
    return getattr(args, "rcpt_limit", None) is not None


def _rcpt_limit_send_mode(args) -> bool:
    """True when RCPTLIM should submit DATA after the RCPT storm (global ``--send``)."""
    return bool(getattr(args, "send", False))


def _rcpt_limit_max_attempts(args) -> int:
    """Max RCPT iterations for RCPTLIM (default ``RCPT_LIMIT_DEFAULT_ATTEMPTS``)."""
    raw = getattr(args, "rcpt_limit", None)
    if raw is None:
        return RCPT_LIMIT_DEFAULT_ATTEMPTS
    return max(1, int(raw))


def _normalize_smtp_role(value: str) -> str:
    """Argparse ``type`` for ``-R`` / ``--role``: case-insensitive ``mta`` or ``submission``."""
    role = (value or "").strip().lower()
    if role not in ("mta", "submission"):
        raise argparse.ArgumentTypeError(
            f"invalid role {value!r} (choose mta or submission)"
        )
    return role


# region -ts test registry (single source of truth for `-ts/--tests`)

# Common outbound message options (shown in per-test help for tests that send mail)
_TS_COMMON_MSG: list[list[str]] = [
    ["-r", "--rcpt-to", "<email>", "Recipient (To)"],
    ["-m", "--mail-from", "<email>", "Envelope sender (MAIL FROM)"],
    ["-cc", "--cc", "<emails>", "CC recipients (comma-separated)"],
    ["-fn", "--from-name", "<name>", "Display name in From header"],
    ["", "--subject", "<text>", "Message subject"],
    ["", "--data", "<text>", "Message body"],
]

# Ordered groups for the main help table
SMTP_TEST_GROUPS: list[tuple[str, list[str]]] = [
    ("Recon & fingerprint", ["BANNER", "IDENTIFY", "IDAGG", "EHLO", "AUTHLIST", "ROLE", "ENCRYPT", "NTLM"]),
    ("Authentication", ["AUTHFMT", "AUTHENUM", "AUTHDN"]),
    ("Protocol & validation", ["HELOVAL", "HELOONLY", "HELOBYP", "INVCMD"]),
    ("Relay & addressing", ["OPENREL", "PROBEDOM", "ALIAS", "BCC", "SPOOF", "BOUNCE"]),
    ("Enumeration & credentials", ["ENUM", "BRUTE"]),
    ("Rate limiting & stress", ["RATELIM", "RCPTLIM", "RCPTDUP", "NOOP1", "NOOP2", "BOMB", "FLOOD"]),
    ("Content security", ["AV", "SSRF", "ZIPXXE"]),
    ("Indirect (no direct SMTP connection)", ["BLACKLIST", "SPF"]),
    ("Utility", ["INTERACT"]),
]

# Per-test definitions:
#   desc      one-line description for the main -ts table
#   long      list of <=3 lines describing what the test does (per-test help)
#   flags     dict dest->value applied to the args namespace when selected
#   value     (dest, default) for tests whose flag carries a value (default set if None)
#   requires  human-readable prerequisite strings (per-test help)
#   common    True -> append common outbound message options to per-test help
#   mods      test-specific option rows [short, long, metavar, help] (per-test help)
SMTP_TESTS: dict[str, dict] = {
    "BANNER": {
        "desc": "Grab banner and service identification",
        "long": ["Connect and read the greeting banner, then identify the product,",
                 "version and CPE from the advertised software string."],
        "flags": {"banner": True},
    },
    "IDENTIFY": {
        "desc": "Identify server software from responses",
        "long": ["Fingerprint the SMTP server from typical responses (banner, EHLO,",
                 "HELP, RCPT error syntax, TLS) without intrusive probing."],
        "flags": {"identify": True},
    },
    "IDAGG": {
        "desc": "Aggressive fingerprinting (VRFY, unknown commands)",
        "long": ["Enhanced identification via VRFY/EXPN, unknown commands (FOOBAR)",
                 "and RFC-edge probing. More accurate but may trigger WAF/IDS."],
        "flags": {"identify": True, "id_aggressive": True},
    },
    "EHLO": {
        "desc": "Grab EHLO extensions (commands JSON)",
        "long": ["Send EHLO and list advertised extensions and AUTH mechanisms."],
        "flags": {"commands": True},
    },
    "AUTHLIST": {
        "desc": "Grab EHLO AUTH mechanisms (auth JSON)",
        "long": ["Same EHLO probe as EHLO but with an authentication-focused JSON",
                 "output shape listing the advertised AUTH mechanisms."],
        "flags": {"authentications": True},
    },
    "ROLE": {
        "desc": "Identify server role (MTA / Submission / Hybrid)",
        "long": ["Determine whether the server behaves as an MTA, a Submission",
                 "service, or a hybrid, based on ports and policy responses."],
        "flags": {"role_identify": True},
    },
    "ENCRYPT": {
        "desc": "Check encryption methods (TLS / STARTTLS)",
        "long": ["Inspect supported transport encryption: implicit TLS and STARTTLS."],
        "flags": {"isencrypt": True},
    },
    "NTLM": {
        "desc": "Inspect NTLM authentication",
        "long": ["Probe NTLM (NTLMSSP) authentication and decode the server challenge",
                 "for leaked domain / host information."],
        "flags": {"ntlm": True},
    },
    "AUTHFMT": {
        "desc": "Probe AUTH LOGIN identity format",
        "long": ["Determine the identity shape the server expects for AUTH LOGIN",
                 "(bare username vs e-mail vs NetBIOS) using passive probes."],
        "flags": {"auth_format": True},
    },
    "AUTHENUM": {
        "desc": "Enumerate users via AUTH",
        "long": ["User enumeration through advertised AUTH LOGIN / PLAIN / NTLM,",
                 "using synthetic invalid baselines to spot differing responses."],
        "flags": {"auth_enum": True},
        "requires": ["-u/--user or -U/--users (candidate names)"],
        "mods": [
            ["-u", "--user", "<name> …", "Candidate username(s)"],
            ["-U", "--users", "<wordlist>", "Username wordlist"],
        ],
    },
    "AUTHDN": {
        "desc": "Test AUTH downgrade after failed authentication",
        "long": ["Check whether advertised AUTH mechanisms change (weaken) after a",
                 "failed authentication attempt."],
        "flags": {"auth_downgrade": True},
    },
    "HELOVAL": {
        "desc": "Test HELO/EHLO hostname validation",
        "long": ["Test how strictly the server validates the HELO/EHLO hostname."],
        "flags": {"helo_validation": True},
    },
    "HELOONLY": {
        "desc": "Test HELO-only without EHLO extensions",
        "long": ["Check whether the server accepts plain HELO without EHLO",
                 "extensions (legacy / downgrade behaviour)."],
        "flags": {"helo_only": True},
    },
    "HELOBYP": {
        "desc": "Test HELO/EHLO bypass of restrictions",
        "long": ["Try HELO/EHLO values that may bypass security restrictions",
                 "(relay / policy checks)."],
        "flags": {"helo_bypass": True},
    },
    "INVCMD": {
        "desc": "Test invalid or non-standard commands",
        "long": ["Send invalid / non-standard SMTP commands and observe robustness,",
                 "information leaks and tarpitting behaviour."],
        "flags": {"invalid_commands": True},
    },
    "OPENREL": {
        "desc": "Test open relay",
        "long": ["Check whether the server relays mail for non-local recipients",
                 "(open relay)."],
        "flags": {"open_relay": True},
    },
    "PROBEDOM": {
        "desc": "Probe which recipient domains are accepted as local",
        "long": ["Probe which recipient domain the server's RCPT TO treats as local."],
        "flags": {"probe_accepted_domain": True},
    },
    "ALIAS": {
        "desc": "Test alias and addressing bypass",
        "long": ["Test address normalization / alias bypass variants (case, dotted,",
                 "plus, percent, UUCP bang paths) against a base recipient."],
        "flags": {"alias_test": True},
        "requires": ["-r/--rcpt-to (base recipient)"],
        "common": True,
        "mods": [
            ["", "--alias-variants", "<v1,v2,...>", "case,case_domain,dotted,plus,percent,bang_simple,bang_nested (default: all)"],
            ["", "--alias-timeout", "<sec>", "Timeout per variant (default: 30)"],
        ],
    },
    "BCC": {
        "desc": "Test BCC header disclosure",
        "long": ["Send a message with To, Cc and Bcc; verify the server strips the",
                 "Bcc header so hidden recipients are not disclosed to To/Cc."],
        "value": ("bcc_test", None),
        "requires": ["-bcc/--bcc <emails> (Bcc addresses)", "-r/--rcpt-to (To)", "-cc/--cc (Cc)"],
        "common": True,
        "mods": [
            ["-bcc", "--bcc", "<emails>", "Bcc recipients (comma-separated)"],
            ["", "--bcc-timeout", "<sec>", "Timeout for BCC test (default: 30)"],
        ],
    },
    "SPOOF": {
        "desc": "Test header spoofing (From, Reply-To, Return-Path)",
        "long": ["Send messages with spoofed From / Reply-To / Return-Path headers",
                 "and report whether the server accepts them (phishing risk)."],
        "flags": {"spoof_headers": True},
        "requires": ["-r/--rcpt-to (recipient)"],
        "common": True,
        "mods": [
            ["", "--spoof-variants", "<v1,v2,...>", "from,reply_to,return_path (default: all)"],
            ["", "--spoof-timeout", "<sec>", "Timeout per message (default: 30)"],
        ],
    },
    "BOUNCE": {
        "desc": "Test bounce / backscatter replay",
        "long": ["Two-probe bounce/backscatter test on one connection to detect",
                 "servers that generate backscatter to a controlled address."],
        "flags": {"bounce_replay": True},
        "requires": ["-m/--mail-from (controlled bounce address)", "-r/--rcpt-to (recipient)"],
        "common": True,
    },
    "ENUM": {
        "desc": "Enumerate users (VRFY / EXPN / RCPT)",
        "long": ["Enumerate valid users via VRFY, EXPN and/or RCPT. Defaults to all",
                 "methods; narrow with --enum-methods and feed names via -u/-U."],
        "value": ("enumerate", "ALL"),
        "mods": [
            ["-e", "--enum-methods", "[VRFY/EXPN/RCPT/ALL]", "Methods to use (default: ALL)"],
            ["-u", "--user", "<name> …", "Candidate username(s)"],
            ["-U", "--users", "<wordlist>", "Username wordlist"],
            ["-t", "--threads", "<n>", "Enumeration threads (default: 1)"],
            ["-sd", "--slow-down", "", "Test slow-down / tarpitting protection"],
            ["", "--enum-reconnect-after", "<n>", "Reconnect after n consecutive failures"],
        ],
    },
    "BRUTE": {
        "desc": "Bruteforce credentials",
        "long": ["Bruteforce SMTP AUTH using username(s) and password(s).",
                 "Requires credentials via -u/-p or -U/-P."],
        "requires": ["-u/--user or -U/--users", "-p/--password or -P/--passwords"],
        "mods": [
            ["-u", "--user", "<name> …", "Username(s)"],
            ["-U", "--users", "<wordlist>", "Username wordlist"],
            ["-p", "--password", "<password>", "Single password"],
            ["-P", "--passwords", "<wordlist>", "Password wordlist"],
        ],
    },
    "RATELIM": {
        "desc": "Test connection rate limiting",
        "long": ["Open many connections to measure whether the server enforces",
                 "connection rate limiting / banning."],
        "value": ("rate_limit", RATE_LIMIT_DEFAULT_ATTEMPTS),
        "mods": [
            ["-rt", "--rate-limit", "<n>", f"Max simultaneous connections to attempt (default: {RATE_LIMIT_DEFAULT_ATTEMPTS})"],
        ],
    },
    "RCPTLIM": {
        "desc": "Test RCPT TO recipient limit",
        "long": ["Storm RCPT TO in one message to find the per-message recipient",
                 "limit. Without -u/-U generates random recipients. With --send it",
                 "also submits one message (DATA) after the RCPT storm."],
        "value": ("rcpt_limit", RCPT_LIMIT_DEFAULT_ATTEMPTS),
        "mods": [
            ["-rl", "--recipient-limit", "<n>", f"Max RCPT attempts per session (default: {RCPT_LIMIT_DEFAULT_ATTEMPTS})"],
            ["", "--send", "", "Submit DATA after the RCPT storm (requires -m/--mail-from)"],
            ["", "--rl-no-precheck", "", "Skip role/open-relay/AUTH pre-check"],
            ["-d", "--domain", "<domain>", "Recipient domain for the probe"],
            ["-m", "--mail-from", "<email>", "Envelope MAIL FROM (default <>)"],
        ],
    },
    "RCPTDUP": {
        "desc": "Test duplicate RCPT TO for one address",
        "long": ["Send RCPT TO repeatedly for the same recipient in one transaction.",
                 "SMTP acceptance does not prove N deliveries — use --send + manual check."],
        "value": ("rcpt_duplicate", RCPT_DUP_DEFAULT),
        "requires": ["-r/--rcpt-to (probed address)"],
        "mods": [
            ["-rdd", "--rcpt-duplicate", "<n>", f"Repeats (default {RCPT_DUP_DEFAULT}, max {RCPT_DUP_MAX})"],
            ["", "--send", "", "Submit minimal DATA after RCPT for manual verification"],
        ],
    },
    "NOOP1": {
        "desc": "NOOP flood on a single connection",
        "long": ["Send NOOPs as fast as possible on one connection; report how many",
                 "the server accepts, response-time growth and error rate."],
        "flags": {"noop_flood1": True},
    },
    "NOOP2": {
        "desc": "NOOP flood on parallel connections",
        "long": ["NOOP flooding DoS across N parallel connections; reports per-command",
                 "reaction time and error rate under load."],
        "value": ("noop_flood2", NOOP_FLOOD2_DEFAULT_CONNECTIONS),
        "mods": [
            ["-nf2", "--noop-flood2", "<n>", f"Parallel connections (default: {NOOP_FLOOD2_DEFAULT_CONNECTIONS})"],
        ],
    },
    "BOMB": {
        "desc": "Mail flooding / rate limiting",
        "long": ["Send many messages to test mail flooding and rate limiting."],
        "flags": {"bomb": True},
        "requires": ["-r/--rcpt-to (recipient)"],
        "common": True,
        "mods": [
            ["", "--bomb-count", "<n>", "Messages to send (default: 100)"],
            ["", "--bomb-timeout", "<sec>", "Max time for the whole test (default: 60)"],
            ["", "--bomb-delay", "<sec>", "Delay between messages (default: 0)"],
            ["", "--bomb-threads", "<n>", "Parallel threads (default: 1)"],
            ["", "--bomb-randomize", "", "Add unique ID to each message"],
        ],
    },
    "FLOOD": {
        "desc": "Queue overload via SIZE and volume",
        "long": ["Test the SIZE extension and queue overload; may delay production",
                 "mail. Stops on 421 (panic)."],
        "flags": {"flood": True},
        "requires": ["-r/--rcpt-to (recipient)"],
        "common": True,
        "mods": [
            ["", "--flood-count", "<n>", "Messages for queue stress (default: 150, max 500)"],
            ["", "--flood-timeout", "<sec>", "Max time for queue stress (default: 90)"],
            ["", "--flood-skip-size-test", "", "Skip MAIL FROM SIZE=oversized test"],
        ],
    },
    "AV": {
        "desc": "Antivirus / antispam filters",
        "long": ["Send benign malware-signature samples (EICAR, double extensions,",
                 "XXE, ...) to test antivirus / antispam filtering."],
        "flags": {"antivirus": True},
        "requires": ["-r/--rcpt-to (recipient)"],
        "common": True,
        "mods": [
            ["", "--av-categories", "<cat,...>", "eicar,double_ext,executable,nested_archive,encoded_content,html_sanitization,xxe,mime_malformed (default: all except zip_bomb)"],
            ["", "--av-zip-bomb", "", "Include zip_bomb category (DoS risk!)"],
            ["", "--av-timeout", "<sec>", "Per-message timeout (default: 30)"],
            ["", "--av-skip-absent", "", "Skip categories with no definition files"],
        ],
    },
    "SSRF": {
        "desc": "Server-side link fetching (SSRF)",
        "long": ["Embed canary URLs in messages to detect whether the server fetches",
                 "links (SSRF). Requires a canary/callback URL."],
        "flags": {"ssrf": True},
        "requires": ["-r/--rcpt-to (recipient)", "--ssrf-canary-url <URL>"],
        "common": True,
        "mods": [
            ["", "--ssrf-canary-url", "<URL>", "Canary/callback URL (Interactsh, ngrok, ...)"],
            ["", "--ssrf-variants", "<v1,v2,...>", "plain,html_link,html_img,html_iframe,multipart,ssrf_malformed,ssrf_nested (default: all)"],
            ["", "--ssrf-internal-urls", "", "Also test internal URLs (127.0.0.1, localhost)"],
            ["", "--ssrf-timeout", "<sec>", "Per-message timeout (default: 30)"],
        ],
    },
    "ZIPXXE": {
        "desc": "Zip bomb, Billion Laughs, XXE",
        "long": ["Send Zip bomb, Billion Laughs and XXE payloads to test archive /",
                 "XML handling. XXE variants require a canary URL."],
        "flags": {"zipxxe": True},
        "requires": ["-r/--rcpt-to (recipient)", "--zipxxe-canary-url for xxe_* variants"],
        "common": True,
        "mods": [
            ["", "--zipxxe-canary-url", "<URL>", "Canary URL for xxe_zip / xxe_docx / xxe_body"],
            ["", "--zipxxe-variants", "<v1,v2,...>", "billion_laughs_attach,billion_laughs_body,xxe_zip,xxe_docx,xxe_body (default: all)"],
            ["", "--zipxxe-zip-bomb", "", "Include zip_bomb (minimal ~200KB; DoS risk!)"],
            ["", "--zipxxe-zip-bomb-full", "", "Include zip_bomb_full (~100KB→~100MB; extreme DoS risk!)"],
            ["", "--zipxxe-timeout", "<sec>", "Per-message timeout (default: 30)"],
        ],
    },
    "BLACKLIST": {
        "desc": "Check target against blacklists",
        "long": ["Look up the target (domain + public IP) against DNS blacklists.",
                 "No direct SMTP connection is made."],
        "flags": {"blacklist_test": True},
    },
    "SPF": {
        "desc": "Check SPF records (requires domain target)",
        "long": ["Fetch and evaluate SPF records for the target domain.",
                 "Requires a domain name (not a bare IP)."],
        "flags": {"spf_test": True},
    },
    "INTERACT": {
        "desc": "Interactive SMTP CLI",
        "long": ["Open an interactive SMTP session for manual command entry."],
        "flags": {"interactive": True},
    },
}


# Tests that cannot be realized without actually delivering a message. When one of
# these is selected explicitly via ``-ts`` without ``--send`` we refuse to run and
# tell the user that ``--send`` is required (see ``_apply_smtp_tests``). Tests not
# listed here either never send (recon/validation) or only send optionally when
# ``--send`` is given (RCPTLIM, RCPTDUP). OPENREL is intentionally exempt: it is a
# core recon test that runs in run-all mode.
SMTP_SEND_REQUIRED: frozenset[str] = frozenset(
    {"BCC", "BOUNCE", "BOMB", "FLOOD", "AV", "ZIPXXE", "SSRF", "SPOOF", "ALIAS"}
)


# Internal per-test boolean dest flags driven exclusively by -ts. The legacy
# test-selecting flags were removed, so argparse no longer defines these dests;
# they must be initialised here so run() / _is_run_all_mode() can read them
# unconditionally. Value-carrying tests (ENUM, BCC, RATELIM, RCPTLIM, RCPTDUP,
# NOOP2) keep their own argparse options (they carry the value) and default to
# None, so they are intentionally NOT listed here.
SMTP_TEST_DESTS: tuple[str, ...] = (
    "banner", "identify", "id_aggressive", "commands", "authentications",
    "auth_format", "auth_enum", "auth_downgrade", "helo_validation",
    "invalid_commands", "helo_only", "helo_bypass", "bounce_replay",
    "spoof_headers", "alias_test", "isencrypt", "ntlm", "noop_flood1",
    "probe_accepted_domain", "open_relay", "role_identify", "interactive",
    "blacklist_test", "spf_test", "bomb", "antivirus", "ssrf", "flood", "zipxxe",
)

# Value-carrying tests whose dest doubles as the selection signal (``None`` means
# "not selected"). Kept separate from the boolean dests above so run-all detection
# can stay data-driven instead of a hand-maintained boolean expression.
SMTP_VALUE_DESTS: tuple[str, ...] = (
    "enumerate", "rate_limit", "noop_flood2", "rcpt_limit", "rcpt_duplicate",
    "bcc_test",
)


def _smtp_parse_test_codes(raw: str | None) -> list[str]:
    """Split and upper-case a raw -ts value into a list of codes."""
    if not raw:
        return []
    return [c.strip().upper() for c in str(raw).split(",") if c.strip()]


def _apply_smtp_tests(args) -> None:
    """Translate ``-ts/--tests`` codes into the internal per-test dest flags.

    ``ALL`` (or no ``-ts``) leaves every flag at default -> run-all mode.
    """
    # Initialise every boolean test dest (argparse no longer defines them).
    for dest in SMTP_TEST_DESTS:
        if not hasattr(args, dest):
            setattr(args, dest, False)

    codes = _smtp_parse_test_codes(getattr(args, "tests", None))
    if not codes:
        return
    if "ALL" in codes:
        # Explicit full scan: apply nothing so _is_run_all_mode() stays True.
        return
    unknown = [c for c in codes if c not in SMTP_TESTS]
    if unknown:
        available = ", ".join(sorted(SMTP_TESTS))
        raise argparse.ArgumentError(
            None,
            f"Unknown test(s): {', '.join(unknown)}. Available: ALL, {available}",
        )

    # Tests that must deliver a message require the global --send switch.
    if not getattr(args, "send", False):
        need_send = [c for c in codes if c in SMTP_SEND_REQUIRED]
        if need_send:
            raise argparse.ArgumentError(
                None,
                "; ".join(
                    f"{code}: Parameter --send is required for this test"
                    for code in need_send
                ),
            )

    for code in codes:
        spec = SMTP_TESTS[code]
        for dest, val in spec.get("flags", {}).items():
            setattr(args, dest, val)
        value = spec.get("value")
        if value is not None:
            dest, default = value
            if getattr(args, dest, None) is None and default is not None:
                setattr(args, dest, default)

    # Every explicitly selected test must actually activate; otherwise report what is
    # missing instead of silently falling back to run-all mode.
    inactive: list[tuple[str, list[str]]] = []
    for code in codes:
        spec = SMTP_TESTS[code]
        if code == "BRUTE":
            active = check_if_brute(args)
        elif "flags" in spec:
            active = all(getattr(args, dest, None) for dest in spec["flags"])
        elif "value" in spec:
            active = getattr(args, spec["value"][0], None) is not None
        else:
            active = True
        if not active:
            inactive.append((code, list(spec.get("requires", []))))
    if inactive:
        parts = [
            f"{code} requires {'; '.join(req)}" if req else f"{code} could not be activated"
            for code, req in inactive
        ]
        raise argparse.ArgumentError(None, "; ".join(parts))


def _smtp_test_help(codes: list[str]):
    """Build a help object (for ptprinthelper.help_print) describing given test codes."""
    if not codes:
        return None
    valid = [c for c in codes if c in SMTP_TESTS]
    if not valid:
        available = ", ".join(sorted(SMTP_TESTS))
        return [
            {"unknown_test": [f"Unknown test: {', '.join(codes)}"]},
            {"available_tests": [f"ALL, {available}"]},
        ]
    out: list[dict] = []
    for code in valid:
        spec = SMTP_TESTS[code]
        header = f"{code} — {spec.get('desc', '')}"
        out.append({"test": [header, *spec.get("long", [])]})
        req = list(spec.get("requires", []))
        if code in SMTP_SEND_REQUIRED:
            req.append("--send (required to actually deliver the test message(s))")
        if req:
            out.append({"requires": req})
        rows: list[list[str]] = list(spec.get("mods", []))
        if spec.get("common"):
            rows = rows + _TS_COMMON_MSG
        if rows:
            out.append({"test_options": rows})
        has_opts = bool(rows or req)
        usage = f"ptsrvtester smtp -ts {code} " + ("<options> <target>" if has_opts else "<target>")
        out.append({"usage": [usage]})
    return out


# endregion
