"""POP3 -ts registry — used for help text only (execution is module discovery)."""
from __future__ import annotations

from ptsrvtester.protocols._shared.utils.cli import rate_limit_test_spec

POP3_TEST_GROUPS: list[tuple[str, list[str]]] = [
    ("Recon & fingerprint", ["BANNER", "CAPA", "ENCRYPT", "NTLM", "HELPINFO"]),
    ("Authentication & credentials", ["ANON", "BRUTE"]),
    ("Connection limits & stress", ["NOOP1", "NOOP2"]),
    ("Connection rate limiting (aggressive)", ["RATELIMIT"]),
]

# Default suite when -ts is omitted or ALL (preserves previous POP3 behaviour).
POP3_DEFAULT_SUITE: tuple[str, ...] = (
    "BANNER", "CAPA", "ENCRYPT", "ANON", "HELPINFO",
)

POP3_TESTS: dict[str, dict] = {
    "BANNER": {
        "desc": "Grab banner and service identification",
        "long": [
            "Connect and read the greeting banner, then identify the product,",
            "version and CPE from the advertised software string.",
        ],
    },
    "CAPA": {
        "desc": "Grab CAPA capabilities",
        "long": [
            "Send CAPA and list advertised capabilities; flags weak options",
            "(USER plaintext, IMPLEMENTATION disclosure, missing STLS).",
        ],
    },
    "ENCRYPT": {
        "desc": "Test encryption options (plaintext / STLS / TLS)",
        "long": [
            "Inspect supported transport encryption on the port: plaintext",
            "login, explicit STLS upgrade and implicit TLS.",
        ],
    },
    "NTLM": {
        "desc": "Inspect NTLM authentication",
        "long": [
            "Probe NTLM (NTLMSSP) authentication and decode the server",
            "challenge for leaked domain / host information.",
        ],
    },
    "HELPINFO": {
        "desc": "Test HELP and IMPLEMENTATION info disclosure",
        "long": [
            "Send HELP (non-standard) and read IMPLEMENTATION from CAPA to",
            "reveal software / version information disclosed by the server.",
        ],
    },
    "ANON": {
        "desc": "Check anonymous authentication",
        "long": [
            "Attempt anonymous / guest login to detect servers that accept",
            "AUTH ANONYMOUS without credentials.",
        ],
    },
    "BRUTE": {
        "desc": "Login bruteforce (USER/PASS)",
        "long": [
            "Bruteforce POP3 USER/PASS. Without -u/-U or -p/-P, built-in lists are used.",
            "Catch-all check first. Error when the server",
            "never stops password guessing.",
        ],
        "mods": [
            ["-u", "--user", "<name> …", "Username(s). Default: root, admin, demo, test, user, jane, john"],
            ["-U", "--users", "<wordlist>", "Username wordlist"],
            ["-p", "--password", "[password] …", "Password(s). Default: pass, pass123, Pass123, password, Pa$$w0rd, abcd, abcde, abcdef, 0000, 1234, 12345, 123456, Admin123"],
            ["-P", "--passwords", "<wordlist>", "Password wordlist"],
            ["", "--spray", "", "Try one password against all users"],
            ["-t", "--brute-threads", "<n>", "Threads for bruteforce (default: 10)"],
        ],
    },
    "NOOP1": {
        "desc": "NOOP connection duration",
        "long": [
            "Test how long connections can be maintained with periodic NOOP.",
            "Pre-authentication test always runs; post-authentication test runs",
            "if -u/-p provided. RFC 1939 specifies 10-minute minimum timeout.",
        ],
        "mods": [
            ["", "--duration", "<sec>", "How long the test runs (default: 35 min pre-auth / 70 min post-auth)"],
            ["", "--delay", "<sec>", "Wait between NOOPs (default: 4 min pre-auth / 5 min post-auth; 0 = max speed)"],
            ["-u", "--user", "<name>", "Username for post-auth test (optional)"],
            ["-p", "--password", "<pass>", "Password for post-auth test (optional)"],
        ],
    },
    "NOOP2": {
        "desc": "NOOP connection count",
        "long": [
            "Test how many connections can be established and maintained with",
            "periodic NOOP. Pre-authentication test always runs; post-authentication",
            "test runs if -u/-p provided. Evaluates per-IP and per-account limits.",
        ],
        "mods": [
            ["", "--count", "<n>", "Max connections to attempt (default: 150)"],
            ["", "--duration", "<sec>", "How long the test runs (default: 120s pre-auth / 180s post-auth)"],
            ["", "--delay", "<sec>", "Wait between NOOPs (default: 60s; 0 = max speed)"],
            ["-t", "--threads", "<n>", "Parallel connect threads (default: 1)"],
            ["-u", "--user", "<name>", "Username for post-auth test (optional)"],
            ["-p", "--password", "<pass>", "Password for post-auth test (optional)"],
        ],
    },
    "RATELIMIT": rate_limit_test_spec(),
}


def _option_rows(rows: list) -> list:
    """Drop the empty short-flag column when a test has none."""
    if not rows or not all(isinstance(row, list) and len(row) >= 4 for row in rows):
        return rows
    if any(row[0] for row in rows):
        return rows
    return [row[1:] for row in rows]


def pop3_test_help(codes: list[str]):
    """Build a help object describing the given test codes."""
    if not codes:
        return None
    valid = [c for c in codes if c in POP3_TESTS]
    if not valid:
        available = ", ".join(POP3_TESTS)
        return [{"unknown_test": [f"Unknown test: {', '.join(codes)}. Available: ALL, {available}"]}]

    blocks = []
    for code in valid:
        spec = POP3_TESTS[code]
        desc = [f"POP3 — {code}: {spec['desc']}"]
        desc.extend(spec.get("long", []) or [])
        if spec.get("requires"):
            desc.append("Requires: " + "; ".join(spec["requires"]))
        mods = _option_rows(list(spec.get("mods", []) or []))
        has_opts = bool(mods or spec.get("requires"))
        usage = f"ptsrvtester pop3 -ts {code} " + ("<options> -tg <target>" if has_opts else "-tg <target>")
        blocks.append({"description": desc})
        if mods:
            blocks.append({"options": mods})
        blocks.append({"usage": [usage]})
    return blocks
