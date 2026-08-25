"""POP3 -ts registry — used for help text only (execution is module discovery)."""
from __future__ import annotations

from ptsrvtester.protocols._shared.utils.cli import rate_limit_test_spec

POP3_TEST_GROUPS: list[tuple[str, list[str]]] = [
    ("Recon & fingerprint", ["BANNER", "CAPA", "ENCRYPT", "NTLM", "HELPINFO"]),
    ("Authentication & credentials", ["ANON", "BRUTE"]),
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
            "Bruteforce POP3 login with the supplied username(s) and",
            "password(s); runs a catch-all check first.",
        ],
        "requires": ["-u/--user or -U/--users", "-p/--password or -P/--passwords"],
        "mods": [
            ["-u", "--user", "<name>", "Single username"],
            ["-U", "--users", "<wordlist>", "Username wordlist"],
            ["-p", "--password", "<password>", "Single password"],
            ["-P", "--passwords", "<wordlist>", "Password wordlist"],
        ],
    },
    "RATELIMIT": rate_limit_test_spec(),
}


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
        options: list[list[str]] = []
        for line in spec.get("long", []) or []:
            options.append(["", "", "", line])
        if spec.get("requires"):
            options.append(["", "", "", ""])
            options.append(["", "", "", "Requires: " + "; ".join(spec["requires"])])
        for row in spec.get("mods", []) or []:
            options.append(row)
        has_opts = bool(spec.get("mods") or spec.get("requires"))
        usage = f"ptsrvtester pop3 -ts {code} " + ("<options> -tg <target>" if has_opts else "-tg <target>")
        blocks.append({"description": [f"POP3 — {code}: {spec['desc']}"]})
        blocks.append({"usage": [usage]})
        if options:
            blocks.append({"options": options})
    return blocks
