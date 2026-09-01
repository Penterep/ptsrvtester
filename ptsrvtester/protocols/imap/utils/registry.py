"""IMAP -ts registry — help text only (execution is module discovery)."""
from __future__ import annotations

IMAP_TEST_GROUPS: list[tuple[str, list[str]]] = [
    ("Recon & fingerprint", ["BANNER", "CAPA", "ENCRYPT", "NTLM"]),
    ("Protocol & validation", ["SNIFF", "INVCMD"]),
    ("Authentication & enumeration", ["ANON", "USRENUM", "USRENUMPLAIN", "BRUTE"]),
    ("Content security", ["EICAR"]),
    ("Rate limiting & stress", ["CONNLIM", "RESLOAD"]),
    ("Access control & TLS", ["MBOXISO", "TLSAUDIT"]),
]

# Default suite when -ts omitted or ALL (matches previous IMAP default recon behaviour).
IMAP_DEFAULT_SUITE: tuple[str, ...] = (
    "BANNER", "CAPA", "ENCRYPT", "ANON",
)

IMAP_TESTS: dict[str, dict] = {
    "BANNER": {
        "desc": "Grab banner and service identification",
        "long": [
            "Connect and read the greeting banner, then identify the product,",
            "version and CPE from the advertised software string.",
        ],
    },
    "CAPA": {
        "desc": "Grab ID and CAPABILITY",
        "long": [
            "Inspect the ID and CAPABILITY responses and flag weak or",
            "information-disclosing options.",
        ],
    },
    "ENCRYPT": {
        "desc": "Test encryption options (plaintext / STARTTLS / TLS)",
        "long": [
            "Inspect supported transport encryption on the port: plaintext",
            "login, explicit STARTTLS upgrade and implicit TLS.",
        ],
    },
    "NTLM": {
        "desc": "Inspect NTLM authentication",
        "long": [
            "AUTHENTICATE NTLM: read CAPABILITY for AUTH=NTLM, send Negotiate",
            "and decode the server Challenge for leaked domain / host info.",
        ],
    },
    "SNIFF": {
        "desc": "Cleartext sniffable probe",
        "long": [
            "Probe cleartext IMAP: CAPABILITY, STARTTLS advertisement and",
            "whether AUTHENTICATE accepts a continuation on plain TCP.",
        ],
    },
    "INVCMD": {
        "desc": "Test invalid / non-standard commands",
        "long": [
            "Audit invalid / malformed IMAP commands, long lines, bad tags and",
            "binary / control octets for robustness and info leaks.",
        ],
    },
    "ANON": {
        "desc": "Check anonymous access",
        "long": [
            "Check SASL ANONYMOUS and LOGIN anonymous / guest / public to",
            "detect servers that accept unauthenticated access.",
        ],
    },
    "USRENUM": {
        "desc": "LOGIN user enumeration",
        "long": [
            "LOGIN each name from the wordlist with a fixed wrong password and",
            "compare errors against non-existent baselines.",
        ],
        "requires": ["--usrenum-wordlist <file>"],
        "mods": [
            ["", "--usrenum-wordlist", "<file>", "Username list (required)"],
            ["", "--usrenum-password", "<str>", "Wrong password for every probe"],
            ["", "--usrenum-max", "<n>", "Limit names read from wordlist (0 = no limit)"],
            ["", "--usrenum-threads", "<n>", "Parallel TCP sessions (default 1)"],
        ],
    },
    "USRENUMPLAIN": {
        "desc": "AUTHENTICATE PLAIN user enumeration",
        "long": [
            "AUTHENTICATE PLAIN (SASL) each name from the wordlist with a wrong",
            "password; use when CAPABILITY lists LOGINDISABLED.",
        ],
        "requires": ["--usrenum-wordlist <file>"],
        "mods": [
            ["", "--usrenum-wordlist", "<file>", "Username list (required)"],
            ["", "--usrenum-password", "<str>", "Wrong password for every probe"],
            ["", "--usrenum-max", "<n>", "Limit names read from wordlist (0 = no limit)"],
            ["", "--usrenum-threads", "<n>", "Parallel TCP sessions (default 1)"],
        ],
    },
    "BRUTE": {
        "desc": "Login bruteforce (USER/PASS)",
        "long": [
            "Bruteforce IMAP login with the supplied username(s) and",
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
    "EICAR": {
        "desc": "APPEND EICAR antivirus probe",
        "long": [
            "APPEND an RFC 822 message containing the EICAR test line to a",
            "mailbox to check server-side antivirus / content filtering.",
        ],
        "requires": ["-u/--user and -p/--password (no wordlists)"],
        "mods": [
            ["", "--eicar-mailbox", "<name>", "Mailbox name for APPEND (default INBOX)"],
        ],
    },
    "CONNLIM": {
        "desc": "Connection limits / rate / idle probes",
        "long": [
            "Connection-count, connect-rate and idle-time probes; with -u/-p",
            "also probes parallel LOGIN sessions and IDLE lifetime.",
        ],
        "mods": [
            ["", "--cl-max", "<n>", "Max concurrent connections in ramp-up"],
        ],
    },
    "RESLOAD": {
        "desc": "APPEND + SEARCH resource-load stress",
        "long": [
            "Bounded authenticated APPEND burst followed by a UID SEARCH ALL",
            "loop; watches for disconnects, errors and slowdown.",
        ],
        "requires": ["-u/--user and -p/--password (no wordlists)"],
        "mods": [
            ["", "--resource-load-mailbox", "<name>", "Mailbox for APPEND phase (default INBOX)"],
            ["", "--resource-load-append-max", "<n>", "Max APPEND operations (hard cap 5000)"],
            ["", "--resource-load-search-max", "<n>", "Max UID SEARCH ALL commands (0 skips)"],
        ],
    },
    "MBOXISO": {
        "desc": "Mailbox isolation / ACL",
        "long": [
            "Post-login isolation: NAMESPACE, LIST, GETACL, bounded EXAMINE",
            "path probes and a LIST dictionary for cross-user access.",
        ],
        "requires": ["-u/--user and -p/--password (no wordlists)"],
        "mods": [
            ["", "--mailbox-iso-foreign-user", "<name>", "Token for cross-user heuristics (default user2)"],
            ["", "--mailbox-iso-mailbox", "<name>", "Own baseline mailbox (default INBOX)"],
        ],
    },
    "TLSAUDIT": {
        "desc": "Strict TLS handshake + certificate audit",
        "long": [
            "Strict TLS handshake with platform trust store and hostname check;",
            "reports TLS version, cipher and certificate subject / issuer / SAN.",
            "Implicit TLS on 993 (or --tls), otherwise STARTTLS when advertised.",
        ],
    },
}


def imap_test_help(codes: list[str]):
    if not codes:
        return None
    valid = [c for c in codes if c in IMAP_TESTS]
    if not valid:
        available = ", ".join(IMAP_TESTS)
        return [{"unknown_test": [f"Unknown test: {', '.join(codes)}. Available: ALL, {available}"]}]

    blocks = []
    for code in valid:
        spec = IMAP_TESTS[code]
        options: list[list[str]] = []
        for line in spec.get("long", []) or []:
            options.append(["", "", "", line])
        if spec.get("requires"):
            options.append(["", "", "", ""])
            options.append(["", "", "", "Requires: " + "; ".join(spec["requires"])])
        for row in spec.get("mods", []) or []:
            options.append(row)
        has_opts = bool(spec.get("mods") or spec.get("requires"))
        usage = f"ptsrvtester imap -ts {code} " + ("<options> -tg <target>" if has_opts else "-tg <target>")
        blocks.append({"description": [f"IMAP — {code}: {spec['desc']}"]})
        blocks.append({"usage": [usage]})
        if options:
            blocks.append({"options": options})
    return blocks
