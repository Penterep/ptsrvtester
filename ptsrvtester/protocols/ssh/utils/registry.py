"""The ``-ts/--tests`` registry for SSH: single source of truth for help text.

Selection itself is handled generically by :class:`BaseMain` (it matches ``-ts``
codes against each module's ``__MODULECODE__``). This registry only feeds the
help tables: the main ``ssh -h`` test list and per-test ``ssh -ts <TEST> -h``.
Keep every code here in sync with a module's ``__MODULECODE__``.
"""

# Ordered groups for the main help table: (group title, [codes]).
SSH_TEST_GROUPS: list[tuple[str, list[str]]] = [
    ("Recon & fingerprint", ["BANNER", "HOSTKEY", "AUTHM"]),
    ("Crypto & configuration", ["AUDIT"]),
    ("Known static keys", ["BADHOSTKEY", "BADAUTHKEY"]),
    ("Credentials", ["BRUTE"]),
]

# Per-test metadata:
#   desc      one-line description for the main -ts table
#   long      <=3 lines describing the test (per-test help)
#   requires  human-readable prerequisites (per-test help)
#   mods      test-specific option rows [short, long, metavar, help] (per-test help)
SSH_TESTS: dict[str, dict] = {
    "BANNER": {
        "desc": "Grab banner and service identification",
        "long": ["Read the SSH identification banner and identify the product,",
                 "version and CPE from the advertised software string."],
    },
    "HOSTKEY": {
        "desc": "Grab the server host key",
        "long": ["Establish an SSH transport and read the remote server host key",
                 "(type + base64)."],
    },
    "AUTHM": {
        "desc": "List supported authentication methods",
        "long": ["List the authentication methods the server offers and warn when",
                 "keyboard-interactive is present (may affect password bruteforce)."],
    },
    "AUDIT": {
        "desc": "Run ssh-audit (CVEs + insecure crypto)",
        "long": ["Use the ssh-audit tool to identify known CVEs and insecure key",
                 "exchange / cipher / MAC configuration."],
    },
    "BADHOSTKEY": {
        "desc": "Check host key against known static (bad) keys",
        "long": ["Compare the server host key against a directory of known-compromised",
                 "public host keys (e.g. rapid7/ssh-badkeys)."],
        "requires": ["-H/--bad-pubkeys <directory> of <name>.pub public keys"],
        "mods": [
            ["-H", "--bad-pubkeys", "<directory>", "Directory of known <name>.pub host keys"],
        ],
    },
    "BADAUTHKEY": {
        "desc": "Check for accepted known static (bad) user keys",
        "long": ["Try a directory of known-compromised private user keys (with their",
                 "<name>.yml usernames) and report any the server accepts."],
        "requires": ["-A/--bad-authkeys <directory> of <name>.key + <name>.yml"],
        "mods": [
            ["-A", "--bad-authkeys", "<directory>", "Directory of known <name>.key private keys + <name>.yml"],
        ],
    },
    "BRUTE": {
        "desc": "Login bruteforce (password or private key)",
        "long": ["Bruteforce SSH login with username(s) and password(s), or with a",
                 "directory of private keys."],
        "requires": ["-u/--user or -U/--users", "-p/--password or -P/--passwords (or --privkeys <directory>)"],
        "mods": [
            ["-u", "--user", "<username>", "Single username"],
            ["-U", "--users", "<wordlist>", "File with usernames"],
            ["-p", "--password", "<password>", "Single password"],
            ["-P", "--passwords", "<wordlist>", "File with passwords"],
            ["", "--privkeys", "<directory>", "Directory of <name>.key private keys (+ <name>.pass)"],
            ["", "--spray", "", "Try one secret across all users (instead of all secrets per user)"],
            ["", "--brute-threads", "<n>", "Threads for bruteforce (default: 10)"],
        ],
    },
}


def ssh_test_help(codes: list[str]):
    """Build a help object (for ptprinthelper.help_print) for the given test codes."""
    if not codes:
        return None
    valid = [c for c in codes if c in SSH_TESTS]
    if not valid:
        available = ", ".join(sorted(SSH_TESTS))
        return [
            {"unknown_test": [f"Unknown test: {', '.join(codes)}"]},
            {"available_tests": [f"ALL, {available}"]},
        ]
    out: list[dict] = []
    for code in valid:
        spec = SSH_TESTS[code]
        out.append({"test": [f"{code} — {spec.get('desc', '')}", *spec.get("long", [])]})
        req = list(spec.get("requires", []))
        if req:
            out.append({"requires": req})
        rows = list(spec.get("mods", []))
        if rows:
            out.append({"test_options": rows})
        has_opts = bool(rows or req)
        usage = f"ptsrvtester ssh -ts {code} " + ("<options> <target>" if has_opts else "<target>")
        out.append({"usage": [usage]})
    return out