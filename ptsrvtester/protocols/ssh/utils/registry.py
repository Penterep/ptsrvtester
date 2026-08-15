"""The ``-ts/--tests`` registry for SSH: single source of truth for help text.

Selection itself is handled generically by :class:`BaseMain` (it matches ``-ts``
codes against each module's ``__MODULECODE__``). This registry only feeds the
help tables: the main ``ssh -h`` test list and per-test ``ssh -ts <TEST> -h``.
Keep every code here in sync with a module's ``__MODULECODE__``.
"""

SSH_TEST_GROUPS: list[tuple[str, list[str]]] = [
    ("Recon & fingerprint", ["BANNER", "HOSTKEY", "AUTHM"]),
    ("Crypto & configuration (ssh-audit)", ["KEX", "KEYALG", "ENC", "MAC", "FINGERPRINT"]),
    ("Known static keys", ["BADHOSTKEY", "BADAUTHKEY"]),
    ("Credentials", ["BRUTE"]),
    ("Denial of service (aggressive)", ["DHEAT"]),
]

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
    "KEX": {
        "desc": "Key exchange algorithms (ssh-audit)",
        "long": ["Report the key exchange algorithms the server offers and flag the",
                 "weak ones (from a shared ssh-audit scan)."],
    },
    "KEYALG": {
        "desc": "Host-key algorithms (ssh-audit)",
        "long": ["Report the host-key algorithms the server offers and flag the weak",
                 "ones. Distinct from HOSTKEY, which fetches the actual host key."],
    },
    "ENC": {
        "desc": "Encryption algorithms / ciphers (ssh-audit)",
        "long": ["Report the encryption (cipher) algorithms the server offers and",
                 "flag the weak ones (from a shared ssh-audit scan)."],
    },
    "MAC": {
        "desc": "MAC algorithms (ssh-audit)",
        "long": ["Report the message authentication code (MAC) algorithms the server",
                 "offers and flag the weak ones (from a shared ssh-audit scan)."],
    },
    "FINGERPRINT": {
        "desc": "Host-key fingerprints (ssh-audit)",
        "long": ["List the SHA256/MD5 fingerprints of the server's host keys",
                 "(informational, from a shared ssh-audit scan)."],
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
    "DHEAT": {
        "desc": "DHEat DoS attack (aggressive; ssh-audit --dheat)",
        "long": ["Actively run ssh-audit's DHEat Diffie-Hellman DoS attack",
                 "(CVE-2002-20001) and report whether the server throttles connections.",
                 "Aggressive and slow — never runs in the default sweep."],
        "requires": ["explicit -ts DHEAT (excluded from ALL); target must offer a DH key exchange"],
        "mods": [
            ["", "--dheat", "<N[:kex[:e_len]]>", "N concurrent sockets, optional kex + fake-e length (default: 10)"],
            ["", "--dheat-duration", "<seconds>", "How long to run the attack before stopping (default: 20)"],
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