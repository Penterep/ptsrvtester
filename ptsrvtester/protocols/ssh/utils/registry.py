"""The ``-ts/--tests`` registry for SSH: single source of truth for help text.

Selection itself is handled generically by :class:`BaseMain` (it matches ``-ts``
codes against each module's ``__MODULECODE__``). This registry only feeds the
help tables: the main ``ssh -h`` test list and per-test ``ssh -ts <TEST> -h``.
Keep every code here in sync with a module's ``__MODULECODE__``.
"""

SSH_TEST_GROUPS: list[tuple[str, list[str]]] = [
    ("Recon & fingerprint", ["BANNER", "HOSTKEY", "AUTHM"]),
    ("Crypto & configuration (ssh-audit)", ["KEX", "KEYALG", "ENC", "MAC", "FINGERPRINT"]),
    ("Protocol & config hygiene", ["SSHV1", "TERRAPIN"]),
    ("Known static keys", ["BADHOSTKEY", "BADAUTHKEY"]),
    ("Root login policy", ["ROOTLOGIN"]),
    ("Post-auth access", ["SHELL", "PRIVS"]),
    ("Port forwarding & tunneling", ["FORWARD"]),
    ("SFTP / file transfer", ["SFTP", "SFTPDATA"]),
    ("Credentials", ["BRUTE"]),
    ("User enumeration (aggressive)", ["USERENUM"]),
    ("Brute-force protection (aggressive)", ["LOCKOUT"]),
    ("Denial of service (aggressive)", ["DHEAT"]),
    ("Connection rate limiting (aggressive)", ["RATELIMIT"]),
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
    "SSHV1": {
        "desc": "Legacy SSH protocol 1 support",
        "long": ["Read the identification banner and report whether the server still",
                 "speaks SSH protocol 1 (protocol version 1.x = SSH-1 only, 1.99 =",
                 "SSH-1 fallback, 2.0 = SSH-2 only). SSH-1 is cryptographically broken",
                 "(CRC-32 attack, trivial MITM); any SSH-1 support is a finding."],
    },
    "TERRAPIN": {
        "desc": "Terrapin prefix-truncation exposure (CVE-2023-48795)",
        "long": ["Read the server KEXINIT and decide whether the transport is",
                 "Terrapin-exploitable: a truncatable cipher mode",
                 "(chacha20-poly1305@openssh.com, or a CBC cipher + *-etm@openssh.com",
                 "MAC) offered together with no strict-kex countermeasure",
                 "(kex-strict-s-v00@openssh.com not advertised). Pre-auth, no",
                 "credentials needed."],
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
    "ROOTLOGIN": {
        "desc": "Is direct login to the root account permitted?",
        "long": ["Check whether the server permits root login. Reads the auth methods",
                 "advertised for root (vs an ordinary name): if root is offered a",
                 "password method, password root login is permitted (PermitRootLogin",
                 "should be no / prohibit-password). If a secret is supplied",
                 "(-p/-P/--privkeys) it also tries a real root login and confirms access.",
                 "Without valid root credentials, no vs yes cannot be proven remotely."],
        "requires": ["nothing (behavioural). Add -p/-P or --privkeys to confirm by real login;",
                     "-u overrides the tested account name (default: root)"],
        "mods": [
            ["-u", "--user", "<username>", "Account to test (default: root)"],
            ["-p", "--password", "<password>", "Password to confirm root login (optional)"],
            ["-P", "--passwords", "<wordlist>", "Passwords to confirm root login (optional)"],
            ["", "--privkeys", "<directory>", "Private keys to confirm root login (optional)"],
        ],
    },
    "SHELL": {
        "desc": "Is shell / command execution permitted after login?",
        "long": ["Log in with the supplied credentials and check what the account can",
                 "actually do: run a command (exec) and open an interactive shell (PTY).",
                 "If either works, shell access is permitted; if neither does, the",
                 "account is shell-restricted (nologin / /bin/false / SFTP-only /",
                 "ForceCommand). Needs valid credentials to log in first."],
        "requires": ["-u/--user (account to test)",
                     "-p/-P or --privkeys (a secret that authenticates the account)"],
        "mods": [
            ["-u", "--user", "<username>", "Account to test (required)"],
            ["-p", "--password", "<password>", "Password to log in"],
            ["-P", "--passwords", "<wordlist>", "Passwords to log in (first that works is used)"],
            ["", "--privkeys", "<directory>", "Private keys to log in"],
        ],
    },
    "PRIVS": {
        "desc": "Post-auth privileges & access (groups, files, sudo)",
        "long": ["Log in with the supplied credentials and enumerate what the account",
                 "can reach: its user groups (flagging privileged / root-equivalent",
                 "ones like sudo/wheel/docker/lxd), read/write/execute rights on",
                 "sensitive files and $PATH directories, which administrative commands",
                 "are available, and its sudo rights (sudo -n -l). Passwordless sudo,",
                 "root-equivalent group membership and writable sensitive files are",
                 "reported as findings. Companion to SHELL; needs valid credentials."],
        "requires": ["-u/--user (account to test)",
                     "-p/-P or --privkeys (a secret that authenticates the account)"],
        "mods": [
            ["-u", "--user", "<username>", "Account to test (required)"],
            ["-p", "--password", "<password>", "Password to log in"],
            ["-P", "--passwords", "<wordlist>", "Passwords to log in (first that works is used)"],
            ["", "--privkeys", "<directory>", "Private keys to log in"],
        ],
    },
    "SFTP": {
        "desc": "SFTP/SCP access control & confinement (post-auth)",
        "long": ["Log in with the supplied credentials, open an SFTP session and",
                 "check how well the account is confined: whether SFTP/SCP is",
                 "available, whether a ChrootDirectory confines it or the real",
                 "filesystem is visible, whether it can read or write outside the",
                 "intended tree, whether a symlink can escape the confinement,",
                 "whether an 'SFTP-only' account unexpectedly also has a shell /",
                 "command execution / port forwarding, and whether an NTFS",
                 "Alternate Data Stream can be written. All write probes use a",
                 "unique name and are cleaned up. Needs valid credentials; never",
                 "runs in the default / ALL sweep."],
        "requires": ["-u/--user (account to test)",
                     "-p/-P or --privkeys (a secret that authenticates the account)"],
        "mods": [
            ["-u", "--user", "<username>", "Account to test (required)"],
            ["-p", "--password", "<password>", "Password to log in"],
            ["-P", "--passwords", "<wordlist>", "Passwords to log in (first that works is used)"],
            ["", "--privkeys", "<directory>", "Private keys to log in"],
        ],
    },
    "SFTPDATA": {
        "desc": "SFTP content scanning & resource limits (aggressive)",
        "long": ["Log in and, with BOUNDED, cleaned-up uploads, check what happens to",
                 "uploaded content and whether limits exist: whether an EICAR test",
                 "file is scanned/rejected or stored intact (no antivirus); whether",
                 "the server decompresses/parses uploads (a bounded ZIP bomb + XXE",
                 "probe timed against an incompressible baseline — a DoS surface); and",
                 "whether any size or file-count quota is enforced (else disk-fill DoS",
                 "is possible). Aggressive and opt-in; every default is small and the",
                 "flags are clamped to safe caps. Needs valid credentials; never runs",
                 "in the default / ALL sweep."],
        "requires": ["-u/--user + -p/-P or --privkeys (a secret that authenticates the account)"],
        "mods": [
            ["-u", "--user", "<username>", "Account to test (required)"],
            ["-p", "--password", "<password>", "Password to log in"],
            ["-P", "--passwords", "<wordlist>", "Passwords to log in"],
            ["", "--privkeys", "<directory>", "Private keys to log in"],
            ["", "--sftp-max-mb", "<n>", "Max MB written in the quota probe (default: 10; cap 200)"],
            ["", "--sftp-max-files", "<n>", "Max files created in the count probe (default: 100; cap 2000)"],
            ["", "--sftp-bomb-mb", "<n>", "Decompressed size of the ZIP-bomb probe (default: 10; cap 200)"],
        ],
    },
    "FORWARD": {
        "desc": "Port forwarding & tunneling capabilities (post-auth)",
        "long": ["Log in with the supplied credentials and probe what the server lets",
                 "an authenticated client tunnel: local forwarding (-L) and dynamic",
                 "SOCKS proxying (-D), remote forwarding (-R), any PermitOpen allow-list,",
                 "GatewayPorts (wildcard remote bind), agent forwarding, X11 forwarding,",
                 "and whether a PTY / interactive shell is granted. Enabled TCP",
                 "forwarding, agent forwarding and X11 forwarding are reported as findings",
                 "(pivoting / agent-hijack / screen-capture surface). Needs valid",
                 "credentials; never runs in the default / ALL sweep."],
        "requires": ["-u/--user (account to test)",
                     "-p/-P or --privkeys (a secret that authenticates the account)"],
        "mods": [
            ["-u", "--user", "<username>", "Account to test (required)"],
            ["-p", "--password", "<password>", "Password to log in"],
            ["-P", "--passwords", "<wordlist>", "Passwords to log in (first that works is used)"],
            ["", "--privkeys", "<directory>", "Private keys to log in"],
        ],
    },
    "LOCKOUT": {
        "desc": "Brute-force protection: account lockout & IP blocking (aggressive)",
        "long": ["Deliberately make failed logins and check whether the server defends",
                 "against password guessing: does it lock the target ACCOUNT, and does",
                 "it block the attacker's IP (fail2ban / firewall)? Aggressive and",
                 "destructive — may lock the account and/or ban this host's IP; runs",
                 "only when named in -ts. Account-lockout needs -p (a VALID password of",
                 "a canary account); IP-blocking needs only -u."],
        "requires": ["-u/--user (target account)",
                     "-p/--password (a VALID password of a canary account) to also test account lockout"],
        "mods": [
            ["-u", "--user", "<username>", "Target account (required)"],
            ["-p", "--password", "<password>", "VALID password of a canary account (enables account-lockout test)"],
            ["", "--lockout-attempts", "<n>", "Failed logins to attempt (default: 8; range 1-100)"],
            ["", "--lockout-cooldown", "<seconds>", "Wait & re-probe to see if a lockout/ban clears (default: 0)"],
        ],
    },
    "USERENUM": {
        "desc": "Username enumeration via auth timing side-channel (aggressive)",
        "long": ["Check whether the server answers differently to valid and invalid",
                 "usernames by timing the authentication phase (CVE-2016-6210 class).",
                 "Calibrates on a KNOWN-VALID login (-u); if that login is timing-",
                 "distinguishable from random names, enumeration is possible and any",
                 "names given in -U are then classified as valid/invalid.",
                 "Aggressive — makes repeated failed logins; runs only when named in -ts."],
        "requires": ["-u/--user (a KNOWN-VALID login used to calibrate the timing oracle)",
                     "-U/--users (optional list of usernames to enumerate once calibrated)"],
        "mods": [
            ["-u", "--user", "<username>", "Known-valid login for calibration (required)"],
            ["-U", "--users", "<wordlist>", "Usernames to enumerate once enumeration is confirmed"],
            ["", "--enum-samples", "<n>", "Timing samples per username (default: 5; range 3-50)"],
            ["", "--enum-baseline", "<n>", "Random invalid names for the baseline (default: 5; range 2-25)"],
            ["", "--enum-sigma", "<f>", "Separation threshold in std devs (default: 3.0)"],
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
    "RATELIMIT": {
        "desc": "Connection rate-limiting test (aggressive)",
        "long": ["Detect whether connection rate limiting is deployed, how many",
                 "concurrent connections can be held, the connect/disconnect rate,",
                 "and how long an idle connection survives (sshd MaxStartups /",
                 "LoginGraceTime). Active load test — runs only when named in -ts,",
                 "never in the default/ALL sweep."],
        "mods": [
            ["", "--rate-count", "<n>", "Connections per scenario (default: 30)"],
            ["", "--rate-concurrency", "<n>", "Parallel connections (default: 10)"],
            ["", "--rate-timeout", "<seconds>", "Per-connection timeout (default: 5)"],
            ["", "--rate-hold-seconds", "<seconds>", "Hold time in concurrency check (default: 2)"],
            ["", "--rate-cooldown-seconds", "<seconds>", "Recovery delay after burst (default: 3)"],
            ["", "--rate-idle-max", "<seconds>", "Max wait for idle drop; 0 disables (default: 30)"],
            ["", "--rate-idle-poll", "<seconds>", "Idle liveness poll interval (default: 1)"],
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