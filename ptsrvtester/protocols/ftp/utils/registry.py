"""FTP -ts registry — help text only (execution is module discovery)."""
from __future__ import annotations

from ptsrvtester.protocols._shared.utils.cli import rate_limit_test_spec

FTP_TEST_GROUPS: list[tuple[str, list[str]]] = [
    ("Recon & fingerprint", ["BANNER", "CMD", "ENCRYPT"]),
    ("Authentication & access", ["ANON", "ACCESS", "BRUTE", "USRENUM"]),
    ("Enumeration", ["ENUMPATH"]),
    ("Data channel & modes", ["MODES", "PASVPORT", "ACTIVE", "ACTIVEFULL"]),
    ("Command surface & validation", ["CMDAUDIT", "CMDAUDITACTIVE", "INVCMD"]),
    ("Rate limiting & stress", ["CONNLIM", "DOS"]),
    ("Access control", ["CHROOT"]),
    ("Content security", ["EICAR"]),
    ("Connection rate limiting (aggressive)", ["RATELIMIT"]),
]

FTP_DEFAULT_SUITE: tuple[str, ...] = ("BANNER", "CMD", "ANON")

FTP_TESTS: dict[str, dict] = {
    "BANNER": {
        "desc": "Grab banner and service identification",
        "long": ["Connect and read the greeting banner, then identify the product,",
                 "version and CPE from the advertised software string."],
    },
    "CMD": {
        "desc": "Grab HELP / SYST / STAT",
        "long": ["Inspect the HELP, SYST and STAT command responses for software",
                 "and configuration information disclosure."],
    },
    "ENCRYPT": {
        "desc": "Test encryption options (plaintext / AUTH TLS / implicit TLS)",
        "long": ["Inspect supported transport encryption: cleartext control channel,",
                 "explicit AUTH TLS (FTPS) and implicit TLS."],
    },
    "ANON": {
        "desc": "Check anonymous authentication",
        "long": ["Attempt anonymous / guest login to detect servers that accept",
                 "unauthenticated access."],
    },
    "ACCESS": {
        "desc": "Read/write access check (listing, bounce)",
        "long": ["Check read/write access using anonymous or supplied credentials;",
                 "optional directory listing and FTP bounce attack."],
        "requires": ["-A/--anonymous or -u/-p (credentials)"],
        "mods": [
            ["-l", "--access-list", "", "Display root directory listing"],
            ["-B", "--bounce", "<ip:port>", "FTP bounce attack to given service"],
            ["", "--bounce-file", "<file>", "File with request to send in bounce"],
        ],
    },
    "BRUTE": {
        "desc": "Login bruteforce (USER/PASS)",
        "long": ["Bruteforce FTP login with the supplied username(s) and",
                 "password(s)."],
        "requires": ["-u/--user or -U/--users", "-p/--password or -P/--passwords"],
        "mods": [
            ["-u", "--user", "<name>", "Single username"],
            ["-U", "--users", "<wordlist>", "Username wordlist"],
            ["-p", "--password", "<password>", "Single password"],
            ["-P", "--passwords", "<wordlist>", "Password wordlist"],
        ],
    },
    "USRENUM": {
        "desc": "Username enumeration (USER + wrong PASS)",
        "long": ["USER then a fixed wrong password; compare distinct replies / timing",
                 "against controls (RFC 2577 user enumeration)."],
        "requires": ["--user-enum-wordlist <file>"],
        "mods": [
            ["", "--user-enum-wordlist", "<file>", "Usernames to test (required)"],
            ["", "--user-enum-password", "<str>", "Fixed wrong password after 331/332"],
            ["", "--user-enum-keep-alive", "", "Reuse one TCP session for all probes"],
            ["", "--user-enum-timing", "", "Compare median PASS-phase latency"],
            ["", "--user-enum-threads", "<n>", "Parallel connections (default 1)"],
            ["", "--user-enum-max", "<n>", "Cap wordlist size (0 = no limit)"],
        ],
    },
    "ENUMPATH": {
        "desc": "Path / directory dictionary enumeration",
        "long": ["Dictionary attack for discovering files and directories using",
                 "supplied credentials (anonymous or -u/-p)."],
        "requires": ["-w/--paths-wordlist <file>", "credentials (-A or -u/-p)"],
        "mods": [
            ["-w", "--paths-wordlist", "<file>", "Paths to test, one per line (required)"],
            ["", "--enum-threads", "<n>", "Threads for enumeration (default 5)"],
            ["", "--base-path", "<path>", "Start directory for enumeration"],
        ],
    },
    "MODES": {
        "desc": "Passive/active data modes + PASV IP leak",
        "long": ["Test passive and active data mode availability and detect PASV",
                 "IP address leakage."],
        "requires": ["credentials (-A or -u/-p)"],
    },
    "PASVPORT": {
        "desc": "Passive data port spread audit",
        "long": ["Repeated passive LIST transfers to check whether data ports stay",
                 "in a narrow, predictable range."],
        "requires": ["credentials (-A or -u/-p)"],
        "mods": [
            ["", "--pasv-port-audit-samples", "<n>", "Samples (default 8, min 4)"],
            ["", "--pasv-port-audit-max-span", "<n>", "Max acceptable port span (default 8192)"],
        ],
    },
    "ACTIVE": {
        "desc": "Quick PORT/PASV policy audit",
        "long": ["Quick active-mode policy audit of PORT / PASV command handling."],
    },
    "ACTIVEFULL": {
        "desc": "Full active-mode methodology",
        "long": ["Full methodology: isolated sessions, raw LIST (D0), PORT+LIST and",
                 "low-port hints. More thorough but noisier than ACTIVE."],
        "mods": [
            ["", "--active-audit-low-ports", "<list>", "Data ports <1000 to test (default 80,443,21)"],
        ],
    },
    "CMDAUDIT": {
        "desc": "HELP / FEAT / SITE command surface",
        "long": ["Audit HELP, FEAT and SITE HELP/ALL; flag high-risk SITE",
                 "extensions (passive, no login required)."],
    },
    "CMDAUDITACTIVE": {
        "desc": "Safe SITE probes post-login",
        "long": ["After the passive command audit, log in and send safe SITE probes",
                 "(timeouts, DELE cleanup, 530 vs 550)."],
        "requires": ["credentials (-A or -u/-p)"],
    },
    "INVCMD": {
        "desc": "Invalid command resilience",
        "long": ["Send raw / malformed control lines (incl. embedded NUL) and rate",
                 "the server's resilience."],
    },
    "CONNLIM": {
        "desc": "Connection / rate / idle / PASV limits",
        "long": ["Bounded probes for concurrent sessions, rapid sequential connects,",
                 "PASV spam and optional idle / slow-auth behaviour."],
        "mods": [
            ["", "--conn-limits-parallel", "<n>", "Simultaneous pre-auth sessions (default 12, max 40)"],
            ["", "--conn-limits-sequential", "<n>", "Rapid sequential connects (default 24, max 80)"],
            ["", "--conn-limits-pasv-attempts", "<n>", "PASV spam per session (default 18, max 60)"],
            ["", "--conn-limits-idle-pre-auth", "<s>", "Pre-login idle seconds (0 = skip)"],
            ["", "--conn-limits-slow-auth-gap", "<s>", "Seconds between USER and PASS (0 = skip)"],
            ["", "--conn-limits-idle-post-auth", "<s>", "Post-login idle seconds (0 = skip; needs creds)"],
        ],
    },
    "DOS": {
        "desc": "XML / ZIP processing-resilience (DoS) probes",
        "long": ["Off-by-default STOR probes (Billion Laughs XML + zip bomb) that may",
                 "stress scanners / indexers. Authorized targets only."],
        "requires": ["credentials (-A or -u/-p)"],
        "mods": [
            ["", "--ftp-dos-timeout", "<sec>", "Per-operation socket timeout (default 30)"],
            ["", "--ftp-dos-force-large", "", "Use full zip bomb (isolated labs only)"],
        ],
    },
    "CHROOT": {
        "desc": "User isolation / chroot audit",
        "long": ["Post-login CWD / .. chain probes to check whether the account can",
                 "reach host-style paths (/etc, /root, /home parent)."],
        "requires": ["credentials (-A or -u/-p)"],
        "mods": [
            ["", "--chroot-audit-paths", "<list>", "Extra comma-separated absolute paths"],
        ],
    },
    "EICAR": {
        "desc": "EICAR antivirus probe (upload + verify)",
        "long": ["Upload the EICAR test file, delay, then SIZE/RETR verification and",
                 "DELE cleanup to check on-access antivirus."],
        "requires": ["credentials (-A or -u/-p)"],
        "mods": [
            ["", "--eicar-post-stor-delay", "<sec>", "Wait after STOR before verify (default 0.5)"],
        ],
    },
    "RATELIMIT": rate_limit_test_spec(),
}


def ftp_test_help(codes: list[str]):
    if not codes:
        return None
    valid = [c for c in codes if c in FTP_TESTS]
    if not valid:
        available = ", ".join(FTP_TESTS)
        return [{"unknown_test": [f"Unknown test: {', '.join(codes)}. Available: ALL, {available}"]}]
    blocks = []
    for code in valid:
        spec = FTP_TESTS[code]
        options: list[list[str]] = []
        for line in spec.get("long", []) or []:
            options.append(["", "", "", line])
        if spec.get("requires"):
            options.append(["", "", "", ""])
            options.append(["", "", "", "Requires: " + "; ".join(spec["requires"])])
        for row in spec.get("mods", []) or []:
            options.append(row)
        has_opts = bool(spec.get("mods") or spec.get("requires"))
        usage = f"ptsrvtester ftp -ts {code} " + ("<options> -tg <target>" if has_opts else "-tg <target>")
        blocks.append({"description": [f"FTP — {code}: {spec['desc']}"]})
        blocks.append({"usage": [usage]})
        if options:
            blocks.append({"options": options})
    return blocks
