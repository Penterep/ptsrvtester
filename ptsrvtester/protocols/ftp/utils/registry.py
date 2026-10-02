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
        "long": ["List commands from HELP, plus the SYST and STAT replies.",
                 "Ordinary commands are ok. Risky or disclosing ones are flagged."],
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
            ["-u", "--user", "<name> …", "Username(s)"],
            ["-U", "--users", "<wordlist>", "Username wordlist"],
            ["-p", "--password", "<password>", "Single password"],
            ["-P", "--passwords", "<wordlist>", "Password wordlist"],
            ["", "--spray", "", "Try one password against all users"],
            ["-t", "--threads", "<n>", "Threads (default: 10)"],
        ],
    },
    "USRENUM": {
        "desc": "Username enumeration (USER + wrong PASS)",
        "long": [
            "Send USER and one wrong password for each name from -u/-U.",
            "Compare the replies. Put one real username in the list so you",
            "can see whether the server answers it differently from names",
            "that do not exist.",
        ],
        "requires": ["-u/--user or -U/--users"],
        "mods": [
            ["-u", "--user", "<name> …", "Candidate username(s)"],
            ["-U", "--users", "<wordlist>", "Username wordlist (required unless -u)"],
            ["-p", "--password", "<str>", "Wrong password for every name (default: PtsrvUEnumWrongPass!77~)"],
            ["", "--user-enum-max", "<n>", "Limit how many names are tested (default: 0 = no limit)"],
            ["-t", "--threads", "<n>", "Threads (default: 1)"],
            ["", "--user-enum-keep-alive", "", "Reuse one connection for all names"],
            ["", "--user-enum-timing", "", "Also compare how long PASS takes"],
        ],
    },
    "ENUMPATH": {
        "desc": "Path / directory dictionary enumeration",
        "long": ["Directory names from -w, file names from --files. Files are tried",
                 "in the login directory and in each directory actually entered."],
        "requires": ["-w/--paths-wordlist or --files", "credentials (-A or -u/-p)"],
        "mods": [
            ["-w", "--paths-wordlist", "<folder>", "Directory names, one per line"],
            ["", "--files", "<file>", "File names to try inside each directory entered"],
            ["", "--depth", "<n>", "Directory levels to walk (default: 1)"],
            ["-t", "--threads", "<n>", "Threads (default: 5)"],
            ["", "--base-path", "<path>", "Start directory for enumeration (default: login CWD)"],
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
            ["", "--pasv-port-audit-samples", "<n>", "Samples (default: 8, min 4)"],
            ["", "--pasv-port-audit-max-span", "<n>", "Max acceptable port span (default: 8192)"],
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
            ["", "--active-audit-low-ports", "<list>", "Data ports <1000 to test (default: 80,443,21)"],
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
        "desc": "Connection limits / idle probes",
        "long": ["Connection-count and idle-time probes; with -u/-p also probes",
                 "parallel logins, post-login idle and PASV allocation."],
        "mods": [
            ["", "--count", "<n>", "Max concurrent connections in ramp-up (default: 100)"],
            ["", "--duration", "<sec>", "How long idle/ban probes wait (default: 300)"],
            ["-t", "--threads", "<n>", "Parallel connect threads (default: 1)"],
            ["-u", "--user", "<name>", "Username for authenticated probes (optional)"],
            ["-p", "--password", "<pass>", "Password for authenticated probes (optional)"],
        ],
    },
    "DOS": {
        "desc": "XML / ZIP processing-resilience (DoS) probes",
        "long": ["Off-by-default STOR probes (Billion Laughs XML + zip bomb) that may",
                 "stress scanners / indexers. Authorized targets only."],
        "requires": ["credentials (-A or -u/-p)"],
        "mods": [
            ["", "--ftp-dos-timeout", "<sec>", "Per-operation socket timeout (default: 30)"],
            ["", "--ftp-dos-large", "", "Large zip bomb, about 1 TiB expanded (isolated labs only)"],
        ],
    },
    "CHROOT": {
        "desc": "User isolation / chroot audit",
        "long": ["Post-login CWD / .. chain probes to check whether the account can",
                 "reach host-style paths (/etc, /root, /home parent)."],
        "requires": ["credentials (-A or -u/-p)"],
        "mods": [],
    },
    "EICAR": {
        "desc": "EICAR antivirus probe (upload + verify)",
        "long": ["Upload the EICAR test file, delay, then SIZE/RETR verification and",
                 "DELE cleanup to check on-access antivirus."],
        "requires": ["credentials (-A or -u/-p)"],
        "mods": [
            ["", "--eicar-post-stor-delay", "<sec>", "Wait after STOR before verify (default: 0.5)"],
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
        desc = [f"FTP — {code}: {spec['desc']}"]
        desc.extend(spec.get("long", []) or [])
        if spec.get("requires"):
            desc.append("Requires: " + "; ".join(spec["requires"]))
        mods = list(spec.get("mods", []) or [])
        has_opts = bool(mods or spec.get("requires"))
        usage = f"ptsrvtester ftp -ts {code} " + ("<options> -tg <target>" if has_opts else "-tg <target>")
        blocks.append({"description": desc})
        blocks.append({"usage": [usage]})
        if mods:
            blocks.append({"options": mods})
    return blocks
