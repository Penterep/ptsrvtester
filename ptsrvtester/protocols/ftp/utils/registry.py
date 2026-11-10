"""FTP -ts registry — help text only (execution is module discovery)."""
from __future__ import annotations

from ptsrvtester.protocols._shared.utils.cli import rate_limit_test_spec

FTP_TEST_GROUPS: list[tuple[str, list[str]]] = [
    ("Recon & fingerprint", ["BANNER", "CMD", "ENCRYPT"]),
    ("Authentication & access", ["ANON", "ACCESS", "BRUTE", "WEAK", "RECYKL", "USRENUM"]),
    ("Enumeration", ["ENUMPATH"]),
    ("Data channel & modes", ["MODES", "PASVPORT", "ACTIVE", "ACTIVEFULL"]),
    ("Command surface & validation", ["CMDAUDITACTIVE", "INVCMD"]),
    ("Rate limiting & stress", ["CONNLIM", "RATELIMIT"]),
    ("Access control", ["CHROOT"]),
    ("Content security", ["EICAR", "DOS"]),
]

FTP_DEFAULT_SUITE: tuple[str, ...] = ("BANNER", "CMD", "ANON")

FTP_TESTS: dict[str, dict] = {
    "BANNER": {
        "desc": "Grab banner and service identification",
        "long": ["Connect and read the greeting banner, then identify the product,",
                 "version and CPE from the advertised software string."],
    },
    "CMD": {
        "desc": "Grab HELP / SYST / STAT and SITE extensions",
        "long": ["List commands from HELP, plus the SYST and STAT replies.",
                 "A 530 reply means login is required, not that the command is missing.",
                 "With -A or -u/-p, read the list again after login.",
                 "When SITE is advertised, list the extensions from SITE HELP.",
                 "SITE CHMOD, CHOWN, CPFR/CPTO, SYMLINK and UMASK use their own codes.",
                 "SITE EXEC is a finding only when command execution is shown.",
                 "Other warning commands are reported as PTV-SVC-FTP-CMD."],
        "mods": [
            ["-A", "--anonymous", "", "Also read the command list after anonymous login"],
            ["-u", "--user", "<name>", "Also read the command list after this login"],
            ["-p", "--password", "[password]", "Password"],
        ],
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
        "desc": "Blocking of a guessing attack",
        "long": ["Try FTP USER/PASS guesses and see whether the server stops them.",
                 "Without -u/-U or -p/-P, built-in lists are used.",
                 "No lockout is PTV-SVC-AUTH-BRUTE."],
        "mods": [
            ["-u", "--user", "<name> …", "Username(s). Default: root, admin, demo, test, user, jane, john"],
            ["-U", "--users", "<wordlist>", "Username wordlist"],
            ["-p", "--password", "[password] …", "Password(s). Default: pass, pass123, Pass123, password, Pa$$w0rd, abcd, abcde, abcdef, 0000, 1234, 12345, 123456, Admin123, test, root, admin"],
            ["-P", "--passwords", "<wordlist>", "Password wordlist"],
            ["", "--spray", "", "Try one password against all users"],
            ["-t", "--threads", "<n>", "Threads (default: 10)"],
        ],
    },
    "WEAK": {
        "desc": "Find credentials with the default wordlist",
        "long": ["Same USER/PASS guesses as BRUTE. Without -u/-U or -p/-P, built-in lists are used.",
                 "A valid login is PTV-SVC-AUTH-WEAK."],
        "mods": [
            ["-u", "--user", "<name> …", "Username(s). Default: root, admin, demo, test, user, jane, john"],
            ["-U", "--users", "<wordlist>", "Username wordlist"],
            ["-p", "--password", "[password] …", "Password(s). Default: pass, pass123, Pass123, password, Pa$$w0rd, abcd, abcde, abcdef, 0000, 1234, 12345, 123456, Admin123, test, root, admin"],
            ["-P", "--passwords", "<wordlist>", "Password wordlist"],
            ["", "--spray", "", "Try one password against all users"],
            ["-t", "--threads", "<n>", "Threads (default: 10)"],
        ],
    },
    "RECYKL": {
        "desc": "Find credentials (same probe as WEAK)",
        "long": ["Alias of WEAK. The probe is the same, including the built-in lists.",
                 "A valid login is PTV-SVC-AUTH-RECYKL."],
        "mods": [
            ["-u", "--user", "<name> …", "Username(s). Default: root, admin, demo, test, user, jane, john"],
            ["-U", "--users", "<wordlist>", "Username wordlist"],
            ["-p", "--password", "[password] …", "Password(s). Default: pass, pass123, Pass123, password, Pa$$w0rd, abcd, abcde, abcdef, 0000, 1234, 12345, 123456, Admin123, test, root, admin"],
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
        "long": ["Before login, check whether PASV, EPSV, PORT and EPRT are accepted.",
                 "With -A or -u/-p, repeat them after login and try one data transfer.",
                 "A 227 or 200 reply means the command is supported, not that data was transferred."],
        "mods": [
            ["-A", "--anonymous", "", "Also repeat the commands after anonymous login"],
            ["-u", "--user", "<name>", "Also repeat the commands after this login"],
            ["-p", "--password", "[password]", "Password"],
        ],
    },
    "PASVPORT": {
        "desc": "Passive data port spread audit",
        "long": ["Read the data port from PASV 227 and EPSV 229, before login.",
                 "With -A or -u/-p, repeat after login. A 530 reply assigns no port.",
                 "LIST is not required to measure the range."],
        "mods": [
            ["-A", "--anonymous", "", "Also measure the range after anonymous login"],
            ["-u", "--user", "<name>", "Also measure the range after this login"],
            ["-p", "--password", "[password]", "Password"],
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
            ["", "--ftp-dos-large", "", "Large zip bomb, about 1 TB expanded (isolated labs only)"],
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

# Login is required (-A or -u/-p). Shown in Options, not only in Requires.
_FTP_CRED_TESTS = frozenset({
    "ACCESS", "ENUMPATH", "CMDAUDITACTIVE", "DOS", "CHROOT", "EICAR",
})
_FTP_LOGIN_OPTS = (
    ["-A", "--anonymous", "", "Anonymous login"],
    ["-u", "--user", "<name>", "Username"],
    ["-p", "--password", "[password]", "Password"],
)


def _append_missing_opts(mods: list, rows: tuple) -> None:
    for row in rows:
        if not any(len(existing) > 1 and existing[1] == row[1] for existing in mods):
            mods.append(list(row))


def _option_rows(rows: list) -> list:
    """Drop the empty short-flag column when a test has none."""
    if not rows or not all(isinstance(row, list) and len(row) >= 4 for row in rows):
        return rows
    if any(row[0] for row in rows):
        return rows
    return [row[1:] for row in rows]


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
        if code in _FTP_CRED_TESTS:
            _append_missing_opts(mods, _FTP_LOGIN_OPTS)
        elif code == "CONNLIM":
            if not any(len(row) > 1 and row[1] == "--anonymous" for row in mods):
                at = next(
                    (i for i, row in enumerate(mods) if len(row) > 1 and row[1] == "--user"),
                    len(mods),
                )
                mods.insert(at, ["-A", "--anonymous", "", "Anonymous login"])
        mods = _option_rows(mods)
        has_opts = bool(mods or spec.get("requires"))
        usage = f"ptsrvtester ftp -ts {code} " + ("<options> -tg <target>" if has_opts else "-tg <target>")
        blocks.append({"description": desc})
        if mods:
            blocks.append({"options": mods})
        blocks.append({"usage": [usage]})
    return blocks
