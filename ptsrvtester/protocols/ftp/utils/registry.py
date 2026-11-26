"""FTP -ts registry — help text only (execution is module discovery)."""
from __future__ import annotations

from ptsrvtester.protocols._shared.utils.cli import rate_limit_test_spec

FTP_TEST_GROUPS: list[tuple[str, list[str]]] = [
    ("Recon & fingerprint", ["BANNER", "CMD", "ENCRYPT"]),
    ("Authentication & access", ["ANON", "ACCESS", "BRUTE", "WEAK", "RECYKL", "USRENUM"]),
    ("Enumeration", ["FILEENUM"]),
    ("Data channel & modes", ["MODES", "PASVPORT", "ACTIVE", "ACTIVEFULL"]),
    ("Command surface & validation", ["CMDAUDITACTIVE", "INVCMD"]),
    ("Rate limiting & stress", ["CONNLIM", "RATELIMIT"]),
    ("Access control", ["CHROOT"]),
    ("Content security", ["EICAR", "ZIPXXE"]),
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
        "desc": "Directory list, read, write and delete check",
        "long": ["Test listing, reading, writing and deleting in --path (default /).",
                 "With --recursive, the same checks run in nested directories",
                 "down to --depth (default 1). The folder contents are listed.",
                 "The test also tries to create a directory and to rename the folder.",
                 "An existing file or the folder itself is deleted only with --delete.",
                 "A file created by the test is always deleted.",
                 "If the listing is refused, -f names the file to test.",
                 "Anonymous read, write or delete is PTV-SVC-FTP-ANONACCESS.",
                 "Write by an authenticated user is PTV-SVC-FTP-WRITE."],
        "requires": ["-A/--anonymous or -u/-p (credentials)"],
        "mods": [
            ["", "--path", "<dir>", "Directory to test (default: /)"],
            ["", "--recursive", "", "Also test nested directories"],
            ["", "--depth", "<n>", "How deep --recursive descends (default: 1)"],
            ["", "--delete", "", "Also delete an existing file and the tested directory"],
            ["-f", "--file", "<name>", "Remote file name when the directory listing is refused"],
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
    "FILEENUM": {
        "desc": "File and directory enumeration",
        "long": ["Try each name from -w with the suffixes from --extension.",
                 "A suffix without a dot gets one. An empty suffix tries the name as a directory.",
                 "With --recurse, the same names are tried inside each directory that is found,",
                 "down to --depth (default: 5)."],
        "requires": ["-w/--wordlist", "credentials (-A or -u/-p)"],
        "mods": [
            ["-w", "--wordlist", "<file>", "Names to try, one per line"],
            ["", "--extension", "<ext> …", "Suffixes, comma or space separated. \"\" tries a directory"],
            ["", "--recurse", "", "Search inside directories that are found"],
            ["", "--depth", "<n>", "How deep --recurse descends (default: 5)"],
            ["-t", "--threads", "<n>", "Threads (default: 5)"],
            ["", "--base-path", "<path>", "Start directory (default: login directory)"],
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
                 "LIST is not required. Span ≤ 200 is limited, 201-500 is wide,",
                 "and a span above 500 is not limited."],
        "mods": [
            ["-c", "--count", "<n>", "Sessions to sample (default: 20)"],
            ["-A", "--anonymous", "", "Also measure the range after anonymous login"],
            ["-u", "--user", "<name>", "Also measure the range after this login"],
            ["-p", "--password", "[password]", "Password"],
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
            ["-c", "--count", "<n>", "Max concurrent connections in ramp-up (default: 100)"],
            ["", "--duration", "<sec>", "How long idle/ban probes wait (default: 300)"],
            ["-t", "--threads", "<n>", "Parallel connect threads (default: 1)"],
            ["-u", "--user", "<name>", "Username for authenticated probes (optional)"],
            ["-p", "--password", "<pass>", "Password for authenticated probes (optional)"],
        ],
    },
    "ZIPXXE": {
        "desc": "XML / ZIP processing-resilience probes",
        "long": ["Check that a small text file can be uploaded into --path, then",
                 "upload a Billion Laughs XML file. A zip bomb is uploaded only",
                 "when its size switch is set. With --delete, the uploaded files",
                 "are removed after --delay."],
        "requires": ["credentials (-A or -u/-p)"],
        "mods": [
            ["", "--path", "<dir>", "Directory to upload into (default: /)"],
            ["", "--timeout", "<sec>", "Per-operation socket timeout (default: 30)"],
            ["", "--delay", "<sec>", "Wait after all uploads before deleting them (default: 30). Used only with --delete"],
            ["", "--delete", "", "Delete the uploaded files after --delay"],
            ["", "--zipxxe-zip-bomb-small", "", "Also upload the small zip bomb (~200 KB expanded)"],
            ["", "--zipxxe-zip-bomb-medium", "", "Also upload the medium zip bomb (~100 MB expanded)"],
            ["", "--zipxxe-zip-bomb-large", "", "Also upload the large zip bomb (~1 TB expanded, isolated labs)"],
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
        "long": ["Check that a small text file can be uploaded into --path, then",
                 "store the EICAR files. After --delay, a finding is reported only",
                 "when the same bytes can still be downloaded."],
        "requires": ["credentials (-A or -u/-p)"],
        "mods": [
            ["", "--path", "<dir>", "Directory to upload into (default: /)"],
            ["", "--delay", "<sec>", "Wait after upload before checking the file (default: 1)"],
            ["", "--delete", "", "Delete the uploaded EICAR files afterwards"],
        ],
    },
    "RATELIMIT": rate_limit_test_spec(),
}

# Login is required (-A or -u/-p). Shown in Options, not only in Requires.
_FTP_CRED_TESTS = frozenset({
    "ACCESS", "FILEENUM", "CMDAUDITACTIVE", "ZIPXXE", "CHROOT", "EICAR",
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
