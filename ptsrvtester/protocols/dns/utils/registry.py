"""The ``-ts/--tests`` registry for DNS: single source of truth for help text.

Selection itself is handled generically by :class:`BaseMain` (it matches ``-ts``
codes against each module's ``__MODULECODE__``). This registry only feeds the
help tables: the main ``dns -h`` test list and per-test ``dns -ts <TEST> -h``.
Keep every code here in sync with a module's ``__MODULECODE__``. Mirrors
``ssh/utils/registry.py``.

Empty skeleton: no DNS modules are defined yet. When a module is added under
``dns/modules/``, register it here so it shows up in the help. Entry format::

    DNS_TEST_GROUPS = [
        ("Group title", ["MYCODE"]),
    ]
    DNS_TESTS = {
        "MYCODE": {
            "desc": "one-line description (shown in `dns -h`)",
            "long": ["longer explanation", "wrapped across lines (for `-ts MYCODE -h`)"],
            "requires": ["-x/--flag (what it needs)"],          # optional
            "mods": [["-x", "--flag", "<val>", "help text"]],    # optional per-test options
        },
    }
"""

DNS_TEST_GROUPS: list[tuple[str, list[str]]] = [
    ("Recon & fingerprint", ["VERSION", "NSID", "TRANSPORT", "EDNS", "ROLE", "CVE"]),
]

DNS_TESTS: dict[str, dict] = {
    "VERSION": {
        "desc": "Software/build disclosure via CHAOS TXT",
        "long": ["Query version.bind, hostname.bind, id.server and authors.bind",
                 "(class CHAOS). A server that answers leaks its software and often",
                 "the exact build/OS (PTV-DNS-VERSIONDISCLOSURE)."],
        "requires": ["-tg/--target (the DNS server to query)"],
        "mods": [["-tg", "--target", "<server>", "DNS server IP[:PORT] to query"]],
    },
    "NSID": {
        "desc": "Server instance identity via NSID (RFC 5001)",
        "long": ["Send an empty EDNS NSID option; a server that echoes one reveals",
                 "which specific instance answered behind anycast/load balancing",
                 "(PTV-DNS-NSID)."],
        "requires": ["-tg/--target"],
        "mods": [["-tg", "--target", "<server>", "DNS server IP[:PORT] to query"]],
    },
    "TRANSPORT": {
        "desc": "Supported transports (UDP/TCP/DoT/DoH/DoQ)",
        "long": ["Probe UDP/53, TCP/53, DoT/853, DoH/443 and DoQ/853 with a benign",
                 "query and report which the server accepts. Informational; DoQ needs",
                 "the optional aioquic package to be tested."],
        "requires": ["-tg/--target"],
        "mods": [["-tg", "--target", "<server>", "DNS server IP[:PORT] to query"]],
    },
    "EDNS": {
        "desc": "EDNS(0) support, UDP payload & DNS cookies",
        "long": ["Send an EDNS(0) query with a client cookie and read the OPT back:",
                 "EDNS support, advertised UDP payload size (large = more",
                 "amplification/fragmentation surface) and DNS cookie support",
                 "(RFC 7873). Informational."],
        "requires": ["-tg/--target"],
        "mods": [["-tg", "--target", "<server>", "DNS server IP[:PORT] to query"]],
    },
    "ROLE": {
        "desc": "Authoritative / recursive / forwarder",
        "long": ["Send a recursive (RD=1) query for an external name and read the",
                 "RA/AA flags and answer. Recursion offered to an arbitrary client",
                 "(open resolver) is a finding — DNS amplification abuse",
                 "(PTV-DNS-OPENRECURSION). A recursive resolver vs a forwarder cannot",
                 "be reliably distinguished remotely."],
        "requires": ["-tg/--target"],
        "mods": [["-tg", "--target", "<server>", "DNS server IP[:PORT] to query"]],
    },
    "CVE": {
        "desc": "Known-CVE match for the advertised version",
        "long": ["Identify the product/version from version.bind (BIND / Unbound /",
                 "PowerDNS / Knot / dnsmasq / Windows DNS) and match it against a seed",
                 "table of well-known CVEs (PTV-DNS-KNOWNCVE). INDICATIVE only: trusts",
                 "the advertised banner (which may be hidden/spoofed) and the table is",
                 "not exhaustive; confirm every match manually."],
        "requires": ["-tg/--target"],
        "mods": [["-tg", "--target", "<server>", "DNS server IP[:PORT] to query"]],
    },
}


def dns_test_help(codes: list[str]):
    """Build a help object (for ``ptprinthelper.help_print``) for the given test codes."""
    if not codes:
        return None
    valid = [c for c in codes if c in DNS_TESTS]
    if not valid:
        available = ", ".join(sorted(DNS_TESTS)) or "(none defined yet)"
        return [
            {"unknown_test": [f"Unknown test: {', '.join(codes)}"]},
            {"available_tests": [f"ALL, {available}"]},
        ]
    out: list[dict] = []
    for code in valid:
        spec = DNS_TESTS[code]
        out.append({"test": [f"{code} — {spec.get('desc', '')}", *spec.get("long", [])]})
        req = list(spec.get("requires", []))
        if req:
            out.append({"requires": req})
        rows = list(spec.get("mods", []))
        if rows:
            out.append({"test_options": rows})
        has_opts = bool(rows or req)
        usage = f"ptsrvtester dns -ts {code} " + ("<options>" if has_opts else "<target>")
        out.append({"usage": [usage]})
    return out
