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
    ("Record enumeration", ["RECORDS", "PTRSWEEP", "WHOIS", "BRUTESUB", "EMAILSEC", "CAA", "WILDCARD"]),
    ("Zone transfer", ["AXFR", "IXFR"]),
    ("Recursion & resolver abuse", ["RECURSION", "AMPLIFICATION", "CACHESNOOP"]),
    ("Cache-poisoning resilience", ["COOKIES"]),
    ("DNSSEC", ["DNSSEC", "DNSSECALG", "RRSIG", "CHAIN", "NSEC"]),
    ("Zone walking", ["ZONEWALK", "NSEC3CRACK"]),
    ("Amplification / DoS", ["AMPFACTOR", "RRL", "TCPFALLBACK"]),
    ("Dynamic update (write)", ["DYNUPDATE", "TSIGUPDATE", "GSSTSIG"]),
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
                 "RA/AA flags and answer to classify the server's role. Informational:",
                 "the open-recursion finding and its abuse are owned by the RECURSION /",
                 "AMPLIFICATION tests. A recursive resolver vs a forwarder cannot be",
                 "reliably distinguished remotely."],
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
    "RECORDS": {
        "desc": "Enumerate DNS records (A/AAAA/MX/TXT/CNAME/NS/SRV/SOA)",
        "long": ["Resolve common record types for each domain and list the values.",
                 "Restrict the types with -rec. Informational."],
        "requires": ["-d/--domain or -dl/--domain-file"],
        "mods": [
            ["-d", "--domain", "<domain>", "Domain to query"],
            ["-dl", "--domain-file", "<file>", "File with domains"],
            ["-rec", "--records", "<type...>", "Record types (default: A AAAA MX TXT CNAME NS SRV SOA)"],
        ],
    },
    "PTRSWEEP": {
        "desc": "Reverse DNS / PTR sweep of an address range",
        "long": ["Reverse-resolve every address in a range (single IP, CIDR, or",
                 "start-end) to reveal internal naming and live hosts. Active — one",
                 "query per address, capped at 1024; only when named in -ts."],
        "requires": ["-r/--range <IP | CIDR | start-end>"],
        "mods": [
            ["-r", "--range", "<range>", "IP, CIDR (192.0.2.0/24) or start-end (192.0.2.1-50)"],
            ["", "--brute-threads", "<n>", "Parallel PTR lookups (default: 10)"],
        ],
    },
    "WHOIS": {
        "desc": "WHOIS registration data",
        "long": ["Fetch the WHOIS registration record for each domain (registrar,",
                 "dates, name servers, contacts where not redacted). Informational."],
        "requires": ["-d/--domain or -dl/--domain-file"],
        "mods": [
            ["-d", "--domain", "<domain>", "Domain to query"],
            ["-dl", "--domain-file", "<file>", "File with domains"],
        ],
    },
    "BRUTESUB": {
        "desc": "Subdomain brute-force enumeration",
        "long": ["Resolve <label>.<domain> for each label in the wordlist. Detects a",
                 "wildcard first and filters wildcard-matching hits so catch-all zones",
                 "do not create false positives (PTV-DNS-SUBDOMAINS). Active — only",
                 "when named in -ts."],
        "requires": ["-d/--domain (or -dl)", "-sub/--subdomains <wordlist>"],
        "mods": [
            ["-d", "--domain", "<domain>", "Base domain"],
            ["-sub", "--subdomains", "<wordlist>", "File with subdomain labels"],
            ["", "--brute-threads", "<n>", "Parallel lookups (default: 10)"],
        ],
    },
    "EMAILSEC": {
        "desc": "Email security records (SPF/DKIM/DMARC)",
        "long": ["Check SPF (TXT), DMARC (_dmarc TXT) and DKIM (common selectors).",
                 "Missing SPF (PTV-DNS-SPFMISSING), permissive SPF +all",
                 "(PTV-DNS-SPFWEAK), missing DMARC (PTV-DNS-DMARCMISSING) and DMARC",
                 "p=none (PTV-DNS-DMARCWEAK) are reported — they enable e-mail",
                 "spoofing. DKIM is selector-dependent, so absence is informational."],
        "requires": ["-d/--domain or -dl/--domain-file"],
        "mods": [
            ["-d", "--domain", "<domain>", "Domain to check"],
            ["-dl", "--domain-file", "<file>", "File with domains"],
            ["", "--dkim-selectors", "<sel...>", "DKIM selectors to try (default: common list)"],
        ],
    },
    "CAA": {
        "desc": "CAA records (certificate issuance control)",
        "long": ["Check whether the domain publishes CAA records. Missing CAA lets any",
                 "public CA issue certificates (PTV-DNS-CAAMISSING). CAA can be",
                 "inherited from a parent zone, which this per-domain check does not",
                 "climb."],
        "requires": ["-d/--domain or -dl/--domain-file"],
        "mods": [
            ["-d", "--domain", "<domain>", "Domain to check"],
            ["-dl", "--domain-file", "<file>", "File with domains"],
        ],
    },
    "WILDCARD": {
        "desc": "Wildcard record detection",
        "long": ["Query random non-existent labels; if they resolve, the zone has a",
                 "wildcard (*) record that masks subdomain enumeration and can hide",
                 "catch-all behaviour (PTV-DNS-WILDCARD)."],
        "requires": ["-d/--domain or -dl/--domain-file"],
        "mods": [
            ["-d", "--domain", "<domain>", "Domain to check"],
            ["-dl", "--domain-file", "<file>", "File with domains"],
        ],
    },
    "AXFR": {
        "desc": "Full zone transfer (AXFR) over TCP",
        "long": ["Discover the domain's authoritative name servers and attempt a full",
                 "AXFR against every one over TCP — primaries and secondaries alike. A",
                 "server that answers leaks the entire zone (PTV-DNS-ZONETRANSFER).",
                 "Trying every NS also catches a misconfigured secondary that allows",
                 "AXFR when the primary refuses. With -tg, that server is tried too."],
        "requires": ["-d/--domain (or -dl)", "optional -tg to also try a specific server"],
        "mods": [
            ["-d", "--domain", "<domain>", "Zone whose name servers are tried"],
            ["-dl", "--domain-file", "<file>", "File with domains"],
            ["-tg", "--target", "<server>", "Also try AXFR against this server directly"],
        ],
    },
    "IXFR": {
        "desc": "Incremental zone transfer (IXFR) over TCP",
        "long": ["Ask each authoritative name server for an incremental transfer",
                 "(changes since serial-1). A non-refused reply leaks zone data",
                 "(PTV-DNS-IXFR); per RFC 1995 the server may answer with a true",
                 "incremental delta or a full AXFR-style fallback — the module reports",
                 "which. With -tg, that server is tried too."],
        "requires": ["-d/--domain (or -dl)", "optional -tg to also try a specific server"],
        "mods": [
            ["-d", "--domain", "<domain>", "Zone whose name servers are tried"],
            ["-dl", "--domain-file", "<file>", "File with domains"],
            ["-tg", "--target", "<server>", "Also try IXFR against this server directly"],
        ],
    },
    "RECURSION": {
        "desc": "Open recursion for external clients",
        "long": ["Send RD=1 queries for names the server is not authoritative for. If",
                 "it sets RA and answers, it is an open resolver that recurses for any",
                 "external client (PTV-DNS-OPENRECURSION) — a cache-poisoning and",
                 "reflection surface."],
        "requires": ["-tg/--target (the server to test)"],
        "mods": [["-tg", "--target", "<server>", "DNS server IP[:PORT] to test"]],
    },
    "AMPLIFICATION": {
        "desc": "Reflection / amplification potential (out-of-zone recursion)",
        "long": ["Send small RD=1 queries for out-of-zone names that yield large",
                 "answers (TXT/DNSKEY/ANY) and measure the response-to-query ratio. A",
                 "large factor on an open resolver means it can be abused as a DDoS",
                 "reflector/amplifier (PTV-DNS-AMPLIFICATION)."],
        "requires": ["-tg/--target"],
        "mods": [["-tg", "--target", "<server>", "DNS server IP[:PORT] to test"]],
    },
    "CACHESNOOP": {
        "desc": "Cache snooping via non-recursive (RD=0) queries",
        "long": ["Send RD=0 queries for popular names. A server that answers from cache",
                 "reveals what its clients recently looked up (PTV-DNS-CACHESNOOP), an",
                 "information leak about user behaviour; the remaining TTL hints at how",
                 "recently."],
        "requires": ["-tg/--target"],
        "mods": [["-tg", "--target", "<server>", "DNS server IP[:PORT] to test"]],
    },
    "COOKIES": {
        "desc": "DNS cookies (RFC 7873)",
        "long": ["Sends a client cookie and checks for a returned server cookie. DNS",
                 "cookies harden against off-path spoofing/amplification; absence →",
                 "PTV-DNS-NOCOOKIE. Observes the client-facing side only (upstream",
                 "cookie use is separate).",
                 "",
                 "Note: source-port randomization, TXID entropy, 0x20 and",
                 "out-of-bailiwick acceptance need an authoritative probe server to",
                 "measure and are deferred to a future implementation."],
        "requires": ["-tg/--target"],
        "mods": [["-tg", "--target", "<server>", "DNS server IP[:PORT] to test"]],
    },
    "DNSSEC": {
        "desc": "Is the zone DNSSEC-signed and valid?",
        "long": ["Fetch DNSKEY + RRSIG from the authoritative servers and validate the",
                 "self-signature. Not signed → PTV-DNS-NODNSSEC; signed but signatures",
                 "do not validate → PTV-DNS-DNSSECINVALID."],
        "requires": ["-d/--domain or -dl/--domain-file"],
        "mods": [
            ["-d", "--domain", "<domain>", "Domain to check"],
            ["-dl", "--domain-file", "<file>", "File with domains"],
        ],
    },
    "DNSSECALG": {
        "desc": "DNSSEC algorithm strength",
        "long": ["List the DNSKEY algorithms and flag deprecated ones (RSA/MD5, DSA,",
                 "SHA-1 based alg 5/7) — migrate to ECDSA (13/14) or EdDSA (15/16)",
                 "(PTV-DNS-WEAKDNSSECALG)."],
        "requires": ["-d/--domain or -dl/--domain-file"],
        "mods": [
            ["-d", "--domain", "<domain>", "Domain to check"],
            ["-dl", "--domain-file", "<file>", "File with domains"],
        ],
    },
    "RRSIG": {
        "desc": "RRSIG signature expiration",
        "long": ["Check the DNSKEY/SOA RRSIG expirations. An expired RRSIG breaks",
                 "validation for everyone (outage) — PTV-DNS-RRSIGEXPIRED; one expiring",
                 "within ~7 days is an early warning — PTV-DNS-RRSIGEXPIRING."],
        "requires": ["-d/--domain or -dl/--domain-file"],
        "mods": [
            ["-d", "--domain", "<domain>", "Domain to check"],
            ["-dl", "--domain-file", "<file>", "File with domains"],
        ],
    },
    "CHAIN": {
        "desc": "DNSSEC chain of trust (DS ↔ DNSKEY)",
        "long": ["Fetch the parent DS records and check each matches a child DNSKEY",
                 "(recomputing the DS digest). A DNSKEY with no DS (island of security)",
                 "or a DS with no matching key breaks validation from the root",
                 "(PTV-DNS-DNSSECCHAIN); SHA-1 DS digests are flagged."],
        "requires": ["-d/--domain or -dl/--domain-file"],
        "mods": [
            ["-d", "--domain", "<domain>", "Domain to check"],
            ["-dl", "--domain-file", "<file>", "File with domains"],
        ],
    },
    "NSEC": {
        "desc": "Authenticated denial: NSEC vs NSEC3",
        "long": ["Query a non-existent name and read the denial records. NSEC allows",
                 "walking the whole zone (PTV-DNS-NSECWALK); NSEC3 with non-zero",
                 "iterations / a salt is flagged against RFC 9276 (PTV-DNS-NSEC3PARAMS).",
                 "Detection only — the ZONEWALK test performs the enumeration."],
        "requires": ["-d/--domain or -dl/--domain-file"],
        "mods": [
            ["-d", "--domain", "<domain>", "Domain to check"],
            ["-dl", "--domain-file", "<file>", "File with domains"],
        ],
    },
    "ZONEWALK": {
        "desc": "Enumerate the zone via NSEC / NSEC3 walking",
        "long": ["NSEC: follow the next-name chain from the apex to list every name in",
                 "plaintext (PTV-DNS-ZONEWALK). NSEC3: collect the hash chain and report",
                 "the name count (still a disclosure; crack with NSEC3CRACK).",
                 "Minimal-covering 'black lies' NSEC is not walkable. Active (many",
                 "queries) — only when named in -ts."],
        "requires": ["-d/--domain or -dl/--domain-file"],
        "mods": [
            ["-d", "--domain", "<domain>", "Zone to walk"],
            ["-dl", "--domain-file", "<file>", "File with domains"],
        ],
    },
    "NSEC3CRACK": {
        "desc": "Offline dictionary cracking of NSEC3 hashes",
        "long": ["Collect the zone's NSEC3 hashes, then hash candidate names (from -sub,",
                 "else a built-in list) with the zone's salt/iterations/algorithm and",
                 "match them to reveal plaintext names (PTV-DNS-NSEC3CRACK). NSEC3 with",
                 "iterations=0 and no salt is the easiest to crack. Only when named in",
                 "-ts."],
        "requires": ["-d/--domain (or -dl)", "optional -sub/--subdomains <wordlist>"],
        "mods": [
            ["-d", "--domain", "<domain>", "Zone to crack"],
            ["-sub", "--subdomains", "<wordlist>", "Candidate labels (default: built-in common list)"],
        ],
    },
    "AMPFACTOR": {
        "desc": "DNS amplification factor (ANY/DNSKEY/large TXT)",
        "long": ["Measure the response-to-query byte ratio for ANY, DNSKEY and TXT",
                 "against the domain's authoritative servers. A large factor means the",
                 "server is usable as a DDoS reflector/amplifier (PTV-DNS-AMPFACTOR); a",
                 "minimised ANY (RFC 8482) is good. Authoritative-side amplification —",
                 "open-resolver reflection is the RECURSION-section AMPLIFICATION test."],
        "requires": ["-d/--domain or -dl/--domain-file"],
        "mods": [
            ["-d", "--domain", "<domain>", "Domain whose servers are measured"],
            ["-dl", "--domain-file", "<file>", "File with domains"],
        ],
    },
    "RRL": {
        "desc": "Response Rate Limiting detection",
        "long": ["Fire a small bounded burst of identical queries and watch for the RRL",
                 "signature (drops and/or TC-slip replies). RRL blunts amplification, so",
                 "its absence is the finding (PTV-DNS-NORRL). Active but bounded (~100",
                 "packets) — only when named in -ts; not seeing RRL is not proof it is",
                 "absent."],
        "requires": ["-d/--domain or -dl/--domain-file"],
        "mods": [
            ["-d", "--domain", "<domain>", "Domain to query repeatedly"],
            ["-dl", "--domain-file", "<file>", "File with domains"],
        ],
    },
    "TCPFALLBACK": {
        "desc": "Truncation (TC) & TCP fallback",
        "long": ["Check that a large record queried with a 512-byte UDP buffer is",
                 "truncated (TC set) and that TCP/53 actually answers. A broken TCP",
                 "path breaks large answers and DNSSEC and forces UDP-only (more",
                 "amplifiable) — PTV-DNS-TCPFALLBACK."],
        "requires": ["-d/--domain or -dl/--domain-file"],
        "mods": [
            ["-d", "--domain", "<domain>", "Domain whose servers are checked"],
            ["-dl", "--domain-file", "<file>", "File with domains"],
        ],
    },
    "DYNUPDATE": {
        "desc": "Unauthenticated dynamic update (RFC 2136)",
        "long": ["WRITE test: send an UNauthenticated UPDATE adding a unique benign TXT",
                 "record to the zone's primary, verify it, then delete it. If accepted,",
                 "anyone can inject/modify records (PTV-DNS-DYNUPDATE). Only when named",
                 "in -ts, and only against systems you are authorized to test."],
        "requires": ["-d/--domain or -dl/--domain-file"],
        "mods": [
            ["-d", "--domain", "<domain>", "Zone to test"],
            ["-dl", "--domain-file", "<file>", "File with domains"],
        ],
    },
    "TSIGUPDATE": {
        "desc": "TSIG update & ACL scoping",
        "long": ["WRITE test: with a supplied TSIG key, check whether its update rights",
                 "are ACL-scoped. If the key can add records under arbitrary/unrelated",
                 "names it is over-privileged (PTV-DNS-TSIGACL). All test records are",
                 "benign and deleted. Needs --tsig-key; only when named in -ts."],
        "requires": ["-d/--domain (or -dl)", "--tsig-key <name:secret> (or name:alg:secret)"],
        "mods": [
            ["-d", "--domain", "<domain>", "Zone to test"],
            ["", "--tsig-key", "<name:secret>", "TSIG key (name:secret or name:alg:secret)"],
        ],
    },
    "GSSTSIG": {
        "desc": "GSS-TSIG / secure update detection (AD)",
        "long": ["Informational: GSS-TSIG (RFC 3645) is the AD/Kerberos secure-update",
                 "mechanism (its deployment is good, not a finding). Uses a NON-WRITING",
                 "prerequisite-only update to reveal whether authenticated update is",
                 "enforced. A definitive GSS-TSIG / authenticated test needs AD domain",
                 "credentials — not performed here."],
        "requires": ["-d/--domain or -dl/--domain-file"],
        "mods": [
            ["-d", "--domain", "<domain>", "Zone to check"],
            ["-dl", "--domain-file", "<file>", "File with domains"],
        ],
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
