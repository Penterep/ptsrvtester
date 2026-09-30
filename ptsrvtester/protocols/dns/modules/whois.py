"""WHOIS — registration data for a domain.

Fetches the WHOIS record for each domain from -d/-dl. Informational: registrar,
dates, name servers and (where not redacted) registrant contacts.
"""
from ptsrvtester.protocols.dns.utils import enum_core as ec
from ptsrvtester.protocols.dns.utils.helpers import text_or_file

__MODULELABEL__ = "WHOIS registration data"
__MODULECODE__ = "WHOIS"
__ORDER__ = 120


def run(ctx):
    domains = [d.strip() for d in text_or_file(ctx.args.domain, ctx.args.domain_file) if d.strip()]
    if not domains:
        ctx.out("This test needs a domain; pass -d <domain> or -dl <file>.", "WARNING", indent=4)
        return

    collected: dict[str, str] = {}
    for domain in domains:
        ctx.out(domain, "INFO", colortext=True, indent=4)
        text = ec.whois_lookup(domain)
        if not text:
            ctx.out("No WHOIS data (lookup failed, rate-limited, or TLD not supported).", "WARNING", indent=8)
            continue
        for line in text.strip().splitlines():
            ctx.out(line, "TEXT", indent=8)
        collected[domain] = text.strip()

    with ctx.results_lock:
        if collected:
            ctx.properties["whois"] = {d: t[:2000] for d, t in collected.items()}
