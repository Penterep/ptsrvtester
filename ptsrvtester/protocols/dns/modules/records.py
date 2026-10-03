"""RECORDS — enumerate common DNS record types for a domain.

Resolves A, AAAA, MX, TXT, CNAME, NS, SRV, SOA (override with -rec) for each
domain from -d/-dl. Informational: it maps the domain's published records.
"""
from ptsrvtester.protocols.dns.utils import enum_core as ec
from ptsrvtester.protocols.dns.utils.helpers import text_or_file

__MODULELABEL__ = "DNS record enumeration (A/AAAA/MX/TXT/…)"
__MODULECODE__ = "RECORDS"
__ORDER__ = 100


def run(ctx):
    domains = [d.strip() for d in text_or_file(ctx.args.domain, ctx.args.domain_file) if d.strip()]
    if not domains:
        ctx.out("This test needs a domain; pass -d <domain> or -dl <file>.", "WARNING", indent=4)
        return

    rtypes = getattr(ctx.args, "records", None) or ec.DEFAULT_RECORD_TYPES
    resolver = ec.resolver_for(ctx)
    all_records: dict[str, dict[str, list[str]]] = {}

    for domain in domains:
        ctx.out(domain, "INFO", colortext=True, indent=4)
        records = ec.lookup_records(resolver, domain, rtypes)
        any_found = False
        for rtype in rtypes:
            values = records.get(rtype) or []
            if values:
                any_found = True
                ctx.out(f"{rtype:<7} {', '.join(values)}", "TITLE", indent=8)
            else:
                ctx.out(f"{rtype:<7} —", "TITLE", indent=8)
        if not any_found:
            ctx.out("No records resolved (domain may not exist or is empty).", "WARNING", indent=8)
        all_records[domain] = {rt: v for rt, v in records.items() if v}

    with ctx.results_lock:
        ctx.properties["records"] = {d: r for d, r in all_records.items() if r}
