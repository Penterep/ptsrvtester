"""CAA — certificate-issuance control (RFC 8659).

Checks whether each domain (-d/-dl) publishes CAA records. A missing CAA record
means any public CA may issue certificates for the domain (weaker mis-issuance
protection) — reported as a finding. Note: CAA can also be inherited from a
parent zone, which this per-domain check does not climb.
"""
from ptsrvtester.protocols.dns.utils import enum_core as ec
from ptsrvtester.protocols.dns.utils.helpers import text_or_file
from ptsrvtester.protocols.dns.utils.results import VULNS

__MODULELABEL__ = "CAA records (certificate issuance control)"
__MODULECODE__ = "CAA"
__ORDER__ = 150


def run(ctx):
    domains = [d.strip() for d in text_or_file(ctx.args.domain, ctx.args.domain_file) if d.strip()]
    if not domains:
        ctx.out("This test needs a domain; pass -d <domain> or -dl <file>.", "WARNING", indent=4)
        return

    resolver = ec.resolver_for(ctx)
    summary: dict[str, list[str]] = {}

    for domain in domains:
        ctx.out(domain, "INFO", colortext=True, indent=4)
        records = ec.caa_records(resolver, domain)
        summary[domain] = records
        if records:
            for rec in records:
                ctx.out(rec, "OK", indent=8)
        else:
            ctx.out("No CAA record — any public CA may issue certificates for this domain.", "VULN", indent=8)
            with ctx.results_lock:
                ctx.deferred_vulns.append({
                    "vuln_code": VULNS.CaaMissing.value,
                    "vuln_request": f"CAA {domain}",
                    "vuln_response": "no CAA record set",
                })

    with ctx.results_lock:
        ctx.properties["caa"] = {d: r for d, r in summary.items()}
