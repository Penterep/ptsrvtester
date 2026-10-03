"""TAKEOVER — subdomain takeover (dangling records to unclaimed cloud resources).

Checks the domain (and any -sub labels) for CNAMEs pointing at known SaaS/cloud
services and whether that target is unclaimed: a dangling CNAME (target
NXDOMAINs) or a matching "unclaimed" HTTP fingerprint means the name can be
taken over (PTV-DNS-TAKEOVER). A CNAME to a takeover-prone service that still
resolves is reported to verify manually.
"""
from ptsrvtester.protocols.dns.utils import enum_core as ec
from ptsrvtester.protocols.dns.utils import integrity_core as ig
from ptsrvtester.protocols.dns.utils.helpers import text_or_file
from ptsrvtester.protocols.dns.utils.results import VULNS

__MODULELABEL__ = "Subdomain takeover"
__MODULECODE__ = "TAKEOVER"
__ORDER__ = 1000


def run(ctx):
    domains = [d.strip() for d in text_or_file(ctx.args.domain, ctx.args.domain_file) if d.strip()]
    if not domains:
        ctx.out("This test needs a domain; pass -d <domain> or -dl <file>.", "WARNING", indent=4)
        return

    labels = []
    if getattr(ctx.args, "subdomains", None):
        labels = [l.strip() for l in text_or_file(None, ctx.args.subdomains) if l.strip()]

    resolver = ec.resolver_for(ctx)
    findings: list[str] = []

    for domain in domains:
        ctx.out(domain, "INFO", colortext=True, indent=4)
        names = [domain] + [f"{l}.{domain.rstrip('.')}" for l in labels]
        any_cname = False
        for name in names:
            res = ig.takeover_check(resolver, name)
            if res.cname is None:
                continue
            any_cname = True
            if res.vulnerable:
                ctx.out(f"{name} → {res.detail}", "VULN", indent=8)
                findings.append(f"{name}: {res.detail}")
            elif res.service:
                ctx.out(f"{name} → {res.detail}", "WARNING", indent=8)
            else:
                ctx.out(f"{name} → {res.detail}", "TITLE", indent=8)
        if not any_cname:
            ctx.out("No CNAMEs among the checked names (pass -sub for subdomains).", "OK", indent=8)

    if findings:
        with ctx.results_lock:
            ctx.properties["takeover"] = findings
            ctx.deferred_vulns.append({
                "vuln_code": VULNS.Takeover.value,
                "vuln_request": "CNAME/target check against takeover fingerprints",
                "vuln_response": "; ".join(findings),
            })
