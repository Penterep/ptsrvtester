"""EMAILSEC — SPF / DKIM / DMARC records (email-spoofing surface).

For each domain (-d/-dl) it checks the SPF record (TXT), the DMARC policy
(_dmarc TXT) and DKIM records for common selectors (override with
--dkim-selectors). Missing SPF/DMARC, a permissive SPF (+all / no fail policy)
and a monitor-only DMARC (p=none) are reported as findings: they leave the
domain open to e-mail spoofing.
"""
from ptsrvtester.protocols.dns.utils import enum_core as ec
from ptsrvtester.protocols.dns.utils.helpers import text_or_file
from ptsrvtester.protocols.dns.utils.results import VULNS

__MODULELABEL__ = "Email security records (SPF/DKIM/DMARC)"
__MODULECODE__ = "EMAILSEC"
__ORDER__ = 140


def run(ctx):
    domains = [d.strip() for d in text_or_file(ctx.args.domain, ctx.args.domain_file) if d.strip()]
    if not domains:
        ctx.out("This test needs a domain; pass -d <domain> or -dl <file>.", "WARNING", indent=4)
        return

    selectors = getattr(ctx.args, "dkim_selectors", None) or ec.DEFAULT_DKIM_SELECTORS
    resolver = ec.resolver_for(ctx)
    summary: dict[str, dict] = {}

    for domain in domains:
        ctx.out(domain, "INFO", colortext=True, indent=4)
        info = ec.email_security(resolver, domain, selectors)
        vulns: list[dict] = []

        # SPF
        if not info.spf:
            ctx.out("SPF      missing — anyone can spoof mail from this domain", "VULN", indent=8)
            vulns.append({"vuln_code": VULNS.SpfMissing.value,
                          "vuln_request": f"TXT {domain} (v=spf1)", "vuln_response": "no SPF record"})
        else:
            ctx.out(f"SPF      {info.spf}", "TEXT", indent=8)
            if info.spf_all in (None, "pass"):
                detail = "+all (passes everything)" if info.spf_all == "pass" else "no all mechanism"
                ctx.out(f"SPF      weak: {detail}", "VULN", indent=8)
                vulns.append({"vuln_code": VULNS.SpfWeak.value,
                              "vuln_request": f"SPF policy for {domain}", "vuln_response": info.spf})
            else:
                ctx.out(f"SPF      policy: {info.spf_all}", "OK", indent=8)

        # DMARC
        if not info.dmarc:
            ctx.out("DMARC    missing — no anti-spoofing policy published", "VULN", indent=8)
            vulns.append({"vuln_code": VULNS.DmarcMissing.value,
                          "vuln_request": f"TXT _dmarc.{domain}", "vuln_response": "no DMARC record"})
        else:
            ctx.out(f"DMARC    {info.dmarc}", "TEXT", indent=8)
            if info.dmarc_policy == "none":
                ctx.out("DMARC    weak: p=none (monitoring only, does not block spoofing)", "VULN", indent=8)
                vulns.append({"vuln_code": VULNS.DmarcWeak.value,
                              "vuln_request": f"DMARC policy for {domain}", "vuln_response": info.dmarc})
            else:
                ctx.out(f"DMARC    policy: p={info.dmarc_policy}", "OK", indent=8)

        # DKIM (informational — selector-dependent, absence is not conclusive)
        if info.dkim:
            for selector, record in info.dkim.items():
                ctx.out(f"DKIM     {selector}._domainkey: {record[:80]}{'…' if len(record) > 80 else ''}", "OK", indent=8)
        else:
            ctx.out(f"DKIM     none found for tried selectors ({len(selectors)}); may use custom selectors", "TEXT", indent=8)

        summary[domain] = {
            "spf": info.spf, "spf_all": info.spf_all,
            "dmarc": info.dmarc, "dmarc_policy": info.dmarc_policy,
            "dkim_selectors": list(info.dkim.keys()),
        }
        with ctx.results_lock:
            ctx.deferred_vulns.extend(vulns)

    with ctx.results_lock:
        ctx.properties["email_security"] = summary
