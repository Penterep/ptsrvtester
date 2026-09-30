"""DNSSEC — is the zone DNSSEC-signed and are its signatures valid?

Fetches the DNSKEY rrset and its RRSIG from the zone's authoritative servers and
validates the self-signature. Reports: not signed (PTV-DNS-NODNSSEC) or signed
but invalid (PTV-DNS-DNSSECINVALID). Algorithm, expiry, chain-of-trust and
NSEC/NSEC3 detail are covered by the DNSSECALG / RRSIG / CHAIN / NSEC tests.
"""
from ptsrvtester.protocols.dns.utils import dnssec_core as dc
from ptsrvtester.protocols.dns.utils import enum_core as ec
from ptsrvtester.protocols.dns.utils.helpers import text_or_file
from ptsrvtester.protocols.dns.utils.results import VULNS

__MODULELABEL__ = "DNSSEC validity"
__MODULECODE__ = "DNSSEC"
__ORDER__ = 500


def run(ctx):
    domains = [d.strip() for d in text_or_file(ctx.args.domain, ctx.args.domain_file) if d.strip()]
    if not domains:
        ctx.out("This test needs a domain; pass -d <domain> or -dl <file>.", "WARNING", indent=4)
        return

    resolver = ec.resolver_for(ctx)
    summary: dict[str, str] = {}

    for domain in domains:
        ctx.out(domain, "INFO", colortext=True, indent=4)
        servers = dc.servers_for(resolver, domain, getattr(ctx, "ip", None))
        if not servers:
            ctx.out("Could not find authoritative servers for the domain.", "WARNING", indent=8)
            continue

        keys = dc.get_dnskey(servers, domain)
        if keys.dnskey is None:
            ctx.out("DNSSEC not deployed (no DNSKEY) — responses are not authenticated.", "VULN", indent=8)
            summary[domain] = "unsigned"
            with ctx.results_lock:
                ctx.deferred_vulns.append({
                    "vuln_code": VULNS.DnssecMissing.value,
                    "vuln_request": f"DNSKEY {domain}",
                    "vuln_response": "no DNSKEY (zone not signed)",
                })
            continue

        key_count = len(keys.dnskey)
        if keys.valid:
            ctx.out(f"DNSSEC deployed and self-signature valid ({key_count} DNSKEY(s)).", "OK", indent=8)
            summary[domain] = "signed, valid"
        else:
            ctx.out(f"DNSSEC deployed but INVALID: {keys.error}", "VULN", indent=8)
            summary[domain] = f"signed, invalid ({keys.error})"
            with ctx.results_lock:
                ctx.deferred_vulns.append({
                    "vuln_code": VULNS.DnssecInvalid.value,
                    "vuln_request": f"validate DNSKEY RRSIG for {domain}",
                    "vuln_response": keys.error or "signature validation failed",
                })

    with ctx.results_lock:
        ctx.properties["dnssec"] = summary