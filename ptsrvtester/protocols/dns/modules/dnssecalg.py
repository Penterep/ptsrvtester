"""DNSSECALG — DNSSEC algorithm strength.

Lists the DNSKEY algorithms and flags deprecated ones (RSA/MD5, DSA, and SHA-1
based alg 5/7) which should be replaced with ECDSA (13/14) or EdDSA (15/16)
(PTV-DNS-WEAKDNSSECALG). RSASHA256/512 (8/10) are acceptable but ECDSA/EdDSA are
recommended.
"""
from ptsrvtester.protocols.dns.utils import dnssec_core as dc
from ptsrvtester.protocols.dns.utils import enum_core as ec
from ptsrvtester.protocols.dns.utils.helpers import text_or_file
from ptsrvtester.protocols.dns.utils.results import VULNS

__MODULELABEL__ = "DNSSEC algorithms"
__MODULECODE__ = "DNSSECALG"
__ORDER__ = 510


def run(ctx):
    domains = [d.strip() for d in text_or_file(ctx.args.domain, ctx.args.domain_file) if d.strip()]
    if not domains:
        ctx.out("This test needs a domain; pass -d <domain> or -dl <file>.", "WARNING", indent=4)
        return

    resolver = ec.resolver_for(ctx)
    summary: dict[str, list[str]] = {}

    for domain in domains:
        ctx.out(domain, "INFO", colortext=True, indent=4)
        servers = dc.servers_for(resolver, domain, getattr(ctx, "ip", None))
        keys = dc.get_dnskey(servers, domain) if servers else None
        if not keys or keys.dnskey is None:
            ctx.out("No DNSKEY (zone not signed) — nothing to assess.", "WARNING", indent=8)
            continue

        algs = dc.key_algorithms(keys.dnskey)
        deprecated: list[str] = []
        for a in algs:
            if a.deprecated:
                ctx.out(f"{a.role} tag {a.key_tag}: {a.name} (alg {a.algorithm}) — DEPRECATED", "VULN", indent=8)
                deprecated.append(f"{a.name}(alg {a.algorithm})")
            elif a.modern:
                ctx.out(f"{a.role} tag {a.key_tag}: {a.name} (alg {a.algorithm}) — modern", "OK", indent=8)
            else:
                ctx.out(f"{a.role} tag {a.key_tag}: {a.name} (alg {a.algorithm}) — acceptable (ECDSA/EdDSA recommended)", "TEXT", indent=8)
        summary[domain] = [f"{a.name}(alg {a.algorithm},{a.role})" for a in algs]

        if deprecated:
            ctx.out("Deprecated DNSSEC algorithm(s) in use — migrate to ECDSA/EdDSA.", "VULN", indent=8)
            with ctx.results_lock:
                ctx.deferred_vulns.append({
                    "vuln_code": VULNS.WeakDnssecAlg.value,
                    "vuln_request": f"DNSKEY algorithms for {domain}",
                    "vuln_response": ", ".join(deprecated),
                })

    with ctx.results_lock:
        ctx.properties["dnssec_algorithms"] = summary