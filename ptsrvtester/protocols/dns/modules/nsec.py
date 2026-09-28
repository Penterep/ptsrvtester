"""NSEC — authenticated denial of existence: NSEC vs NSEC3.

Queries a random non-existent name and inspects the authenticated-denial records.
NSEC lets an attacker walk the whole zone (enumerate every name) —
PTV-DNS-NSECWALK. NSEC3 hashes the names; per RFC 9276 it should use 0
iterations and an empty salt, so non-zero iterations / a salt are flagged
(PTV-DNS-NSEC3PARAMS; extra iterations add validation cost without real benefit).
"""
from ptsrvtester.protocols.dns.utils import dnssec_core as dc
from ptsrvtester.protocols.dns.utils import enum_core as ec
from ptsrvtester.protocols.dns.utils.helpers import text_or_file
from ptsrvtester.protocols.dns.utils.results import VULNS

__MODULELABEL__ = "Authenticated denial (NSEC / NSEC3)"
__MODULECODE__ = "NSEC"
__ORDER__ = 540


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
        info = dc.denial_of_existence(servers, domain) if servers else dc.DenialInfo(error="no authoritative servers")

        if info.error:
            ctx.out(f"Could not determine denial type: {info.error}", "WARNING", indent=8)
            continue
        if info.kind is None:
            ctx.out("No NSEC/NSEC3 records seen (zone may be unsigned or uses minimal responses).", "TEXT", indent=8)
            summary[domain] = "none"
            continue

        if info.kind == "NSEC":
            if info.nsec_walkable:
                ctx.out(f"Classic NSEC in use (owner {info.nsec_owner} → next {info.nsec_next}) — "
                        "the full zone can be walked (enumerate every name).", "VULN", indent=8)
                summary[domain] = "NSEC (walkable)"
                with ctx.results_lock:
                    ctx.deferred_vulns.append({
                        "vuln_code": VULNS.NsecWalk.value,
                        "vuln_request": f"NSEC probe for {domain}",
                        "vuln_response": f"classic NSEC (owner {info.nsec_owner}, next {info.nsec_next}) — walkable",
                    })
            else:
                ctx.out("Minimal-covering NSEC (e.g. 'black lies') — signs each name on demand, "
                        "so the zone is NOT walkable.", "OK", indent=8)
                summary[domain] = "NSEC (minimal-covering, not walkable)"
            continue

        # NSEC3
        salt = info.nsec3_salt or "-"
        ctx.out(f"NSEC3 in use — iterations={info.nsec3_iterations}, salt={salt}", "OK", indent=8)
        summary[domain] = f"NSEC3 (iter={info.nsec3_iterations}, salt={salt})"
        non_compliant = (info.nsec3_iterations and info.nsec3_iterations > 0) or (salt not in ("-", ""))
        if non_compliant:
            ctx.out("NSEC3 uses non-zero iterations and/or a salt — RFC 9276 recommends "
                    "0 iterations and no salt (extra iterations only add validation cost).", "VULN", indent=8)
            with ctx.results_lock:
                ctx.deferred_vulns.append({
                    "vuln_code": VULNS.Nsec3Params.value,
                    "vuln_request": f"NSEC3 parameters for {domain}",
                    "vuln_response": f"iterations={info.nsec3_iterations}, salt={salt}",
                })

    with ctx.results_lock:
        ctx.properties["nsec"] = summary