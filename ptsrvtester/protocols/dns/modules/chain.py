"""CHAIN — DNSSEC chain of trust (parent DS ↔ child DNSKEY).

Fetches the DS records the parent zone publishes for the domain and checks each
matches a DNSKEY in the child zone (recomputing the DS digest from the key). A
DNSKEY with no matching DS (or a DS with no matching key) breaks the chain of
trust — validating resolvers cannot authenticate the zone (PTV-DNS-DNSSECCHAIN).
Also flags SHA-1 DS digests.
"""
from ptsrvtester.protocols.dns.utils import dnssec_core as dc
from ptsrvtester.protocols.dns.utils import enum_core as ec
from ptsrvtester.protocols.dns.utils.helpers import text_or_file
from ptsrvtester.protocols.dns.utils.results import VULNS

__MODULELABEL__ = "DNSSEC chain of trust (DS ↔ DNSKEY)"
__MODULECODE__ = "CHAIN"
__ORDER__ = 530


def run(ctx):
    domains = [d.strip() for d in text_or_file(ctx.args.domain, ctx.args.domain_file) if d.strip()]
    if not domains:
        ctx.out("This test needs a domain; pass -d <domain> or -dl <file>.", "WARNING", indent=4)
        return

    resolver = ec.resolver_for(ctx)

    for domain in domains:
        ctx.out(domain, "INFO", colortext=True, indent=4)
        servers = dc.servers_for(resolver, domain, getattr(ctx, "ip", None))
        keys = dc.get_dnskey(servers, domain) if servers else None
        dnskey = keys.dnskey if keys else None
        matches, ds_present = dc.chain_of_trust(servers, resolver, domain, dnskey)

        if not ds_present:
            if dnskey is not None:
                ctx.out("Zone is signed (DNSKEY present) but the parent publishes NO DS — "
                        "island of security; not authenticated from the root.", "VULN", indent=8)
                with ctx.results_lock:
                    ctx.deferred_vulns.append({
                        "vuln_code": VULNS.DnssecChain.value,
                        "vuln_request": f"DS {domain} (parent)",
                        "vuln_response": "DNSKEY present but no DS at parent (broken chain)",
                    })
            else:
                ctx.out("No DS at parent and no DNSKEY — zone is simply unsigned.", "OK", indent=8)
            continue

        broken = False
        for m in matches:
            weak = " (SHA-1 digest — weak)" if m.digest_type == 1 else ""
            if m.matched is True:
                ctx.out(f"DS tag {m.key_tag} ({m.digest_name}) ↔ DNSKEY: match{weak}", "OK", indent=8)
            elif m.matched is None:
                ctx.out(f"DS tag {m.key_tag} ({m.digest_name}): could not verify (unsupported digest)", "WARNING", indent=8)
            else:
                ctx.out(f"DS tag {m.key_tag} ({m.digest_name}): NO matching DNSKEY{weak}", "VULN", indent=8)
                broken = True

        if broken:
            ctx.out("Chain of trust is broken (a parent DS has no matching child DNSKEY).", "VULN", indent=8)
            with ctx.results_lock:
                ctx.deferred_vulns.append({
                    "vuln_code": VULNS.DnssecChain.value,
                    "vuln_request": f"DS↔DNSKEY match for {domain}",
                    "vuln_response": "; ".join(f"tag {m.key_tag}={'ok' if m.matched else 'no-match'}" for m in matches),
                })
        elif all(m.matched for m in matches):
            ctx.out("Chain of trust consistent (every DS matches a DNSKEY).", "OK", indent=8)