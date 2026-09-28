"""DYNUPDATE — unauthenticated dynamic update (RFC 2136).

Sends an UNauthenticated UPDATE that adds a unique benign TXT record to the
zone's SOA primary, verifies whether it was created, then DELETES it (cleanup).
If the record is accepted, anyone can inject/modify records in the zone
(PTV-DNS-DYNUPDATE) — a critical misconfiguration. WRITE test — only when named
in -ts, and only against systems you are authorized to test.
"""
from ptsrvtester.protocols.dns.utils import dynupdate_core as du
from ptsrvtester.protocols.dns.utils import enum_core as ec
from ptsrvtester.protocols.dns.utils.helpers import text_or_file
from ptsrvtester.protocols.dns.utils.results import VULNS

import dns.rcode

__MODULELABEL__ = "Unauthenticated dynamic update (RFC 2136)"
__MODULECODE__ = "DYNUPDATE"
__ORDER__ = 800
__RUN_IN_ALL__ = False   # active WRITE attempt: only when named in -ts


def run(ctx):
    domains = [d.strip() for d in text_or_file(ctx.args.domain, ctx.args.domain_file) if d.strip()]
    if not domains:
        ctx.out("This test needs a domain; pass -d <domain> or -dl <file>.", "WARNING", indent=4)
        return

    resolver = ec.resolver_for(ctx)

    for domain in domains:
        ctx.out(domain, "INFO", colortext=True, indent=4)
        servers = du.primary_ips(resolver, domain)
        if not servers:
            ctx.out("Could not resolve the zone's primary/authoritative servers.", "WARNING", indent=8)
            continue

        ip = servers[0]
        name = du.test_name(domain)
        rcode = du.add_txt(ip, domain, name)

        if rcode is None:
            ctx.out(f"No response to the update from {ip}.", "WARNING", indent=8)
            continue
        rtext = dns.rcode.to_text(rcode)

        if rcode != dns.rcode.NOERROR:
            # REFUSED / NOTAUTH = authentication/ACL required (good); NOTIMP = no dynamic update.
            hint = {"NOTAUTH": "authentication required (TSIG/GSS-TSIG)",
                    "REFUSED": "refused by ACL",
                    "NOTIMP": "dynamic update not supported"}.get(rtext, rtext)
            ctx.out(f"Unauthenticated update rejected on {ip} — {rtext} ({hint}).", "OK", indent=8)
            continue

        # Accepted — verify, then always clean up.
        present = du.verify_present(ip, name)
        du.delete_name(ip, domain, name)
        cleaned = not du.verify_present(ip, name)

        if present:
            ctx.out(f"Unauthenticated UPDATE ACCEPTED on {ip} — injected {name} (then deleted; "
                    f"cleanup {'ok' if cleaned else 'FAILED — remove manually'}).", "VULN", indent=8)
            with ctx.results_lock:
                ctx.properties.setdefault("dynupdate", {})[domain] = "unauthenticated update allowed"
                ctx.deferred_vulns.append({
                    "vuln_code": VULNS.DynUpdate.value,
                    "vuln_request": f"RFC 2136 UPDATE add {name} TXT (no auth) to {ip}",
                    "vuln_response": f"NOERROR and record created (cleaned up: {cleaned})",
                })
        else:
            ctx.out(f"Server returned NOERROR but no record was created on {ip} (likely silently dropped).", "WARNING", indent=8)