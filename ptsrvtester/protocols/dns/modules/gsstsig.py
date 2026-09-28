"""GSSTSIG — GSS-TSIG (AD-integrated secure dynamic update) detection.

GSS-TSIG (RFC 3645) is the Kerberos-based TSIG that Windows AD-integrated DNS
uses for secure dynamic update. Whether it is DEPLOYED is a good thing, not a
finding, so this is informational. A full GSS-TSIG negotiation needs AD domain
(Kerberos) credentials, which the tool does not perform; instead this uses a
NON-WRITING prerequisite-only update (RFC 2136 §2.4) to reveal whether the server
enforces authenticated update at all, and explains what a definitive test needs.
"""
from ptsrvtester.protocols.dns.utils import dynupdate_core as du
from ptsrvtester.protocols.dns.utils import enum_core as ec
from ptsrvtester.protocols.dns.utils.helpers import text_or_file

import dns.rcode

__MODULELABEL__ = "GSS-TSIG / secure update (AD)"
__MODULECODE__ = "GSSTSIG"
__ORDER__ = 820
__RUN_IN_ALL__ = False


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

        rcode = du.prereq_probe(ip, domain)  # prerequisite-only: no changes made
        rtext = dns.rcode.to_text(rcode) if rcode is not None else "no response"

        if rcode is None:
            ctx.out("No response to the (non-writing) prerequisite probe.", "WARNING", indent=8)
        elif rcode == dns.rcode.NOTIMP:
            ctx.out("Server does not implement dynamic update (NOTIMP) — GSS-TSIG not applicable.", "OK", indent=8)
        elif rcode in (dns.rcode.NOTAUTH, dns.rcode.REFUSED):
            ctx.out(f"Authenticated update is enforced ({rtext}) — consistent with TSIG or, on "
                    "AD-integrated DNS, GSS-TSIG.", "OK", indent=8)
        else:
            ctx.out(f"Prerequisite-only update processed without authentication ({rtext}) — "
                    "secure update may not be enforced (see DYNUPDATE).", "WARNING", indent=8)

        ctx.out("GSS-TSIG (RFC 3645) is the AD/Kerberos secure-update mechanism. Confirming it, "
                "and any authenticated update test, needs AD domain credentials — not performed here.", "TEXT", indent=8)

        with ctx.results_lock:
            ctx.properties.setdefault("secure_update", {})[domain] = rtext