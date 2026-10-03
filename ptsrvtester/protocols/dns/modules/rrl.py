"""RRL — Response Rate Limiting detection.

Fires a small bounded burst of identical queries at the server and watches for
the RRL signature: many queries but far fewer full replies (drops) and/or
truncated "slip" replies (TC). RRL blunts amplification/reflection abuse, so its
ABSENCE is the finding (PTV-DNS-NORRL). Active but bounded (~100 packets) — only
when named in -ts. Not observing RRL at this rate is not proof it is absent
(the burst may stay under the threshold).
"""
from ptsrvtester.protocols.dns.utils import dnssec_core as dc
from ptsrvtester.protocols.dns.utils import dos_core as dos
from ptsrvtester.protocols.dns.utils import enum_core as ec
from ptsrvtester.protocols.dns.utils.helpers import text_or_file
from ptsrvtester.protocols.dns.utils.results import VULNS

__MODULELABEL__ = "Response Rate Limiting (RRL)"
__MODULECODE__ = "RRL"
__ORDER__ = 710
__RUN_IN_ALL__ = False


def run(ctx):
    domains = [d.strip() for d in text_or_file(ctx.args.domain, ctx.args.domain_file) if d.strip()]
    if not domains:
        ctx.out("This test needs a domain; pass -d <domain> or -dl <file>.", "WARNING", indent=4)
        return

    resolver = ec.resolver_for(ctx)

    for domain in domains:
        ctx.out(domain, "INFO", colortext=True, indent=4)
        servers = dc.servers_for(resolver, domain, getattr(ctx, "ip", None))
        if not servers:
            ctx.out("Could not find authoritative servers for the domain.", "WARNING", indent=8)
            continue

        res = dos.rrl_probe(servers[0], domain)
        if res.error:
            ctx.out(f"RRL probe failed: {res.error}", "WARNING", indent=8)
            continue

        ctx.out(f"Sent {res.sent}, received {res.received} (truncated/slip {res.truncated}).", "TITLE", indent=8)
        if res.rrl_detected:
            ctx.out("Response Rate Limiting appears active (drops / TC-slip observed).", "OK", indent=8)
            with ctx.results_lock:
                ctx.properties.setdefault("rrl", {})[domain] = "active"
            continue

        ctx.out("No RRL observed at this rate — server answered the whole burst "
                "(weaker against amplification/reflection abuse).", "VULN", indent=8)
        with ctx.results_lock:
            ctx.properties.setdefault("rrl", {})[domain] = "not observed"
            ctx.deferred_vulns.append({
                "vuln_code": VULNS.NoRrl.value,
                "vuln_request": f"burst of {res.sent} identical A queries for {domain}",
                "vuln_response": f"received {res.received}/{res.sent}, no rate limiting seen",
            })