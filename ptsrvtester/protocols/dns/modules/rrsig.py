"""RRSIG — RRSIG signature expiration.

Reads the RRSIG expiration for the zone's DNSKEY and SOA rrsets. An expired
RRSIG breaks validation for everyone using validating resolvers (an outage /
availability issue); one expiring within a few days is an early warning.
Reports PTV-DNS-RRSIGEXPIRED / PTV-DNS-RRSIGEXPIRING.
"""
from datetime import datetime, timezone

from ptsrvtester.protocols.dns.utils import dnssec_core as dc
from ptsrvtester.protocols.dns.utils import enum_core as ec
from ptsrvtester.protocols.dns.utils.helpers import text_or_file
from ptsrvtester.protocols.dns.utils.results import VULNS

__MODULELABEL__ = "RRSIG expiration"
__MODULECODE__ = "RRSIG"
__ORDER__ = 520


def _fmt(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def run(ctx):
    domains = [d.strip() for d in text_or_file(ctx.args.domain, ctx.args.domain_file) if d.strip()]
    if not domains:
        ctx.out("This test needs a domain; pass -d <domain> or -dl <file>.", "WARNING", indent=4)
        return

    resolver = ec.resolver_for(ctx)

    for domain in domains:
        ctx.out(domain, "INFO", colortext=True, indent=4)
        servers = dc.servers_for(resolver, domain, getattr(ctx, "ip", None))
        sigs = dc.rrsig_expiry(servers, domain) if servers else []
        if not sigs:
            ctx.out("No RRSIG found (zone not signed, or signatures unavailable).", "WARNING", indent=8)
            continue

        expired = [s for s in sigs if s.expired]
        expiring = [s for s in sigs if s.expiring]
        for s in sigs:
            line = f"RRSIG {s.covers:<7} tag {s.key_tag}: expires {_fmt(s.expiration)} ({s.days_left:g} days)"
            if s.expired:
                ctx.out(line + " — EXPIRED", "VULN", indent=8)
            elif s.expiring:
                ctx.out(line + " — expiring soon", "VULN", indent=8)
            else:
                ctx.out(line, "OK", indent=8)

        with ctx.results_lock:
            if expired:
                ctx.deferred_vulns.append({
                    "vuln_code": VULNS.RrsigExpired.value,
                    "vuln_request": f"RRSIG expiration for {domain}",
                    "vuln_response": "; ".join(f"{s.covers} tag {s.key_tag} expired {_fmt(s.expiration)}" for s in expired),
                })
            elif expiring:
                ctx.deferred_vulns.append({
                    "vuln_code": VULNS.RrsigExpiring.value,
                    "vuln_request": f"RRSIG expiration for {domain}",
                    "vuln_response": "; ".join(f"{s.covers} tag {s.key_tag} in {s.days_left:g}d" for s in expiring),
                })