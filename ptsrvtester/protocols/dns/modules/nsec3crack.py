"""NSEC3CRACK — offline dictionary cracking of NSEC3 hashes.

Collects the zone's NSEC3 hashes, then hashes candidate names (from -sub, else a
built-in common list) with the zone's salt/iterations/algorithm and matches them
against the collected hashes to reveal plaintext names (PTV-DNS-NSEC3CRACK).
NSEC3 with iterations=0 and no salt (RFC 9276) is the easiest to crack. Active +
offline compute — only when named in -ts.
"""
from ptsrvtester.protocols.dns.utils import dnssec_core as dc
from ptsrvtester.protocols.dns.utils import enum_core as ec
from ptsrvtester.protocols.dns.utils import zonewalk_core as zw
from ptsrvtester.protocols.dns.utils.helpers import text_or_file
from ptsrvtester.protocols.dns.utils.results import VULNS

__MODULELABEL__ = "NSEC3 offline hash cracking"
__MODULECODE__ = "NSEC3CRACK"
__ORDER__ = 610
__RUN_IN_ALL__ = False


def run(ctx):
    domains = [d.strip() for d in text_or_file(ctx.args.domain, ctx.args.domain_file) if d.strip()]
    if not domains:
        ctx.out("This test needs a domain; pass -d <domain> or -dl <file>.", "WARNING", indent=4)
        return

    if getattr(ctx.args, "subdomains", None):
        labels = [l.strip() for l in text_or_file(None, ctx.args.subdomains) if l.strip()]
        wordlist_note = f"{len(labels)} labels from -sub"
    else:
        labels = list(zw.DEFAULT_LABELS)
        wordlist_note = f"built-in {len(labels)} common labels (use -sub for more)"

    resolver = ec.resolver_for(ctx)

    for domain in domains:
        ctx.out(domain, "INFO", colortext=True, indent=4)
        servers = dc.servers_for(resolver, domain, getattr(ctx, "ip", None))
        if not servers:
            ctx.out("Could not find authoritative servers for the domain.", "WARNING", indent=8)
            continue

        params, hashes = zw.collect_nsec3(servers, domain)
        if params is None or not hashes:
            ctx.out("Zone does not use NSEC3 (or no hashes collected) — nothing to crack.", "OK", indent=8)
            continue

        ctx.out(f"NSEC3 alg {params.algorithm}, iterations {params.iterations}, salt {params.salt_hex}; "
                f"{len(hashes)} hashes collected; trying {wordlist_note}.", "TEXT", indent=8)
        revealed = zw.crack_nsec3(hashes, params, domain, labels)

        if not revealed:
            ctx.out("No hashes cracked with this wordlist (try a larger -sub list).", "OK", indent=8)
            continue

        for h, name in sorted(revealed.items(), key=lambda kv: kv[1]):
            ctx.out(f"{name:<40} {h}", "VULN", indent=8)
        ctx.out(f"Recovered {len(revealed)}/{len(hashes)} name(s) by offline NSEC3 cracking.", "VULN", indent=8)
        with ctx.results_lock:
            ctx.properties.setdefault("nsec3_cracked", {})[domain] = sorted(revealed.values())
            ctx.deferred_vulns.append({
                "vuln_code": VULNS.Nsec3Cracked.value,
                "vuln_request": f"NSEC3 offline crack of {domain} (iterations {params.iterations}, salt {params.salt_hex})",
                "vuln_response": f"{len(revealed)} names: " + ", ".join(sorted(revealed.values())),
            })