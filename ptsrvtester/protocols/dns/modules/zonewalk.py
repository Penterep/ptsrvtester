"""ZONEWALK — enumerate a zone via NSEC / NSEC3 walking.

NSEC: follow the ``next`` chain from the apex to list every name in the zone in
plaintext (PTV-DNS-ZONEWALK). Minimal-covering "black lies" NSEC is not walkable.
NSEC3: the names are hashed, so this collects the NSEC3 hash chain and reports
how many names exist (still a disclosure — try NSEC3CRACK to recover the
plaintext). Active (many queries) — only when named in -ts.
"""
from ptsrvtester.protocols.dns.utils import dnssec_core as dc
from ptsrvtester.protocols.dns.utils import enum_core as ec
from ptsrvtester.protocols.dns.utils import zonewalk_core as zw
from ptsrvtester.protocols.dns.utils.helpers import text_or_file
from ptsrvtester.protocols.dns.utils.results import VULNS

__MODULELABEL__ = "Zone walking (NSEC / NSEC3)"
__MODULECODE__ = "ZONEWALK"
__ORDER__ = 600
__RUN_IN_ALL__ = False

SAMPLE = 40


def run(ctx):
    domains = [d.strip() for d in text_or_file(ctx.args.domain, ctx.args.domain_file) if d.strip()]
    if not domains:
        ctx.out("This test needs a domain; pass -d <domain> or -dl <file>.", "WARNING", indent=4)
        return

    resolver = ec.resolver_for(ctx)
    summary: dict[str, object] = {}

    for domain in domains:
        ctx.out(domain, "INFO", colortext=True, indent=4)
        servers = dc.servers_for(resolver, domain, getattr(ctx, "ip", None))
        if not servers:
            ctx.out("Could not find authoritative servers for the domain.", "WARNING", indent=8)
            continue

        denial = dc.denial_of_existence(servers, domain)
        if denial.error or denial.kind is None:
            ctx.out("No NSEC/NSEC3 seen — zone is unsigned or does not expose authenticated denial.", "OK", indent=8)
            continue

        if denial.kind == "NSEC":
            if not denial.nsec_walkable:
                ctx.out("Minimal-covering NSEC ('black lies') — the zone is NOT walkable.", "OK", indent=8)
                summary[domain] = "NSEC (not walkable)"
                continue
            names, truncated = zw.walk_nsec(servers, domain)
            for n in names[:SAMPLE]:
                ctx.out(n, "TEXT", indent=8)
            if len(names) > SAMPLE:
                ctx.out(f"… (+{len(names) - SAMPLE} more)", "TEXT", indent=8)
            tail = " (truncated at cap)" if truncated else ""
            ctx.out(f"Enumerated {len(names)} name(s) via NSEC walking{tail}.", "VULN", indent=8)
            summary[domain] = {"method": "NSEC", "count": len(names)}
            with ctx.results_lock:
                ctx.properties.setdefault("zonewalk", {})[domain] = names
                ctx.deferred_vulns.append({
                    "vuln_code": VULNS.ZoneWalk.value,
                    "vuln_request": f"NSEC chain walk of {domain}",
                    "vuln_response": f"{len(names)} names: " + ", ".join(names[:50]),
                })
            continue

        # NSEC3
        params, hashes = zw.collect_nsec3(servers, domain)
        if not hashes or params is None:
            ctx.out("NSEC3 in use but no hashes collected.", "WARNING", indent=8)
            continue
        ctx.out(f"NSEC3 (alg {params.algorithm}, iterations {params.iterations}, salt {params.salt_hex}) — "
                f"collected {len(hashes)} distinct hash(es).", "VULN", indent=8)
        ctx.out("Names are hashed; run NSEC3CRACK to attempt offline recovery.", "ADDITIONS", colortext=True, indent=8)
        summary[domain] = {"method": "NSEC3", "hashes": len(hashes)}
        with ctx.results_lock:
            ctx.deferred_vulns.append({
                "vuln_code": VULNS.ZoneWalk.value,
                "vuln_request": f"NSEC3 hash collection of {domain}",
                "vuln_response": f"{len(hashes)} NSEC3 hashes (iterations {params.iterations}, salt {params.salt_hex})",
            })

    with ctx.results_lock:
        ctx.properties["zonewalk_summary"] = summary