"""AMPFACTOR — DNS amplification factor of the server's own answers.

Measures the response-to-query byte ratio for ANY, DNSKEY and large TXT against
the domain's authoritative servers. A large factor means the server can be
abused as a DDoS reflector/amplifier (an attacker spoofs the victim's address).
A minimised ANY response (RFC 8482) is a good sign. High factor →
PTV-DNS-AMPFACTOR.

(This is the authoritative-side amplification; the RECURSION-section
AMPLIFICATION test covers open-resolver out-of-zone reflection.)
"""
from ptsrvtester.protocols.dns.utils import dnssec_core as dc
from ptsrvtester.protocols.dns.utils import dos_core as dos
from ptsrvtester.protocols.dns.utils import enum_core as ec
from ptsrvtester.protocols.dns.utils.helpers import text_or_file
from ptsrvtester.protocols.dns.utils.results import VULNS

__MODULELABEL__ = "Amplification factor (ANY/DNSKEY/TXT)"
__MODULECODE__ = "AMPFACTOR"
__ORDER__ = 700

AMP_THRESHOLD = 10.0


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

        measures = dos.amplification_factors(servers, domain)
        if not measures:
            ctx.out("No response to amplification probes.", "OK", indent=8)
            continue

        for m in measures:
            note = " (ANY minimised — RFC 8482)" if m.minimized else ""
            state = "answered" if m.answered else "no data"
            cat = "VULN" if (m.answered and m.factor >= AMP_THRESHOLD) else "TITLE"
            ctx.out(f"{m.rtype:<7} {m.request_size}→{m.response_size} B  x{m.factor}  ({state}{note})", cat, indent=8)

        best = dos.best_factor(measures)
        if best is None or best.factor < AMP_THRESHOLD:
            ctx.out(f"Max amplification factor is low (x{best.factor if best else 0}).", "OK", indent=8)
            with ctx.results_lock:
                ctx.properties.setdefault("amp_factor", {})[domain] = best.factor if best else 0
            continue

        ctx.out(f"High amplification: {best.rtype} gives x{best.factor} "
                f"({best.request_size}→{best.response_size} B) — usable as a reflector/amplifier.", "VULN", indent=8)
        with ctx.results_lock:
            ctx.properties.setdefault("amp_factor", {})[domain] = best.factor
            ctx.deferred_vulns.append({
                "vuln_code": VULNS.AmpFactor.value,
                "vuln_request": f"{best.rtype} {domain} ({best.request_size} B)",
                "vuln_response": f"{best.response_size} B response, amplification factor x{best.factor}",
            })