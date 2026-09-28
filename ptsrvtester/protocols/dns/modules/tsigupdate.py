"""TSIGUPDATE — TSIG-authenticated update & ACL scoping.

With an operator-supplied TSIG key (--tsig-key), sends signed UPDATEs to check
whether the key's update rights are properly ACL-restricted. A well-configured
server scopes a key to specific names/types (e.g. BIND update-policy); if the
key can add records under arbitrary/unrelated names, it is over-privileged
(PTV-DNS-TSIGACL). All test records are benign and deleted afterwards. WRITE test
— only when named in -ts.
"""
from ptsrvtester.protocols.dns.utils import dynupdate_core as du
from ptsrvtester.protocols.dns.utils import enum_core as ec
from ptsrvtester.protocols.dns.utils.helpers import text_or_file
from ptsrvtester.protocols.dns.utils.results import VULNS

import dns.rcode

__MODULELABEL__ = "TSIG update & ACL scoping"
__MODULECODE__ = "TSIGUPDATE"
__ORDER__ = 810
__RUN_IN_ALL__ = False   # active WRITE attempt, needs a TSIG key: only when named in -ts

# Arbitrary/unrelated names a least-privilege key should NOT be able to write.
PROBE_LABELS = ("ptsrv-arbitrary1", "ptsrv-admin", "ptsrv-_acme-challenge")


def run(ctx):
    domains = [d.strip() for d in text_or_file(ctx.args.domain, ctx.args.domain_file) if d.strip()]
    if not domains:
        ctx.out("This test needs a domain; pass -d <domain> or -dl <file>.", "WARNING", indent=4)
        return
    if not getattr(ctx.args, "tsig_key", None):
        ctx.out("This test needs a TSIG key; pass --tsig-key <name:secret> (or name:alg:secret).", "WARNING", indent=4)
        return
    try:
        tsig = du.parse_tsig(ctx.args.tsig_key)
    except ValueError as e:
        ctx.out(f"Invalid --tsig-key: {e}", "ERROR", indent=4)
        return

    resolver = ec.resolver_for(ctx)

    for domain in domains:
        ctx.out(domain, "INFO", colortext=True, indent=4)
        servers = du.primary_ips(resolver, domain)
        if not servers:
            ctx.out("Could not resolve the zone's primary/authoritative servers.", "WARNING", indent=8)
            continue
        ip = servers[0]

        # First confirm the key is accepted at all.
        base = du.test_name(domain)
        rcode = du.add_txt(ip, domain, base, tsig=tsig)
        if rcode is None:
            ctx.out(f"No response to the TSIG update from {ip}.", "WARNING", indent=8)
            continue
        rtext = dns.rcode.to_text(rcode)
        if rcode == dns.rcode.NOTAUTH:
            ctx.out("TSIG key rejected (NOTAUTH) — bad key/algorithm or not permitted.", "OK", indent=8)
            continue
        if rcode != dns.rcode.NOERROR:
            ctx.out(f"TSIG update returned {rtext} — key not accepted for this write.", "OK", indent=8)
            continue

        du.verify_present(ip, base)
        du.delete_name(ip, domain, base, tsig=tsig)
        ctx.out("TSIG key accepted and can add records — now testing name scope.", "TEXT", indent=8)

        # Now test whether the key can write ARBITRARY/unrelated names (broad ACL).
        writable = []
        for label in PROBE_LABELS:
            name = f"{label}.{domain.rstrip('.')}"
            rc = du.add_txt(ip, domain, name, tsig=tsig)
            if rc == dns.rcode.NOERROR and du.verify_present(ip, name):
                writable.append(name)
                du.delete_name(ip, domain, name, tsig=tsig)  # cleanup
            elif rc == dns.rcode.NOERROR:
                du.delete_name(ip, domain, name, tsig=tsig)

        if writable:
            ctx.out(f"Key can write arbitrary/unrelated names ({len(writable)}) — update policy not "
                    "scoped (over-privileged).", "VULN", indent=8)
            for n in writable:
                ctx.out(f"    {n}", "TEXT", indent=8)
            with ctx.results_lock:
                ctx.properties.setdefault("tsig_acl", {})[domain] = "unrestricted"
                ctx.deferred_vulns.append({
                    "vuln_code": VULNS.TsigAcl.value,
                    "vuln_request": f"TSIG-signed UPDATE of arbitrary names in {domain}",
                    "vuln_response": "writable: " + ", ".join(writable),
                })
        else:
            ctx.out("Key could not write the arbitrary probe names — update policy appears scoped.", "OK", indent=8)
            with ctx.results_lock:
                ctx.properties.setdefault("tsig_acl", {})[domain] = "scoped"