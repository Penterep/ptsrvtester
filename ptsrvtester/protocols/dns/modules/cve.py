"""CVE — match the advertised software version against known CVEs.

Re-reads version.bind, identifies the product/version (BIND / Unbound /
PowerDNS / Knot / dnsmasq / Windows DNS) and checks it against a seed table of
well-known CVEs. This is INDICATIVE only: it trusts the advertised banner
(which can be hidden or spoofed) and the table is a maintained starting point,
not exhaustive. Any match is reported as a finding to be confirmed manually.
"""
from ptsrvtester.protocols.dns.utils import fingerprint_core as fp
from ptsrvtester.protocols.dns.utils.results import VULNS

__MODULELABEL__ = "Known-CVE match for advertised version"
__MODULECODE__ = "CVE"
__ORDER__ = 60


def run(ctx):
    target = fp.server_target(ctx)
    if target is None:
        ctx.out("This test needs a target DNS server; pass -tg <server>.", "WARNING", indent=4)
        return
    ip, port = target

    values = fp.chaos_txt(ip, port, "version.bind")
    version_string = values[0] if values else None
    if not version_string:
        ctx.out("No version.bind disclosed — cannot match CVEs from the banner.", "OK", indent=4)
        ctx.out("(Windows DNS never answers CHAOS TXT; try other fingerprinting.)", "ADDITIONS", colortext=True, indent=4)
        return

    product, version, note = fp.identify_product(version_string)
    ctx.out(f"{'Advertised':<12} {version_string}", "TEXT", indent=4)
    ctx.out(f"{'Product':<12} {product or 'unknown'}" + (f"  ({note})" if note else ""), "TEXT", indent=4)
    ctx.out(f"{'Version':<12} {'.'.join(str(p) for p in version) if version else 'unparsed'}", "TEXT", indent=4)

    if product is None or version is None:
        ctx.out("Could not identify product/version from the banner — no CVE match attempted.", "WARNING", indent=4)
        return

    matches = fp.match_cves(product, version)
    if not matches:
        ctx.out("No seed-table CVE matches the advertised version (table is not exhaustive).", "OK", indent=4)
        return

    ctx.out("Advertised version matches known CVE(s) — confirm manually:", "VULN", indent=4)
    for entry in matches:
        ctx.out(f"  {entry.cve}: {entry.summary}", "VULN", indent=4)

    with ctx.results_lock:
        ctx.properties["cve_matches"] = [m.cve for m in matches]
        ctx.deferred_vulns.append({
            "vuln_code": VULNS.KnownCve.value,
            "vuln_request": f"version.bind = {version_string} ({product})",
            "vuln_response": "; ".join(f"{m.cve}: {m.summary}" for m in matches),
        })
