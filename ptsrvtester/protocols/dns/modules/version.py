"""VERSION — software/build disclosure via CHAOS-class TXT records.

Queries version.bind, hostname.bind, id.server and authors.bind (class CHAOS).
A server that answers leaks its software and often the exact build/OS, which
helps an attacker target known vulnerabilities — reported as a finding.
"""
from ptsrvtester.protocols.dns.utils import fingerprint_core as fp
from ptsrvtester.protocols.dns.utils.results import VULNS

__MODULELABEL__ = "Software version disclosure (CHAOS TXT)"
__MODULECODE__ = "VERSION"
__ORDER__ = 10


def run(ctx):
    target = fp.server_target(ctx)
    if target is None:
        ctx.out("This test needs a target DNS server; pass -tg <server>.", "WARNING", indent=4)
        return
    ip, port = target

    chaos = fp.collect_chaos(ip, port)
    disclosed = {name: vals for name, vals in chaos.items() if vals}

    for name in fp.CHAOS_NAMES:
        vals = chaos.get(name)
        if vals:
            ctx.out(f"{name:<15} {', '.join(vals)}", "VULN", indent=4)
        elif vals == []:
            ctx.out(f"{name:<15} refused / not set", "TEXT", indent=4)
        else:
            ctx.out(f"{name:<15} no response", "TEXT", indent=4)

    if not disclosed:
        ctx.out("No CHAOS TXT information disclosed.", "OK", indent=4)
        return

    ctx.out("Server discloses software/build information via CHAOS TXT.", "VULN", indent=4)

    version_string = (disclosed.get("version.bind") or [None])[0]
    product = version = None
    if version_string:
        product, version, _ = fp.identify_product(version_string)

    with ctx.results_lock:
        ctx.properties["software_type"] = "dns-server"
        for name, vals in disclosed.items():
            ctx.properties[name.replace(".", "_")] = ", ".join(vals)
        if version_string:
            ctx.properties["description"] = f"version.bind: {version_string}"
        if version:
            ctx.properties["version"] = ".".join(str(p) for p in version)
        if product:
            ctx.properties["vendor"] = product
        ctx.deferred_vulns.append({
            "vuln_code": VULNS.VersionDisclosure.value,
            "vuln_request": "CHAOS TXT: " + ", ".join(fp.CHAOS_NAMES),
            "vuln_response": "; ".join(f"{n}={', '.join(v)}" for n, v in disclosed.items()),
        })
