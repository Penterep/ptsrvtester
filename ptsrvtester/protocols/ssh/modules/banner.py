"""BANNER — SSH identification banner + service fingerprint."""
from ptsrvtester.protocols.ssh.utils.helpers import vendor_from_cpe
from ptsrvtester.protocols.ssh.utils.service_identification import identify_service
from ptsrvtester.protocols.ssh.utils.ssh_helpers import grab_banner
from ptsrvtester.protocols.ssh.utils.results import VULNS

__MODULELABEL__ = "Banner"
__MODULECODE__ = "BANNER"
__ORDER__ = 10


def run(ctx):
    ip, port = ctx.target
    try:
        banner = grab_banner(ip, port)
    except Exception as e:
        msg = f"Failed to grab banner from the server {ip}:{port}: {e}"
        ctx.out(msg, "VULN", indent=4)
        with ctx.results_lock:
            ctx.properties["infoError"] = msg
        return

    sid = identify_service(banner)
    if sid is None:
        banner_cat = "NOTVULN"
    elif sid.version is not None:
        banner_cat = "VULN"
    else:
        banner_cat = "WARNING"
    ctx.out(banner, banner_cat, indent=4)

    with ctx.results_lock:
        ctx.properties["description"] = f"Banner: {banner}"
        ctx.properties["version"] = sid.version if sid else None
        ctx.properties["vendor"] = vendor_from_cpe(sid.cpe) if sid else None
        if sid is not None:
            ctx.properties["cpe"] = sid.cpe
            if sid.version is not None:
                ctx.deferred_vulns.append({"vuln_code": VULNS.Banner.value})

    if sid is not None:
        ctx.out("Service Identification", "INFO", colortext=True)
        ctx.out(f"Product:  {sid.product}", "TEXT", indent=4)
        ctx.out(f"Version:  {sid.version if sid.version else 'unknown'}", "TEXT", indent=4)
        ctx.out(f"CPE:      {sid.cpe}", "TEXT", indent=4)