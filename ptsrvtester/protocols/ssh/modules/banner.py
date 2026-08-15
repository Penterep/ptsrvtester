"""BANNER — SSH identification banner + service fingerprint.

The raw banner is taken from the shared ssh-audit scan when available (ssh-audit
reports it anyway, so this avoids a duplicate connection), falling back to a
direct socket read if ssh-audit did not run or failed. Product/version/CPE
identification (identify_service) is applied on top of whichever banner we got.
"""
from ptsrvtester.protocols.ssh.utils.helpers import vendor_from_cpe
from ptsrvtester.protocols.ssh.utils.service_identification import identify_service
from ptsrvtester.protocols.ssh.utils.ssh_helpers import grab_banner
from ptsrvtester.protocols.ssh.utils.results import VULNS

__MODULELABEL__ = "Banner"
__MODULECODE__ = "BANNER"
__ORDER__ = 10


def _get_banner(ctx) -> str:
    """Prefer the ssh-audit banner (no extra connection); fall back to a socket read."""
    run = ctx.ssh_audit.get()
    if run.ok:
        raw = ((run.data or {}).get("banner") or {}).get("raw")
        if raw and raw.strip():
            return raw.strip()
    ip, port = ctx.target
    return grab_banner(ip, port)


def run(ctx):
    ip, port = ctx.target
    try:
        banner = _get_banner(ctx)
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
            if sid.cpe:
                ctx.properties["cpe"] = sid.cpe
            if sid.version is not None:
                ctx.deferred_vulns.append({"vuln_code": VULNS.Banner.value})

    if sid is not None:
        ctx.out("Service Identification", "INFO", colortext=True)
        ctx.out(f"Product:  {sid.product}", "TEXT", indent=4)
        ctx.out(f"Version:  {sid.version if sid.version else 'unknown'}", "TEXT", indent=4)
        if sid.cpe:
            ctx.out(f"CPE:      {sid.cpe}", "TEXT", indent=4)