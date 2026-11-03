"""BANNER — SSH identification banner + service fingerprint.

The raw banner is taken from the shared ssh-audit scan when available (ssh-audit
reports it anyway, so this avoids a duplicate connection), falling back to a
direct socket read if ssh-audit did not run or failed. Product/version/CPE
identification (identify_service) is applied on top of whichever banner we got.
"""
from ptsrvtester.protocols.ssh.utils.service_identification import identify_service
from ptsrvtester.protocols.ssh.utils.ssh_helpers import grab_banner, unreachable_message

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


def _seed_reachable(ctx, ip, port, reachable: bool) -> None:
    """Seed the run-shared reachability cache so later service tests skip re-probing."""
    cache = getattr(ctx, "reach_cache", None)
    if cache is not None:
        cache[(ip, port)] = reachable


def run(ctx):
    ip, port = ctx.target
    ctx.debug(f"Retrieving the SSH identification banner from {ip}:{port}")
    try:
        banner = _get_banner(ctx)
    except Exception as e:
        # No banner at all -> not a reachable SSH service. Seed the cache so the
        # other service tests short-circuit, and say the run is moot here.
        _seed_reachable(ctx, ip, port, False)
        ctx.debug(f"Banner grab failed: {e}")
        ctx.out(unreachable_message(ip, port), "WARNING", indent=4)
        return
    _seed_reachable(ctx, ip, port, True)

    ctx.debug("Identifying the product and version from the banner")
    sid = identify_service(banner)
    ctx.debug(
        f"Service identified as {sid.product} {sid.version or '(version unknown)'}"
        if sid else "Service could not be identified from the banner"
    )
    if sid is None:
        banner_cat = "NOTVULN"
    elif sid.version is not None:
        banner_cat = "VULN"
    else:
        banner_cat = "WARNING"

    ctx.out("")
    ctx.out("Returned information:", "TEXT", indent=4)
    ctx.out(banner, banner_cat, indent=4)

    if sid is not None and sid.version is not None:
        ctx.vulns.hit(ctx.module_code)

    if sid is not None:
        ctx.out(f"{'Product':<9}{sid.product}", "TEXT", indent=4)
        ctx.out(f"{'Version':<9}{sid.version if sid.version else 'unknown'}", "TEXT", indent=4)
        if sid.cpe:
            ctx.out(f"{'CPE':<9}{sid.cpe}", "TEXT", indent=4)