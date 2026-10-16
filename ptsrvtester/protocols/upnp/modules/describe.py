"""DESCRIBE — retrieve safe UPnP device and service descriptions."""

__MODULELABEL__ = "UPnP device descriptions"
__MODULECODE__ = "DESCRIBE"
__ORDER__ = 20


def run(ctx) -> None:
    devices = ctx.engine.describe()
    ctx.out(
        f"Descriptions: {len(devices)} ({ctx.engine.description_status})",
        "TEXT" if ctx.engine.description_status in ("complete",) else "TITLE",
        indent=4,
    )
    for item in devices:
        location = repr(item["location"][:200])
        if item["status"] == "described":
            device = item["description"]["device"]
            name = repr((device["friendlyName"] or "unnamed")[:160])
            kind = repr((device["deviceType"] or "unknown")[:160])
            ctx.out(
                f"{name}  type={kind}  services={len(device['services'])}  "
                f"embedded={len(device['embeddedDevices'])}",
                "TEXT", indent=8,
            )
            ctx.out(f"LOCATION={location}", "TEXT", indent=12)
        else:
            error = repr((item.get("error") or item["status"])[:160])
            ctx.out(f"{location}: {item['status']} ({error})", "TITLE", indent=8)
        ctx.out()
