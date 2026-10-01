"""DISCOVER — query a targeted SSDP endpoint for UPnP advertisements."""

__MODULELABEL__ = "SSDP device discovery"
__MODULECODE__ = "DISCOVER"
__ORDER__ = 10


def run(ctx) -> None:
    discoveries = ctx.engine.discover()
    ctx.out(
        f"Responses: {len(discoveries)} ({ctx.engine.discovery_status})",
        "TEXT" if ctx.engine.discovery_status in ("complete",) else "TITLE",
        indent=4,
    )
    for error in ctx.engine.module_errors:
        if error["test"] == "DISCOVER":
            ctx.out(error["error"], "TITLE", indent=4)
    if not any(response["valid"] for response in discoveries):
        ctx.out("No usable SSDP response; UPnP availability is undetermined", "TITLE", indent=4)
    for response in discoveries:
        source = response["sourceIp"]
        st = repr((response["st"] or "unknown")[:160])
        usn = repr((response["usn"] or "unknown")[:160])
        location = repr((response["location"] or "unknown")[:200])
        category = "TEXT" if response["valid"] else "TITLE"
        ctx.out(f"{source}  ST={st}  USN={usn}", category, indent=8)
        ctx.out(f"LOCATION={location}", "TEXT", indent=12)
        if response["validationErrors"]:
            ctx.out(
                f"Invalid response: {', '.join(response['validationErrors'])}",
                "TITLE", indent=12,
            )
        ctx.out()
