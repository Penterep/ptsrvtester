"""IGDINFO — read selected status values from advertised gateway services."""

__MODULELABEL__ = "UPnP IGD status"
__MODULECODE__ = "IGDINFO"
__ORDER__ = 30


def run(ctx) -> None:
    results = ctx.engine.igd_info()
    ctx.out(f"IGD services: {len(results)} ({ctx.engine.igd_status})", "TEXT" if ctx.engine.igd_status in ("complete", "no_services",) else "TITLE", indent=4)
    for result in results:
        service = repr(result["serviceType"][:160])
        udn = repr((result["udn"] or "unknown")[:160])
        category = "TEXT" if result["status"] == "complete" else "TITLE"
        ctx.out(f"{service}  UDN={udn}  status={result['status']}", category, indent=8)
        if result.get("error"):
            ctx.out(f"Error: {result['error'][:160]!r}", "TITLE", indent=12)
        for action, entry in result["actions"].items():
            state = entry["status"]
            ctx.out(f"{action}: {state}", "TEXT" if state == "ok" else "TITLE", indent=12)
            if state == "ok":
                for key, value in entry["values"].items():
                    ctx.out(f"{key}={value[:160]!r}", "TEXT", indent=16)
            else:
                detail = entry.get("error") or entry.get("errorCode") or entry.get("httpStatus")
                if detail is not None:
                    ctx.out(f"Detail: {str(detail)[:160]!r}", "TITLE", indent=16)
        ctx.out()
