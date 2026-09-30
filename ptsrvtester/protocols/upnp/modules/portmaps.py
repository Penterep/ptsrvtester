"""PORTMAPS — explicitly enumerate a bounded number of IGD port mappings."""

__MODULELABEL__ = "UPnP IGD port mappings"
__MODULECODE__ = "PORTMAPS"
__ORDER__ = 40


def run(ctx) -> None:
    results = ctx.engine.port_mappings()
    count = sum(len(result["entries"]) for result in results)
    ctx.out(
        f"Port mappings: {count} across {len(results)} IGD services "
        f"({ctx.engine.port_mapping_status})",
        "TEXT", indent=4,
    )
    for result in results:
        service = repr(result["serviceType"][:160])
        category = "TEXT" if result["status"] == "complete" else "WARNING"
        ctx.out(
            f"{service}  entries={len(result['entries'])}  status={result['status']}",
            category, indent=8,
        )
        if result.get("error"):
            ctx.out(f"Error: {result['error'][:160]!r}", "WARNING", indent=12)
        for entry in result["entries"]:
            external = entry.get("NewExternalPort", "")[:32]
            protocol = entry.get("NewProtocol", "")[:32]
            internal = entry.get("NewInternalClient", "")[:160]
            internal_port = entry.get("NewInternalPort", "")[:32]
            description = entry.get("NewPortMappingDescription", "")[:160]
            ctx.out(
                f"[{entry['index']}] {external!r}/{protocol!r} -> "
                f"{internal!r}:{internal_port!r}  {description!r}",
                "TEXT", indent=12,
            )
