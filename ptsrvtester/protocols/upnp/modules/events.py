"""EVENTS: explicitly subscribe to bounded GENA property changes."""

__MODULELABEL__ = "UPnP GENA events"
__MODULECODE__ = "EVENTS"
__ORDER__ = 60


def run(ctx) -> None:
    results = ctx.engine.events()
    ctx.out(
        f"GENA events: {ctx.engine.event_count} across {len(results)} services "
        f"({ctx.engine.event_status})",
        "TEXT" if ctx.engine.event_status in ("complete", "no_services",) else "TITLE", indent=4,
    )
    for result in results:
        category = "TEXT" if result["status"] in ("complete", "no_events") else "TITLE"
        ctx.out(
            f"{result['serviceType'][:160]!r}  events={len(result['events'])}  "
            f"status={result['status']}",
            category, indent=8,
        )
        if result.get("error"):
            ctx.out(f"Error: {result['error'][:160]!r}", "TITLE", indent=12)
        if result.get("unsubscribeError"):
            ctx.out(
                f"UNSUBSCRIBE: {result['unsubscribeError'][:160]!r}",
                "TITLE", indent=12,
            )
        for event in result["events"][:20]:
            ctx.out(
                f"SEQ={event['seq']}  properties={event['properties']!r}"[:300],
                "TEXT", indent=12,
            )
        if len(result["events"]) > 20:
            ctx.out(
                f"... {len(result['events']) - 20} further events in JSON",
                "TEXT", indent=12,
            )
        ctx.out()
