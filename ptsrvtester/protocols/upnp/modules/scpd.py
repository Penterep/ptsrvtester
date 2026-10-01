"""SCPD — read the advertised service action and state-variable schema."""

__MODULELABEL__ = "UPnP service descriptions"
__MODULECODE__ = "SCPD"
__ORDER__ = 35


def run(ctx) -> None:
    results = ctx.engine.scpd()
    described = sum(item["status"] == "described" for item in results)
    ctx.out(
        f"Service descriptions: {described}/{len(results)} ({ctx.engine.scpd_status})",
        "TEXT" if ctx.engine.scpd_status in ("complete", "no_services",) else "TITLE", indent=4,
    )
    for result in results:
        kind = repr((result["serviceType"] or "unknown")[:160])
        category = "TEXT" if result["status"] == "described" else "TITLE"
        ctx.out(f"{kind}  status={result['status']}", category, indent=8)
        if result["status"] == "described":
            description = result["description"]
            actions = description["actions"]
            variables = description["stateVariables"]
            ctx.out(
                f"Actions: {len(actions)}  state variables: {len(variables)}",
                "TEXT", indent=12,
            )
            for action in actions[:20]:
                ctx.out(f"Action: {action['name'][:160]!r}", "TEXT", indent=16)
            if len(actions) > 20:
                ctx.out(f"... {len(actions) - 20} further actions in JSON", "TEXT", indent=16)
        elif result.get("error"):
            ctx.out(f"Error: {result['error'][:160]!r}", "TITLE", indent=12)
        ctx.out()
