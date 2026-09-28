"""NOTIFY — passively observe SSDP announcements from one selected host."""

__MODULELABEL__ = "Passive SSDP notifications"
__MODULECODE__ = "NOTIFY"
__ORDER__ = 50


def run(ctx) -> None:
    notifications = ctx.engine.notify()
    ctx.out(
        f"Notifications: {len(notifications)} ({ctx.engine.notify_status})",
        "TEXT", indent=4,
    )
    for item in notifications[:50]:
        category = "TEXT" if item["valid"] else "WARNING"
        nts = repr((item["nts"] or "unknown")[:80])
        nt = repr((item["nt"] or "unknown")[:160])
        usn = repr((item["usn"] or "unknown")[:160])
        ctx.out(f"{item['sourceIp']}  NTS={nts}  NT={nt}", category, indent=8)
        ctx.out(f"USN={usn}", "TEXT", indent=12)
        if item["validationErrors"]:
            ctx.out(
                f"Invalid notification: {', '.join(item['validationErrors'])}",
                "WARNING", indent=12,
            )
    if len(notifications) > 50:
        ctx.out(f"... {len(notifications) - 50} further notifications in JSON", "TEXT", indent=8)
