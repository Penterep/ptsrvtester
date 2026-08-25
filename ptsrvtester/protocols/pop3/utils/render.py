"""Shared text rendering helpers for POP3 modules (ctx.out based)."""
from __future__ import annotations

from .capa import capa_level_bullet, parse_capa_commands
from .helpers import vendor_from_cpe
from .results import VULNS
from .service_identification import identify_service


def emit_banner(ctx, info) -> None:
    if not info or info.banner is None:
        return
    sid = identify_service(info.banner)
    if sid is None:
        bullet = "NOTVULN"
    elif sid.version is not None:
        bullet = "VULN"
    else:
        bullet = "WARNING"
    ctx.out(info.banner, bullet, indent=4)
    if sid is not None:
        ctx.out("Service Identification", "INFO", colortext=True)
        ctx.out(f"Product:  {sid.product}", "TEXT", indent=4)
        ctx.out(f"Version:  {sid.version if sid.version else 'unknown'}", "TEXT", indent=4)
        ctx.out(f"CPE:      {sid.cpe}", "TEXT", indent=4)
        ctx.report.update_properties(
            description=f"Banner: {info.banner}",
            version=sid.version,
            vendor=vendor_from_cpe(sid.cpe),
            cpe=sid.cpe,
        )
        if sid.version is not None:
            ctx.report.add_vulnerability(vuln_code=VULNS.Banner.value)
    else:
        ctx.report.update_properties(description=f"Banner: {info.banner}")


def emit_capa_section(ctx, title: str, capa: dict, enc: bool) -> list[str]:
    ctx.out(title, "INFO", colortext=True)
    lines = []
    for display, level in parse_capa_commands(capa, enc):
        ctx.out(display, capa_level_bullet(level), indent=4)
        lines.append(display)
    return lines


def emit_capa(ctx, info) -> None:
    if not info or not (info.capability or info.capability_stls):
        return
    encrypted = ctx.port == 995 or ctx.tls
    capa_stls = info.capability_stls

    json_lines: list[str] = []
    if info.capability is not None and capa_stls is not None:
        json_lines = emit_capa_section(ctx, "CAPA command (PLAIN)", info.capability, False)
        json_lines.append("---")
        json_lines += emit_capa_section(ctx, "CAPA command (STLS)", capa_stls, True)
    elif info.capability is not None:
        title = "CAPA command (TLS)" if encrypted else "CAPA command (PLAIN)"
        json_lines = emit_capa_section(ctx, title, info.capability, encrypted)
    if json_lines:
        ctx.report.update_properties(capability="\n".join(json_lines))


def emit_helpinfo(ctx, help_response: str | None, implementation: str | None) -> None:
    if help_response is not None:
        ctx.out("HELP:", "WARNING", indent=4)
        for line in help_response.splitlines():
            ctx.out(line, "TEXT", indent=8)
        ctx.report.update_properties(helpCommand=help_response)
    else:
        ctx.out("HELP: not supported", "NOTVULN", indent=4)

    if implementation is not None:
        ctx.out(f"IMPLEMENTATION: {implementation}", "WARNING", indent=4)
        ctx.report.update_properties(implementation=implementation)
    else:
        ctx.out("IMPLEMENTATION: not advertised in CAPA", "NOTVULN", indent=4)
