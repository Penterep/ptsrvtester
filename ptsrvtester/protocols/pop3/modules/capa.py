"""CAPA — capability listing."""
from ..utils.connection import fetch_capa_after_stls, require_server_info
from ..utils.results import InfoResult, VULNS
from ..utils.render import emit_capa_section

_AUTH_PLAIN = frozenset({"PLAIN", "LOGIN"})
_AUTH_WEAK = frozenset({"CRAM-MD5", "DIGEST-MD5", "NTLM", "ANONYMOUS", "KERBEROS_V4"})


def _sasl_methods(capa: dict) -> list[str]:
    for key, vals in capa.items():
        if str(key).upper() != "SASL":
            continue
        return [str(v).upper() for v in (vals or [])]
    return []


def _capa_body(capa: dict, capa_text: str | None) -> str:
    """Server CAPA lines. Fall back to one line per capability when the raw reply was not kept."""
    if capa_text:
        return capa_text
    lines = []
    for key, vals in capa.items():
        extra = " ".join(str(v) for v in (vals or []))
        lines.append(f"{key} {extra}".strip())
    return "\n".join(lines)


def _mark_capa(text: str, tokens: frozenset[str]) -> str:
    """Wrap only the lines that advertise one of ``tokens``. The other lines stay as sent."""
    marked = []
    for line in text.splitlines():
        parts = line.split()
        key = parts[0].upper() if parts else ""
        args = {part.upper() for part in parts[1:]}
        hit = (key == "USER" and "USER" in tokens) or (key == "SASL" and bool(args & tokens))
        marked.append(f"**{line}**" if hit else line)
    return "\n".join(marked)


def _record_cleartext_auth(ctx, capa: dict, capa_text: str | None = None) -> None:
    """Cleartext CAPA only. PLAIN/LOGIN/USER and the other weak SASL methods."""
    advertised = _sasl_methods(capa)
    plain = [name for name in advertised if name in _AUTH_PLAIN]
    if any(str(key).upper() == "USER" for key in capa):
        plain = ["USER", *plain]
    weak = [name for name in advertised if name in _AUTH_WEAK]
    body = _capa_body(capa, capa_text)
    if plain and body:
        ctx.report.note_poc(VULNS.AuthPlain.value, ("CAPA", _mark_capa(body, _AUTH_PLAIN | {"USER"})))
        ctx.report.add_vulnerability(vuln_code=VULNS.AuthPlain.value)
    if weak and body:
        ctx.report.note_poc(VULNS.AuthWeak.value, ("CAPA", _mark_capa(body, _AUTH_WEAK)))
        ctx.report.add_vulnerability(vuln_code=VULNS.AuthWeak.value)

__MODULELABEL__ = ""  # section titles come from emit_capa (CAPA command PLAIN/STLS/…)
__MODULECODE__ = "CAPA"
__ORDER__ = 20


def run(ctx):
    info = require_server_info(ctx)
    if info is None:
        return

    encrypted = ctx.port == 995 or ctx.tls
    json_lines: list[str] = []

    if info.capability is not None:
        title = "CAPA command (TLS)" if encrypted else "CAPA command (PLAIN)"
        json_lines += emit_capa_section(ctx, title, info.capability, encrypted)
        if not encrypted:
            _record_cleartext_auth(ctx, info.capability, info.capa_text)

    if encrypted or not info.capability or "STLS" not in info.capability:
        if json_lines:
            ctx.report.update_properties(capability="\n".join(json_lines))
        return

    capa_stls = fetch_capa_after_stls(ctx.args, debug=ctx.debug)
    if capa_stls:
        json_lines.append("---")
        json_lines += emit_capa_section(ctx, "CAPA command (STLS)", capa_stls, True)
        ctx.server_info._info = InfoResult(
            info.banner, info.capability, capa_stls, info.capa_text,
        )

    if json_lines:
        ctx.report.update_properties(capability="\n".join(json_lines))
