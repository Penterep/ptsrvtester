"""CAPA — capability listing."""
import sys

from ..utils.connection import fetch_capa_after_stls, require_server_info
from ..utils.results import InfoResult
from ..utils.render import emit_capa_section

__MODULELABEL__ = ""  # section titles come from emit_capa (CAPA command PLAIN/STLS/…)
__MODULECODE__ = "CAPA"
__ORDER__ = 20


def _flush(ctx) -> None:
    """Print buffered lines now so -vv debug and CAPA results stay in probe order."""
    if ctx.json:
        return
    lock = ctx.print_lock
    chunk = lock.get_output_string()
    if chunk:
        sys.stdout.write(chunk)
        sys.stdout.flush()
        lock.output_string = ""


def run(ctx):
    info = require_server_info(ctx)
    if info is None:
        return
    _flush(ctx)

    encrypted = ctx.port == 995 or ctx.tls
    json_lines: list[str] = []

    if info.capability is not None:
        title = "CAPA command (TLS)" if encrypted else "CAPA command (PLAIN)"
        json_lines += emit_capa_section(ctx, title, info.capability, encrypted)
        _flush(ctx)

    if encrypted or not info.capability or "STLS" not in info.capability:
        if json_lines:
            ctx.report.update_properties(capability="\n".join(json_lines))
        return

    capa_stls = fetch_capa_after_stls(ctx.args, debug=ctx.debug)
    _flush(ctx)
    if capa_stls:
        json_lines.append("---")
        json_lines += emit_capa_section(ctx, "CAPA command (STLS)", capa_stls, True)
        _flush(ctx)
        ctx.server_info._info = InfoResult(info.banner, info.capability, capa_stls)

    if json_lines:
        ctx.report.update_properties(capability="\n".join(json_lines))
