"""CAPA — ID + CAPABILITY listing."""
from ._common import ensure_info

__MODULELABEL__ = ""  # section titles come from ID / CAPABILITY PLAIN/STARTTLS
__MODULECODE__ = "CAPA"
__ORDER__ = 20


def run(ctx):
    e = ensure_info(ctx, get_commands=True)
    if getattr(e.results, "info_error", None):
        return

    e._stream_capa_id_and_plain()

    info = e.results.info
    if info is None:
        return
    encrypted = bool(getattr(ctx, "tls", False) or getattr(ctx, "port", 0) == 993)
    capa = info.capability or []
    if encrypted or "STARTTLS" not in [c.upper() for c in capa]:
        return

    capa_stls = e.fetch_capability_after_starttls()
    if not capa_stls:
        return
    e.results.info = info._replace(capability_starttls=capa_stls)
    e._stream_capa_starttls()
