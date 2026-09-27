"""CAPA — ID + CAPABILITY listing."""
import sys

from ._common import ensure_info

__MODULELABEL__ = ""  # section titles come from ID / CAPABILITY PLAIN/STARTTLS
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
    e = ensure_info(ctx, get_commands=True)
    if getattr(e.results, "info_error", None):
        return
    _flush(ctx)

    e._stream_capa_id_and_plain()
    _flush(ctx)

    info = e.results.info
    if info is None:
        return
    encrypted = bool(getattr(ctx, "tls", False) or getattr(ctx, "port", 0) == 993)
    capa = info.capability or []
    if encrypted or "STARTTLS" not in [c.upper() for c in capa]:
        return

    capa_stls = e.fetch_capability_after_starttls()
    _flush(ctx)
    if not capa_stls:
        return
    e.results.info = info._replace(capability_starttls=capa_stls)
    e._stream_capa_starttls()
    _flush(ctx)
