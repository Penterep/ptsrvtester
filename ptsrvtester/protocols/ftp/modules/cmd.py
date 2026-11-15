"""CMD — HELP / SYST / STAT, plus SITE extensions."""
__MODULELABEL__ = ""  # section title is printed with the command list
__MODULECODE__ = "CMD"
__ORDER__ = 20

from ..utils.helpers import check_if_brute
from ._common import eng, ensure_creds, ensure_info


def _wants_login(ctx) -> bool:
    return bool(getattr(ctx.args, "anonymous", False) or check_if_brute(ctx.args))


def _site_listed(e, help_text: str | None) -> bool:
    listed = {name for name, _implemented in e._ftp_help_command_rows(help_text or "")}
    return "SITE" in listed


def run(ctx):
    e = eng(ctx)
    e.results.commands_requested = True
    live = not e.use_json
    want_login = _wants_login(ctx)
    row_indent = 8 if want_login else 4
    if live:
        # The summary printer would repeat the headings after the exchange.
        e._commands_streamed = True
        title = "FTP commands (TLS)" if e._ftp_commands_encrypted() else "FTP commands (PLAIN)"
        e._tprint(title, "INFO", indent=0)
        e._modes_vv_indent = row_indent
        if want_login:
            e._tprint("Before login", "INFO", indent=4)
    try:
        e = ensure_info(ctx, get_commands=True)
        if getattr(e.results, "info_error", None):
            return
        info = e.results.info
        if live and info is not None:
            e._stream_command_rows(info.help_response, info.syst, info.stat, indent=row_indent)
        if want_login:
            if live:
                print()
                e._tprint("After login", "INFO", indent=4)
                e._modes_vv_indent = row_indent
            creds = ensure_creds(ctx)
            if creds is None:
                e._commands_login_note = e._missing_login_line()
                if live:
                    e._tprint(e._commands_login_note, "WARNING", indent=row_indent)
            else:
                e._commands_reread(creds)
                note = getattr(e, "_commands_login_note", None)
                if note and live:
                    e._tprint(note, "WARNING", indent=row_indent)
                elif live:
                    info = e.results.info
                    if info is not None:
                        e._stream_command_rows(info.help_response, info.syst, info.stat, indent=row_indent)
        info = e.results.info
        if info is not None and _site_listed(e, info.help_response):
            if live:
                print()
                e._tprint("SITE extensions", "INFO", indent=4)
                e._modes_vv_indent = 8
            e._collect_site_extensions()
            if live:
                e._stream_site_names()
        e._record_command_findings()
    finally:
        e._modes_vv_indent = None
    e._stream_commands_result()
