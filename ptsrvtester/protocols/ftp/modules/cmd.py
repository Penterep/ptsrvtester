"""CMD — HELP / SYST / STAT, plus SITE extensions."""
__MODULELABEL__ = ""  # section title is printed with the command list
__MODULECODE__ = "CMD"
__ORDER__ = 20

from ..utils.helpers import check_if_brute
from ._common import eng, ensure_creds, ensure_info


def run(ctx):
    e = eng(ctx)
    e.results.commands_requested = True
    e = ensure_info(ctx, get_commands=True)
    if getattr(e.results, "info_error", None):
        return
    if getattr(ctx.args, "anonymous", False) or check_if_brute(ctx.args):
        creds = ensure_creds(ctx)
        if creds is None:
            e._commands_login_note = e._missing_login_line()
        else:
            e._commands_reread(creds)
    e._collect_site_extensions()
    e._record_command_findings()
    e._stream_commands_result()

