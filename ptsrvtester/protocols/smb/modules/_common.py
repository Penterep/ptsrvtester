from ..smb_utils.helpers import SMBResults
from ..smb_utils.server_connection import ServerConnection
from ptsrvtester.protocols._base import ModuleContext


def get_output(ctx: ModuleContext) -> SMBResults | None:
    ip, port = ctx.target
    output: SMBResults = ctx.output

    ran_now = False
    if not output.has_ran:
        ctx.out(f"IP address:              {ip}", "INFO", indent=4)
        ctx.out(f"Port:                    {port}", "INFO", indent=4)
        ran_now = True
        ServerConnection(ctx).connect()

    if output.had_error:
        ctx.out(f"Could not connect to server: {output.error_info}", "ERROR", indent=4, condition=ran_now)
        return None
    return output
