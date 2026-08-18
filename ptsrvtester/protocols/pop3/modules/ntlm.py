"""NTLM — NTLMSSP challenge information disclosure."""
from ..utils.connection import auth_ntlm
from ..utils.results import VULNS

__MODULELABEL__ = "NTLM information"
__MODULECODE__ = "NTLM"
__ORDER__ = 40


def run(ctx):
    result = auth_ntlm(ctx.args, debug=ctx.debug)
    if not result.success or result.ntlm is None:
        ctx.out("Not available", "NOTVULN", indent=4)
        ctx.report.update_properties(ntlmInfoStatus="failed")
        return

    lines = [
        f"Target name: {result.ntlm.target_name}",
        f"NetBios domain name: {result.ntlm.netbios_domain}",
        f"NetBios computer name: {result.ntlm.netbios_computer}",
        f"DNS domain name: {result.ntlm.dns_domain}",
        f"DNS computer name: {result.ntlm.dns_computer}",
        f"DNS tree: {result.ntlm.dns_tree}",
        f"OS version: {result.ntlm.os_version}",
    ]
    ctx.out("NTLM information", "VULN", indent=4)
    for line in lines:
        for part in (line or "").replace("\r", "").splitlines():
            ctx.out(part, "TEXT", indent=8)

    ctx.report.update_properties(ntlmInfoStatus="ok")
    ctx.report.add_vulnerability(
        vuln_code=VULNS.NTLM.value,
        vuln_request="ntlm authentication",
        vuln_response="\n".join(lines),
    )
