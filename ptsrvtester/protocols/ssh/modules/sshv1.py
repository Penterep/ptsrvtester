"""SSHV1 — legacy SSH protocol version 1 support (pre-auth).

Reads the identification banner and decides whether the server still speaks SSH-1
(protocol version ``1.x`` = SSH-1 only, ``1.99`` = SSH-1 fallback available,
``2.0`` = SSH-2 only). SSH-1 is cryptographically broken, so any SSH-1 support is
a finding. See :mod:`..utils.protohygiene_core`. Safe and pre-auth, so it runs in
the default sweep.
"""
from ptsrvtester.protocols.ssh.utils.ssh_helpers import (
    grab_banner,
    service_reachable,
    unreachable_message,
)
from ptsrvtester.protocols.ssh.utils.protohygiene_core import assess_sshv1

__MODULELABEL__ = "SSH protocol 1 (legacy)"
__MODULECODE__ = "SSHV1"
__ORDER__ = 15


def run(ctx):
    ip, port = ctx.target
    if service_reachable(ctx) is False:
        ctx.out(unreachable_message(ip, port), "WARNING", indent=4)
        return

    ctx.debug(f"Reading the SSH banner from {ip}:{port} to detect protocol-1 support")
    try:
        banner = grab_banner(ip, port)
    except Exception as e:
        ctx.out(f"Could not read the SSH banner from {ip}:{port}: {e}", "WARNING", indent=4)
        return

    ctx.debug("Assessing the advertised protocol version")
    r = assess_sshv1(banner)
    if r.protoversion is None:
        ctx.out(f"Unrecognised identification string: {banner}", "WARNING", indent=4)
        return

    ctx.out("")
    ctx.out("Returned information:", "TEXT", indent=4)
    ctx.out(f"advertised protocol version: {r.protoversion}", "TEXT", indent=4)
    if r.only_v1:
        ctx.out("Server speaks SSH-1 ONLY (SSH-2 not offered) — legacy, cryptographically broken",
                "VULN", indent=4)
    elif r.supports_v1:
        ctx.out("Server offers SSH-1 fallback (protocol 1.99) — SSH-1 is cryptographically broken "
                "and should be disabled", "VULN", indent=4)
    else:
        ctx.out("SSH-1 not supported (SSH-2 only)", "OK", indent=4)

    if r.is_finding:
        ctx.vulns.hit(ctx.module_code)
