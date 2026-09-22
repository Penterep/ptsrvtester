"""TERRAPIN — CVE-2023-48795 prefix-truncation exposure (pre-auth).

Reads the server's KEXINIT off the wire (no authentication) and decides whether
the transport is Terrapin-exploitable: a vulnerable cipher mode
(``chacha20-poly1305@openssh.com`` or a CBC cipher + ``*-etm@openssh.com`` MAC)
combined with no strict-kex countermeasure (``kex-strict-s-v00@openssh.com`` not
advertised). See :mod:`..utils.protohygiene_core` for the verdict logic. Safe and
pre-auth, so it runs in the default sweep.
"""
from ptsrvtester.protocols.ssh.utils.ssh_helpers import read_kexinit
from ptsrvtester.protocols.ssh.utils.protohygiene_core import assess_terrapin
from ptsrvtester.protocols.ssh.utils.results import VULNS

__MODULELABEL__ = "Terrapin (CVE-2023-48795)"
__MODULECODE__ = "TERRAPIN"
__ORDER__ = 45


def run(ctx):
    ip, port = ctx.target
    try:
        kexinit = read_kexinit(ip, port)
    except Exception as e:
        ctx.out(f"Could not read KEXINIT from {ip}:{port}: {e}", "WARNING", indent=4)
        with ctx.results_lock:
            ctx.properties["terrapinStatus"] = str(e)
        return

    r = assess_terrapin(kexinit)
    if not r.readable:
        ctx.out("Terrapin: could not evaluate (no SSH-2 KEXINIT)", "WARNING", indent=4)
        for n in r.notes:
            ctx.out(n, "TEXT", indent=8)
        with ctx.results_lock:
            ctx.properties["terrapinStatus"] = "unreadable"
        return

    ctx.out(f"strict kex (kex-strict-s-v00@openssh.com): "
            f"{'advertised' if r.strict_kex else 'NOT advertised'}",
            "OK" if r.strict_kex else "TEXT", indent=4)
    if r.vulnerable_modes:
        ctx.out("Terrapin-affected modes offered: " + ", ".join(r.vulnerable_modes),
                "TEXT", indent=4)

    if r.is_finding:
        ctx.out("VULNERABLE to Terrapin (CVE-2023-48795) — no strict kex and a truncatable "
                "cipher mode is offered", "VULN", indent=4)
    elif r.strict_kex:
        ctx.out("Not vulnerable — strict kex is supported", "OK", indent=4)
    else:
        ctx.out("Not vulnerable — no Terrapin-affected cipher mode is offered", "OK", indent=4)

    for n in r.notes:
        ctx.out(n, "TEXT", indent=8)

    with ctx.results_lock:
        ctx.properties["terrapinVulnerable"] = bool(r.vulnerable)
        ctx.properties["terrapinStrictKex"] = bool(r.strict_kex)
        ctx.properties["terrapinModes"] = r.vulnerable_modes
        if r.is_finding:
            ctx.deferred_vulns.append({
                "vuln_code": VULNS.Terrapin.value,
                "vuln_request": "read server KEXINIT (kex/enc/mac name-lists)",
                "vuln_response": "no strict kex (kex-strict-s-v00@openssh.com) and Terrapin-affected "
                                 "mode(s) offered: " + ", ".join(r.vulnerable_modes),
            })
