"""KEX — key exchange algorithms (from the shared ssh-audit scan)."""
from ptsrvtester.protocols.ssh.utils.sshaudit import report_algorithm_section

__MODULELABEL__ = "Key exchange algorithms"
__MODULECODE__ = "KEX"
__ORDER__ = 40


def run(ctx):
    report_algorithm_section(ctx, "kex", vuln_request="ssh-audit key exchange (kex)")