"""MAC — message authentication code algorithms (from the shared ssh-audit scan)."""
from ptsrvtester.protocols.ssh.utils.sshaudit import report_algorithm_section

__MODULELABEL__ = "MAC algorithms"
__MODULECODE__ = "MAC"
__ORDER__ = 43


def run(ctx):
    report_algorithm_section(ctx, "mac", vuln_request="ssh-audit MAC algorithms")