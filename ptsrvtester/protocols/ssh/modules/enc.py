"""ENC — encryption algorithms / ciphers (from the shared ssh-audit scan)."""
from ptsrvtester.protocols.ssh.utils.sshaudit import report_algorithm_section

__MODULELABEL__ = "Encryption algorithms (ciphers)"
__MODULECODE__ = "ENC"
__ORDER__ = 42


def run(ctx):
    report_algorithm_section(ctx, "enc", vuln_request="ssh-audit encryption (ciphers)")