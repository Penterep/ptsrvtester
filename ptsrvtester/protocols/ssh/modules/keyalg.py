"""KEYALG — host-key algorithms (from the shared ssh-audit scan).

Distinct from HOSTKEY, which fetches the actual server host key; this test reports
the *host-key algorithms* the server offers and flags the weak ones.
"""
from ptsrvtester.protocols.ssh.utils.sshaudit import report_algorithm_section

__MODULELABEL__ = "Host-key algorithms"
__MODULECODE__ = "KEYALG"
__ORDER__ = 41


def run(ctx):
    report_algorithm_section(ctx, "key", vuln_request="ssh-audit host-key algorithms")