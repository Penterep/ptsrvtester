"""BANNER — LDAP banner."""
__MODULELABEL__ = "LDAP banner"
__MODULECODE__ = "BANNER"
__ORDER__ = 10

from ._common import eng


def run(ctx):
    e = eng(ctx)
    e.results.Banner = e.ldap_banner()
