"""BRUTE — LDAP bruteforce."""
__MODULELABEL__ = "LDAP bruteforce"
__MODULECODE__ = "BRUTE"
__ORDER__ = 40

from ._common import eng


def run(ctx):
    e = eng(ctx)
    e.results.credentials = e.ldap_bruteforce()
