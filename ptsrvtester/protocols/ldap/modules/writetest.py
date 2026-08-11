"""WRITETEST — LDAP write access."""
__MODULELABEL__ = "LDAP write access"
__MODULECODE__ = "WRITETEST"
__ORDER__ = 50

from ._common import eng


def run(ctx):
    e = eng(ctx)
    e.results.Writetest = e.ldap_check_write_access()
