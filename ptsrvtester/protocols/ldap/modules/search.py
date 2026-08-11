"""SEARCH — LDAP search."""
__MODULELABEL__ = "LDAP search"
__MODULECODE__ = "SEARCH"
__ORDER__ = 20

from ._common import eng


def run(ctx):
    e = eng(ctx)
    e.results.Search = e.ldap_search()
