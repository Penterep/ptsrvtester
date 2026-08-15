"""USERENUM — LDAP user enumeration."""
__MODULELABEL__ = "LDAP user enumeration"
__MODULECODE__ = "USERENUM"
__ORDER__ = 30

from ._common import eng


def run(ctx):
    e = eng(ctx)
    e.results.usernames = e.ldap_enumerate_users()
