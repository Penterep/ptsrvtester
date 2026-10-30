"""Result types shared by the SSH modules.

These are the same dataclasses / named tuples the old flat ``protocols/ssh.py``
used; they are collected here so every ``modules/*.py`` can import them from one
place (absolute import — the modules are loaded dynamically by BaseMain and have
no package parent, so relative imports would fail).
"""
from dataclasses import dataclass
from typing import NamedTuple

from ptsrvtester.protocols.ssh.utils.helpers import Creds


class PrivKeyDetails(NamedTuple):
    keypath: str
    passphrase: str | None


@dataclass(frozen=True)
class SSHCreds(Creds):
    privkey: PrivKeyDetails | None


class BadPubkeyResult(NamedTuple):
    bad: bool
    path: str


class VulnCollector:
    """Collects the codes of the SSH tests that found something, with the ``ctx``
    that reported each (so the SSH main can attach a per-module ``poc``).

    SSH emits ONE JSON vulnerability object per test code that reported a finding
    (``results.vulnerabilities`` is a list of ``{"vulnCode": ..., "poc": ...}``
    entries). A code is ``PTV-SVC-SSH-<MODULECODE>`` (``PTV-SVC-<PROTOCOL>-<CODE>``,
    matching the DNS scheme ``PTV-SVC-DNS-``), derived from the running module's
    ``-ts`` code.

    Injected onto every module's ``ctx`` as ``ctx.vulns`` by ``SSH._make_context``
    (wrapped in a per-ctx sink so each finding remembers its module); a module that
    finds something calls ``ctx.vulns.hit(ctx.module_code)``. The SSH main iterates
    :attr:`hits` in ``output()`` and adds each as a separate vulnerability via ptlibs
    ``add_vulnerability`` (which de-duplicates by code).
    """

    PROTOCOL = "SSH"

    def __init__(self) -> None:
        self._hits: list[tuple[str, object]] = []   # (code, ctx) in first-seen order
        self._seen: set[str] = set()

    def hit(self, module_code: str, ctx=None) -> None:
        """Record that the module identified by ``module_code`` found something."""
        code = f"PTV-SVC-{self.PROTOCOL}-{str(module_code).upper()}"
        if code in self._seen:
            return
        self._seen.add(code)
        self._hits.append((code, ctx))

    @property
    def codes(self) -> list[str]:
        """Just the finding codes, in first-seen order."""
        return [c for c, _ in self._hits]

    @property
    def hits(self) -> list[tuple[str, object]]:
        """``(code, ctx)`` pairs, so the main can slice each finding's log segment."""
        return list(self._hits)