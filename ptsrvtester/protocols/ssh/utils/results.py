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
    """Collects the codes of the SSH tests that found something.

    SSH emits ONE JSON vulnerability object per test code that reported a finding
    (``results.vulnerabilities`` is a list of ``{"vulnCode": ...}`` entries). A code
    is ``PTV-SSH-<MODULECODE>`` (second position = protocol), derived from the
    running module's ``-ts`` code.

    Injected onto every module's ``ctx`` as ``ctx.vulns`` by ``SSH.build_context``;
    a module that finds something calls ``ctx.vulns.hit(ctx.module_code)``. The SSH
    main iterates :attr:`codes` in ``output()`` and adds each as a separate
    vulnerability via ptlibs ``add_vulnerability`` (which de-duplicates by code).
    """

    PROTOCOL = "SSH"

    def __init__(self) -> None:
        self.codes: list[str] = []

    def hit(self, module_code: str) -> None:
        """Record that the module identified by ``module_code`` found something."""
        code = f"PTV-{self.PROTOCOL}-{str(module_code).upper()}"
        if code not in self.codes:
            self.codes.append(code)