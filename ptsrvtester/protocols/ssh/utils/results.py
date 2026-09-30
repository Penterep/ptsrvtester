"""Result types shared by the SSH modules.

These are the same dataclasses / named tuples the old flat ``protocols/ssh.py``
used; they are collected here so every ``modules/*.py`` can import them from one
place (absolute import — the modules are loaded dynamically by BaseMain and have
no package parent, so relative imports would fail).
"""
from dataclasses import dataclass
from enum import Enum
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


class VULNS(Enum):
    InsecureCrypto = "PTV-GENERAL-INSECURECRYPTO"
    BadHostKey = "PTV-SSH-BADHOSTKEY"
    BadAuthKeys = "PTV-SSH-BADAUTHKEYS"
    WeakCreds = "PTV-GENERAL-WEAKCREDENTIALS"
    Banner = "PTV-SVC-BANNER"
    DHEat = "PTV-SSH-DHEAT"
    # Missing brute-force protection (LOCKOUT test):
    NoAccountLockout = "PTV-SSH-NOACCOUNTLOCKOUT"
    NoIpBlocking = "PTV-SSH-NOIPBLOCKING"
    # Username enumeration via auth timing side-channel (USERENUM test):
    UserEnum = "PTV-SSH-USERENUM"
    # Direct root login permitted (ROOTLOGIN test):
    RootLoginPermitted = "PTV-SSH-ROOTLOGIN"
    # Shell / command execution permitted after login (SHELL test):
    ShellAccess = "PTV-SSH-SHELLACCESS"
    # Post-auth privileges & access (PRIVS test):
    PrivilegedGroup = "PTV-SSH-PRIVGROUP"
    SensitiveFileAccess = "PTV-SSH-SENSITIVEFILE"
    SudoAccess = "PTV-SSH-SUDOACCESS"
    # Port forwarding & tunneling (FORWARD test):
    PortForwarding = "PTV-SSH-PORTFORWARDING"
    AgentForwarding = "PTV-SSH-AGENTFORWARDING"
    X11Forwarding = "PTV-SSH-X11FORWARDING"
    # SFTP access control & confinement (SFTP test):
    SftpNoChroot = "PTV-SSH-SFTPNOCHROOT"
    SftpTraversal = "PTV-SSH-SFTPTRAVERSAL"
    SftpSymlinkEscape = "PTV-SSH-SFTPSYMLINK"
    SftpUnrestricted = "PTV-SSH-SFTPUNRESTRICTED"
    SftpADS = "PTV-SSH-SFTPADS"
    # SFTP content scanning & resource limits (SFTPDATA test):
    SftpNoAntivirus = "PTV-SSH-SFTPNOAV"
    SftpContentProcessingDoS = "PTV-SSH-SFTPPROCESSINGDOS"
    SftpNoQuota = "PTV-SSH-SFTPNOQUOTA"
    # Protocol & config hygiene (TERRAPIN / SSHV1 tests):
    Terrapin = "PTV-SSH-TERRAPIN"
    SSHv1 = "PTV-SSH-SSHV1"