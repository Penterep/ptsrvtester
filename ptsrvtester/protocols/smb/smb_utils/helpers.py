from dataclasses import dataclass
from typing import Optional, Protocol, TYPE_CHECKING
import argparse, ipaddress, socket

from ptlibs.ptjsonlib import PtJsonLib

if TYPE_CHECKING:
    from .cli import SMBArgs


@dataclass
class Target:
    ip: str
    port: int


class SMBContext(Protocol):
    """Quality of life structural type for the ``ctx`` a module's ``run(ctx)`` receives.

    Never instantiated - only exists so that ctx has hints
    """

    # core ModuleContext fields
    args: "SMBArgs"
    target: tuple[str, int]
    ptjsonlib: PtJsonLib
    json: bool
    verbose: bool

    def out(
        self,
        string: str = "",
        category: str = "text",
        *,
        colortext: bool = False,
        indent: int = 0,
        condition: Optional[bool] = True,
    ) -> None: ...

    def debug(self, string: str = "", *, indent: int = 4) -> None: ...

    host: str
    ip: str
    port: int
    mapping: dict
    server_name: str
    os_version: str
    dns_domain_name: str
    dns_host_name: str
    ntlmv2_support: bool | None
    login_required: bool | None
    signing_required: bool | None
    successful_dialects: list
    v30_encryption: str
    v311_encryption: str
    error: bool | None


def get_if_available(getter):
    try:
        return getter()
    except Exception:
        return None

def valid_target_smb(target: str) -> Target:
    return valid_target(target, domain_allowed=True)


def valid_target(target: str, port_required: bool = False, domain_allowed: bool = False) -> Target:
    """
    Decides whether the target argument is a valid IP address or hostname
    with optional valid port definition. Designed for automatic usage by argparse.

    Args:
        target (str): target argument
        port_required (bool, optional): whether to require port definition. Defaults to False.
        domain_allowed (bool, optional): whether to allow hostnames. Defaults to False.

    Raises:
        argparse.ArgumentError: invalid format
        argparse.ArgumentError: missing port number
        argparse.ArgumentError: invalid ip address
        argparse.ArgumentError: unresolvable hostname
        argparse.ArgumentError: invalid port number

    Returns:
        Target: parsed Target
    """
    split = target.split(":")
    if not port_required and len(split) > 2:
        raise argparse.ArgumentError(None, "The target has to be IP[:PORT]")

    if port_required and len(split) != 2:
        raise argparse.ArgumentError(None, "The target has to be IP:PORT")

    try:
        ipaddress.ip_address(split[0])
    except:
        if domain_allowed:
            try:
                socket.gethostbyname(split[0])
            except Exception:
                raise argparse.ArgumentError(
                    None, f"Cannot resolve target name '{split[0]}' into IP address"
                )
        else:
            raise argparse.ArgumentError(None, "Invalid target IP address")

    if len(split) > 1:
        try:
            port = int(split[1])
            if port <= 0 or port >= 65536:
                raise ValueError
        except:
            raise argparse.ArgumentError(None, "Invalid PORT number")
    else:
        port = 0

    return Target(split[0], port)