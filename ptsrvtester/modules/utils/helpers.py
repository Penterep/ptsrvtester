import os, ipaddress, socket, argparse
from dataclasses import dataclass
from typing import Callable

from ptlibs.threads import ptthreads

from .._base import BaseArgs


def vendor_from_cpe(cpe: str | None) -> str | None:
    """Extract vendor from CPE 2.3 string (e.g. cpe:2.3:a:microsoft:exchange_server:* -> microsoft)."""
    if not cpe or ":" not in cpe:
        return None
    parts = cpe.split(":")
    if len(parts) >= 4 and parts[2] in ("a", "o", "h"):
        return parts[3] or None
    return None


@dataclass(frozen=True)
class Creds:
    user: str
    passw: str


@dataclass
class Target:
    ip: str
    port: int


class ArgsWithBruteforce(BaseArgs):
    user: str | None
    users: str | None  # renamed from users_file
    password: str | None  # renamed from passw
    passwords: str | None  # renamed from passw_file
    spray: bool
    threads: int


def add_bruteforce_args(parser: argparse.ArgumentParser):
    """
    Adds bruteforce arguments to ArgumentParser
    - username or file with usernames
    - password or file with passwords
    - spray option
    - number of threads

    Args:
        parser (argparse.ArgumentParser)
    """
    bruteforce = parser.add_argument_group(
        "LOGIN / BRUTEFORCE",
        "user/users + password/passwords",
    )

    # username / users file
    bruteuser = bruteforce.add_mutually_exclusive_group()
    bruteuser.title = "bruteuser"
    bruteuser.add_argument("-u", "--user", type=str, help="username")
    bruteuser.add_argument("-U", "--users", type=str, help="file containing usernames")

    # password / passwords file
    brutepass = bruteforce.add_mutually_exclusive_group()
    brutepass.title = "brutepass"
    brutepass.add_argument("-p", "--password", type=str, help="password")
    brutepass.add_argument("-P", "--passwords", type=str, help="file containing passwords")

    # other configuration
    bruteforce.add_argument(
        "--spray",
        action="store_true",
        help="try 1 password/key for all users (instead of trying all passwords/keys for 1 user)",
    )
    bruteforce.add_argument(
        "--brute-threads",
        type=int,
        default=10,
        nargs="?",
        dest="threads",
        help="number of threads for bruteforce (default: 10)",
    )


def check_if_brute(args: ArgsWithBruteforce) -> bool:
    """
    Decides whether to perfrom bruteforce operations
    based on the module arguments

    Args:
        args (ArgsWithBruteforce): module arguments

    Returns:
        bool: whether to perform bruteforce
    """
    if (args.user or args.users) and (args.password or args.passwords):
        return True
    else:
        return False


def simple_bruteforce(
    try_login: Callable[[Creds], Creds | None],
    user: str | None,
    userf: str | None,
    passw: str | None,
    passwf: str | None,
    spray: bool,
    threads: int,
) -> set[Creds]:
    """
    Performs a login bruteforce attack using an arbitrary login functino.
    Also decides chooses the appropriate values from the provided arguments.

    Args:
        try_login (Callable[[Creds], Creds  |  None]): login function
        user (str | None): username argument
        userf (str | None): users file argument
        passw (str | None): password argument
        passwf (str | None): passwords file argument
        spray (bool): spray argument
        threads (int): threads argument

    Returns:
        set[Creds]: a set of valid login credentials
    """
    users = text_or_file(user, userf)
    passwords = text_or_file(passw, passwf)

    if spray:
        creds = [Creds(u, p) for p in passwords for u in users]
    else:
        creds = [Creds(u, p) for u in users for p in passwords]

    # TODO maybe custom without ptthreads because of missing stop-on-success functionality
    pt_threads = ptthreads.PtThreads(True)
    result = pt_threads.threads(creds, try_login, threads)
    found_creds: set[Creds] = set(result)

    found_creds.discard(None)

    return found_creds


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


def get_mode(args: argparse.Namespace) -> str:
    """Decides what TLS mode is implied by the module arguments

    Args:
        args (argparse.Namespace): module arguments

    Returns:
        str: TLS / STARTTLS / PLAIN
    """
    if args.tls:
        return "TLS"
    elif args.starttls:
        return "STARTTLS"
    else:
        return "PLAIN"


def text_or_file(text: str | None, filepath: str | None) -> list[str]:
    """Returns either `text` or `filepath` contents while prefering `text`

    Args:
        text (str | None): value
        filepath (str | None): file with values

    Returns:
        list[str]: list of picked value(s)
    """
    result = []
    if text is not None:
        result = [text]
    elif filepath is not None:
        _encodings = ("utf-8", "cp1250", "iso-8859-2", "cp1252", "latin-1")
        try:
            with open(filepath, "rb") as f:
                raw = f.read()
        except FileNotFoundError:
            raise argparse.ArgumentError(None, f"File not found: '{filepath}'")
        except PermissionError:
            raise argparse.ArgumentError(None, f"Cannot read file (permission denied): '{filepath}'")
        except OSError as e:
            raise argparse.ArgumentError(None, f"Cannot read file '{filepath}': {e}")
        for enc in _encodings:
            try:
                result = raw.decode(enc).splitlines()
                break
            except UnicodeDecodeError:
                continue
        else:
            result = raw.decode("utf-8", errors="replace").splitlines()

    return result


def filepaths(directory: str, ext: str) -> list[str]:
    """
    Finds files of given extension in a given directory
    and returns their paths

    Args:
        directory (str): search directory
        ext (str): search file extension

    Returns:
        list[str]: list of file paths
    """
    files: list[str] = []
    for f in os.listdir(directory):
        fullpath = os.path.join(directory, f)
        if os.path.isfile(fullpath) and f.endswith(ext):
            files.append(fullpath)

    return files


def text(data: bytes) -> str | None:
    """
    Attempts to decode bytes as a string

    Args:
        data (bytes): bytes to decode

    Returns:
        str | None: decoded string or None
    """
    try:
        return data.decode()
    except:
        return None
