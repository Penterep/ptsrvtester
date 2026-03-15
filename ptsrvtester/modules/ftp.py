import argparse, ftplib, ipaddress, random, re, socket, ssl, threading
from dataclasses import dataclass
from enum import Enum
from io import BytesIO
from ssl import SSLSocket
from string import ascii_uppercase
from typing import NamedTuple

from ptlibs.ptjsonlib import PtJsonLib

from ._base import BaseModule, BaseArgs, Out
from ptlibs.ptprinthelper import get_colored_text
from ptlibs.threads import ptthreads

from .utils.helpers import (
    Target,
    Creds,
    ArgsWithBruteforce,
    check_if_brute,
    get_mode,
    valid_target,
    vendor_from_cpe,
    add_bruteforce_args,
    simple_bruteforce,
    text_or_file,
)
from .utils.service_identification import identify_service


# region helper methods


class TestFailedError(Exception):
    """Custom exception for run-all mode: test failed but continue with next test."""
    pass


def valid_target_ftp(target: str) -> Target:
    """Argparse helper: IP or hostname with optional port (like SMTP)."""
    return valid_target(target, domain_allowed=True)


def valid_target_bounce(target: str) -> Target:
    """Argparse helper: IP:PORT or HOST:PORT for bounce target."""
    return valid_target(target, port_required=True, domain_allowed=True)


def nop_callback(_: str):
    """RETR callback helper"""
    pass


# endregion


# region helper classes


class AccessCheckHelper:
    def __init__(self):
        self.lines_read: list[str] | None = None

    def read_callback(self, line: str) -> None:
        """LIST callback helper"""
        if self.lines_read is None:
            self.lines_read = []

        self.lines_read.append(line)


# inspired by https://stackoverflow.com/questions/12164470/python-ftp-implicit-tls-connection-issue
class FTP_TLS_implicit(ftplib.FTP_TLS):
    """Helper class for implicit TLS"""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._sock = None

    @property
    def sock(self):
        return self._sock

    @sock.setter
    def sock(self, value):
        if not isinstance(value, SSLSocket):
            self._sock = self.context.wrap_socket(value)
        else:
            self._sock = value


# endregion


# region data classes
class BounceRequestResult(NamedTuple):
    ftpserver_filepath: str
    stored: bool
    uploaded: bool
    cleaned: bool


class BounceResult(NamedTuple):
    target: Target
    used_creds: Creds | None
    bounce_accepted: bool | None
    port_accessible: bool | None
    request: BounceRequestResult | None


@dataclass
class AccessPermissions:
    creds: Creds
    dirlist: list[str] | None = None
    write: str | None = None
    read: str | None = None
    delete: str | None = None


class AccessCheckResult(NamedTuple):
    errors: list[str] | None
    results: list[AccessPermissions] | None


class InfoResult(NamedTuple):
    banner: str | None
    help_response: str | None  # HELP command output (list of supported commands)
    syst: str | None
    stat: str | None


class EncryptionResult(NamedTuple):
    """Result of encryption test: plaintext, AUTH TLS (explicit), implicit TLS."""
    plaintext_ok: bool
    auth_tls_ok: bool
    tls_ok: bool


class ModesResult(NamedTuple):
    """Result of passive/active mode availability test."""
    passive_ok: bool
    active_ok: bool
    pasv_ip_leak: str | None = None  # leaked internal IP from 227 if differs from target


@dataclass
class PathEnumResult:
    """Result of path enumeration (dictionary attack): found path with type and optional size."""
    path: str
    exists: bool
    is_directory: bool | None  # True=CWD ok, False=SIZE ok (file), None=unknown
    size: int | None  # for files when SIZE succeeds


@dataclass
class FTPResults:
    info: InfoResult | None = None
    info_error: str | None = None  # When run-all info/connect fails
    banner_requested: bool = False
    commands_requested: bool = False
    access: AccessCheckResult | None = None
    access_error: str | None = None  # When run-all access check fails
    anonymous: bool | None = None
    anonymous_error: str | None = None  # When run-all anonymous test fails
    creds: set[Creds] | None = None
    bounce: BounceResult | None = None
    encryption: EncryptionResult | None = None
    encryption_error: str | None = None
    path_enum: list[PathEnumResult] | None = None
    path_enum_error: str | None = None
    modes: ModesResult | None = None
    modes_error: str | None = None


class VULNS(Enum):
    Anonymous = "PTV-GENERAL-ANONYMOUS"
    Bounce = "PTV-FTP-BOUNCE"
    WeakCreds = "PTV-GENERAL-WEAKCREDENTIALS"


# endregion

# region arguments


class FTPArgs(ArgsWithBruteforce):
    target: Target
    active: bool
    tls: bool
    starttls: bool
    anonymous: bool
    info: bool
    access: bool
    access_list: bool
    bounce: Target | None
    bounce_file: str | None
    isencrypt: bool

    @staticmethod
    def get_help():
        return [
            {"description": ["FTP Testing Module"]},
            {"usage": ["ptsrvtester ftp <options> <target>"]},
            {"usage_example": [
                "ptsrvtester ftp --starttls -iAal 127.0.0.1",
                "ptsrvtester ftp -ie 127.0.0.1",
                "ptsrvtester ftp -Am 127.0.0.1",
                "ptsrvtester ftp -u admin -P passwords.txt 127.0.0.1:21"
            ]},
            {"options": [
                ["-i", "--info", "", "Grab banner and inspect HELP, SYST, STAT commands"],
                ["-b", "--banner", "", "Grab banner + Service Identification (product, version, CPE)"],
                ["-c", "--commands", "", "Grab HELP, SYST and STAT commands only"],
                ["-ie", "--isencrypt", "", "Test encryption options (plaintext, AUTH TLS, implicit TLS)"],
                ["-A", "--anonymous", "", "Check anonymous authentication"],
                ["-a", "--access", "", "Check read/write access"],
                ["-l", "--access-list", "", "Display directory listing"],
                ["-B", "--bounce", "", "FTP bounce attack"],
                ["", "--bounce-file", "<file>", "File with request to send (requires --access)"],
                ["-m", "--modes", "", "Test passive/active data modes + PASV IP leakage"],
                ["", "--active", "", "Use active mode"],
                ["", "--tls", "", "Use implicit SSL/TLS"],
                ["", "--starttls", "", "Use explicit SSL/TLS"],
                ["", "", "", ""],
                ["-u", "--user", "<username>", "Single username for bruteforce"],
                ["-U", "--users", "<wordlist>", "File with usernames"],
                ["-p", "--password", "<password>", "Single password for bruteforce"],
                ["-P", "--passwords", "<wordlist>", "File with passwords"],
                ["", "", "", ""],
                ["-e", "--enum-paths", "", "Dictionary attack for path discovery (requires creds)"],
                ["-w", "--paths-wordlist", "<file>", "Paths to test, one per line (required with -e)"],
                ["", "--enum-threads", "<n>", "Threads for path enumeration (default: 5)"],
                ["", "--base-path", "<path>", "Start directory for enumeration"],
                ["", "", "", ""],
                ["-h", "--help", "", "Show this help message and exit"],
            ]}
        ]

    def add_subparser(self, name: str, subparsers) -> None:
        """Adds a subparser of FTP arguments"""

        examples = """example usage:
  ptsrvtester ftp -h
  ptsrvtester ftp --starttls -iAal 127.0.0.1
  ptsrvtester ftp -ie 127.0.0.1
  ptsrvtester ftp -Am 127.0.0.1
  ptsrvtester ftp -Aae -w paths.txt 127.0.0.1
  ptsrvtester -j ftp -u admin -P passwords.txt --brute-threads 20 127.0.0.1:21"""

        parser = subparsers.add_parser(
            name,
            epilog=examples,
            add_help=True,
            formatter_class=argparse.RawTextHelpFormatter,
        )

        if not isinstance(parser, argparse.ArgumentParser):
            raise TypeError  # IDE typing

        parser.add_argument(
            "target",
            type=valid_target_ftp,
            help="IP[:PORT] or HOST[:PORT] (e.g. 127.0.0.1 or ftp.example.com:21)",
        )

        parser.add_argument(
            "--active", action="store_true", help="use active mode (passive by default)"
        )
        tls = parser.add_mutually_exclusive_group()
        tls.add_argument("--tls", action="store_true", help="use implicit SSL/TLS")
        tls.add_argument("--starttls", action="store_true", help="use explicit SSL/TLS")

        recon = parser.add_argument_group("RECON")
        recon.add_argument(
            "-i",
            "--info",
            action="store_true",
            help="grab banner and inspect HELP, SYST and STAT commands",
        )
        recon.add_argument("-b", "--banner", action="store_true", help="grab banner + Service Identification (product, version, CPE)")
        recon.add_argument("-c", "--commands", action="store_true", help="grab HELP, SYST and STAT commands only")
        recon.add_argument(
            "-ie", "--isencrypt", action="store_true", dest="isencrypt",
            help="test encryption options (plaintext, AUTH TLS, implicit TLS)"
        )
        recon.add_argument(
            "-A", "--anonymous", action="store_true", help="check anonymous authentication"
        )
        access_check = recon.add_mutually_exclusive_group()
        access_check.add_argument(
            "-a",
            "--access",
            action="store_true",
            help="check read and write access for all valid credentials",
        )
        recon.add_argument(
            "-l",
            "--access-list",
            action="store_true",
            help="display root directory listing",
        )

        bounce = parser.add_argument_group("BOUNCE", "FTP bounce attack (requires valid login)")
        bounce.add_argument(
            "-B",
            "--bounce",
            type=valid_target_bounce,
            help="bounce to the specified IP:PORT or HOST:PORT service",
        )
        bounce.add_argument(
            "--bounce-file",
            type=str,
            help="file containing a request to be sent to the attacked service"
            + " (requires --access or --access-all with write permissions)",
        )

        path_enum = parser.add_argument_group(
            "PATH ENUMERATION",
            "Dictionary attack for discovering files and directories (requires valid credentials)",
        )
        path_enum.add_argument(
            "-e",
            "--enum-paths",
            action="store_true",
            dest="enum_paths",
            help="run path enumeration from wordlist (requires --access or anonymous/bruteforce)",
        )
        path_enum.add_argument(
            "-w",
            "--paths-wordlist",
            type=str,
            dest="paths_wordlist",
            help="file with paths to test, one per line (required with -e)",
        )
        path_enum.add_argument(
            "--enum-threads",
            type=int,
            default=5,
            dest="enum_threads",
            help="threads for path enumeration (default: 5)",
        )
        path_enum.add_argument(
            "--base-path",
            type=str,
            default="",
            dest="base_path",
            help="starting directory for enumeration (default: login home)",
        )

        modes_grp = parser.add_argument_group(
            "DATA MODE",
            "Test passive and active mode availability (requires login)",
        )
        modes_grp.add_argument(
            "-m",
            "--modes",
            action="store_true",
            dest="modes",
            help="test passive/active data modes and PASV IP leakage",
        )

        add_bruteforce_args(parser)


# endregion


# region main module code


class FTP(BaseModule):
    @staticmethod
    def module_args():
        return FTPArgs()

    def __init__(self, args: BaseArgs, ptjsonlib: PtJsonLib):

        if not isinstance(args, FTPArgs):
            raise argparse.ArgumentError(
                None, f'module "{args.module}" received wrong arguments namespace'
            )

        if not args.access:
            if args.bounce_file:
                raise argparse.ArgumentError(None, "--bounce-file requires also --access")
            if args.access_list:
                raise argparse.ArgumentError(None, "--access-list requires also --access")

        enum_paths = getattr(args, "enum_paths", False)
        if enum_paths:
            if not getattr(args, "paths_wordlist", None):
                raise argparse.ArgumentError(None, "--enum-paths requires --paths-wordlist (-w)")
            if not args.access and not args.anonymous and not check_if_brute(args):
                raise argparse.ArgumentError(
                    None,
                    "--enum-paths requires credentials (use --access with --anonymous or bruteforce -u/-P)",
                )

        if getattr(args, "modes", False):
            if not args.access and not args.anonymous and not check_if_brute(args):
                raise argparse.ArgumentError(
                    None,
                    "--modes requires credentials (use --anonymous or bruteforce -u/-P)",
                )

        # Default port number
        if args.target.port == 0:
            if args.tls:
                args.target.port = 990
            else:
                args.target.port = 21

        self.do_brute = check_if_brute(args)
        self.use_json = getattr(args, "json", False)

        self.args = args
        self.ptjsonlib = ptjsonlib
        self.results: FTPResults
        self.ftp: ftplib.FTP
        self._output_lock = threading.Lock()
        self._streamed_banner = False
        self._streamed_encryption = False
        self._streamed_anonymous = False
        self._streamed_brute = False

    def _is_run_all_mode(self) -> bool:
        """True when only target is given (no test switches). Run all tests in sequence."""
        return not (
            self.args.info
            or self.args.banner
            or self.args.commands
            or getattr(self.args, "isencrypt", False)
            or self.args.anonymous
            or self.args.access
            or self.args.access_list
            or self.args.bounce
            or self.do_brute
            or getattr(self.args, "enum_paths", False)
            or getattr(self.args, "modes", False)
        )

    def _fail(self, msg: str) -> None:
        """In run-all mode: raise TestFailedError. Otherwise: end_error + SystemExit."""
        if hasattr(self, 'run_all_mode') and self.run_all_mode:
            raise TestFailedError(msg)
        else:
            self.ptjsonlib.end_error(msg, self.use_json)
            raise SystemExit

    def run(self) -> None:
        """Executes FTP methods based on module configuration. Results streamed immediately."""
        self.results = FTPResults()
        self.run_all_mode = self._is_run_all_mode()
        isencrypt = getattr(self.args, "isencrypt", False)

        # -ie only mode: encryption test and return
        if (
            isencrypt
            and not self.args.info
            and not self.args.banner
            and not self.args.commands
            and not self.args.anonymous
            and not self.args.access
            and not self.args.access_list
            and not self.args.bounce
            and not self.do_brute
        ):
            try:
                self.results.encryption = self.test_encryption()
            except Exception as e:
                self.results.encryption_error = str(e)
            self._stream_encryption_result()
            return

        if self.run_all_mode:
            self._run_all_tests()
            return

        # Normal mode: connect first, then run tests and stream immediately
        try:
            self.ftp = self.connect()
        except (TestFailedError, SystemExit):
            raise
        except Exception as e:
            self.results.info_error = str(e)
            return

        # Anonymous (info/STAT may need login; run before info when both requested)
        if self.args.anonymous:
            self.results.anonymous = self.anonymous()
            self._stream_anonymous_result()

        # Bruteforce (info/STAT may need creds for STAT when anonymous disabled)
        if self.do_brute:
            if not self.use_json:
                self.ptprint("Login bruteforce", Out.INFO)
            self.results.creds = simple_bruteforce(
                self._try_login,
                self.args.user,
                self.args.users,
                self.args.password,
                self.args.passwords,
                self.args.spray,
                self.args.threads,
                on_success=self._on_brute_success if not self.use_json else None,
            )
            self._stream_brute_result()

        # Info (banner + commands) - needs anonymous/creds for STAT
        if self.args.info or self.args.banner or self.args.commands:
            do_banner = self.args.banner or self.args.info
            do_commands = self.args.commands or self.args.info
            self.results.banner_requested = do_banner
            self.results.commands_requested = do_commands
            try:
                info = self.info(get_commands=do_commands)
                self.results.info = InfoResult(
                    info.banner if do_banner else None,
                    info.help_response if do_commands else None,
                    info.syst if do_commands else None,
                    info.stat if do_commands else None,
                )
                self._stream_banner_result()
            except Exception as e:
                self.results.info_error = str(e)

        # Encryption test (-ie)
        if isencrypt:
            try:
                self.results.encryption = self.test_encryption()
            except Exception as e:
                self.results.encryption_error = str(e)
            self._stream_encryption_result()

        # Access check
        if self.args.access:
            self.results.access = self.access_check()
            if self.args.bounce:
                self.results.bounce = self.bounce()

        # Path enumeration (dictionary attack)
        if getattr(self.args, "enum_paths", False):
            creds = self._get_path_enum_creds()
            if creds is not None:
                try:
                    paths_raw = text_or_file(None, self.args.paths_wordlist)
                    paths = [p.strip() for p in paths_raw if p.strip() and not p.strip().startswith("#")]
                    if not self.use_json:
                        self.ptprint("Path enumeration", Out.INFO)
                    self.results.path_enum = self.path_enumeration(creds, paths)
                except Exception as e:
                    self.results.path_enum_error = str(e)
            else:
                self.results.path_enum_error = "No valid credentials for path enumeration"

        # Data mode (passive/active) test
        if getattr(self.args, "modes", False):
            creds = self._get_path_enum_creds()
            if creds is not None:
                try:
                    self.results.modes = self.test_modes(creds)
                except Exception as e:
                    self.results.modes_error = str(e)
            else:
                self.results.modes_error = "No credentials for mode test (use --anonymous or bruteforce -u/-P)"

    def _get_path_enum_creds(self) -> Creds | None:
        """Get credentials for path enumeration (anonymous or first brute cred)."""
        if self.results.anonymous:
            return Creds("anonymous", "")
        if self.results.creds and len(self.results.creds) > 0:
            return next(iter(self.results.creds))
        return None

    def _run_all_tests(self) -> None:
        """Run all tests in sequence. On failure: print error, continue with next. Stream immediately."""
        # 1. Banner + commands (SYST, STAT)
        self.results.banner_requested = True
        self.results.commands_requested = True
        try:
            self.ftp = self.connect()
            self.results.info = self.info(get_commands=True)
            self._stream_banner_result()
        except TestFailedError as e:
            self.results.info_error = str(e)
            return
        except Exception as e:
            self.results.info_error = str(e)
            return

        # 2. Anonymous authentication
        try:
            self.results.anonymous = self.anonymous()
            self._stream_anonymous_result()
        except TestFailedError as e:
            self.results.anonymous_error = str(e)
        except Exception as e:
            self.results.anonymous_error = str(e)

        # 3. Access check (only if anonymous is enabled)
        if self.results.anonymous:
            try:
                self.results.access = self.access_check()
            except TestFailedError as e:
                self.results.access_error = str(e)
            except Exception as e:
                self.results.access_error = str(e)

        # 4. Data mode test (passive/active + PASV IP leakage; requires creds)
        creds = self._get_path_enum_creds()
        if creds is not None:
            try:
                self.results.modes = self.test_modes(creds)
            except TestFailedError:
                raise
            except Exception as e:
                self.results.modes_error = str(e)
        else:
            self.results.modes_error = "No credentials for mode test (use --anonymous or bruteforce -u/-P)"

    def connect(self) -> ftplib.FTP | ftplib.FTP_TLS | FTP_TLS_implicit:
        """
        Establishes a new FTP connection with the appropriate
        encryption mode according to module arguments

        Returns:
            ftplib.FTP | ftplib.FTP_TLS | FTP_TLS_implicit: new connection
        """
        timeout = 10
        try:
            if self.args.tls:
                ftp = FTP_TLS_implicit()
                ftp.connect(self.args.target.ip, self.args.target.port, timeout=timeout)
            elif self.args.starttls:
                ftp = ftplib.FTP_TLS()
                ftp.connect(self.args.target.ip, self.args.target.port, timeout=timeout)
                ftp.auth()
            else:
                ftp = ftplib.FTP()
                ftp.connect(self.args.target.ip, self.args.target.port, timeout=timeout)
        except Exception as e:
            msg = (
                f"Could not connect to the target server "
                + f"{self.args.target.ip}:{self.args.target.port} ({get_mode(self.args)}): {e}"
            )
            raise OSError(msg) from e

        # Passive/Active mode
        ftp.set_pasv(not self.args.active)
        return ftp

    def info(self, get_commands: bool = True) -> InfoResult:
        """Performs bannergrabbing; optionally HELP, SYST and STAT commands.

        Returns:
            InfoResult: (banner, help_response, syst, stat)
        """
        banner = self.ftp.welcome
        if banner is None:
            banner = ""

        help_response = None
        syst = None
        stat = None
        if get_commands:
            try:
                help_response = self.ftp.sendcmd("HELP")
                if help_response and help_response.strip():
                    help_response = help_response.strip()
                else:
                    help_response = None
            except Exception:
                pass
            try:
                syst = self.ftp.sendcmd("SYST")
                if re.match(r"[0-9]+ UNIX Type: L8", syst):
                    syst = None
            except Exception:
                pass
            try:
                if not self.results.anonymous and self.results.creds is not None:
                    for creds in self.results.creds:
                        self.ftp.login(creds.user, creds.passw)
                        break
                stat = self.ftp.sendcmd("STAT")
            except Exception:
                pass

        return InfoResult(banner, help_response, syst, stat)

    def anonymous(self) -> bool:
        """Attempts anonymous authentication

        Returns:
            bool: result
        """
        try:
            self.ftp.login()
            return True
        except ftplib.Error:
            return False

    def access_check(self) -> AccessCheckResult:
        """
        Attempts to login with all available valid credentials
        (including anonymous) and perform:
        - directory listing
        - file write
        - file read
        - file delete (just cleanup)

        Returns:
            AccessCheckResult: results
        """
        access_permissions: list[AccessPermissions] = []

        # Construct a list of all valid credentials
        all_creds: list[Creds] = []

        if self.results.anonymous:
            all_creds.append(Creds("anonymous", ""))

        if self.results.creds is not None:
            all_creds.extend(self.results.creds)

        if len(all_creds) == 0:
            return AccessCheckResult(["No valid credentials"], None)

        # Check all credentials
        errors: list[str] = []
        for creds in all_creds:
            ftp = self.connect()
            try:
                ftp.login(creds.user, creds.passw)
            except Exception as e:
                # Valid creds but server-side error
                errors.append(str(e))
                access_permissions.append(AccessPermissions(creds, None, None, None, None))
                continue

            write, read, delete = None, None, None
            ach = AccessCheckHelper()

            # Directory listing
            try:
                ftp.dir(ach.read_callback)
            except Exception as e:
                # Unexpected error, maybe timeout or similar
                errors.append(str(e))
                access_permissions.append(AccessPermissions(creds, None, None, None, None))
                continue

            # Root and top-level directories
            directories: list[str] = [""]
            if ach.lines_read is not None:
                for l in ach.lines_read:
                    # LIST response format is not standardised
                    # expecting and trying to parse the following format:
                    # drwxr-xr-x  2 root   root    4096 May  3 13:57 spaces in name

                    # Not a directory
                    if l[0] != "d":
                        continue

                    # Directory
                    try:
                        after_colon = l.split(":")[1:][0]
                        after_space = after_colon.split(" ")[1:]
                        dir_name = " ".join(after_space)
                        directories.append(dir_name)
                    except:
                        errors.append(f"Unknown response format: {l}")
                        access_permissions.append(
                            AccessPermissions(creds, ach.lines_read, None, None, None)
                        )

            text = BytesIO(b"FILE WRITE TEST")
            filename = "".join(random.choices(ascii_uppercase, k=15)) + ".txt"

            # Check permissions in parsed directories
            for dir in directories:
                # Record only the first successful hit
                if write is not None:
                    break

                text.seek(0)
                filepath = dir + "/" + filename

                # Write
                try:
                    ftp.storlines("STOR " + filepath, text)
                    write = filepath
                except ftplib.Error:
                    pass

                # Read
                if write:
                    try:
                        ftp.retrlines("RETR " + filepath, nop_callback)
                        read = filepath
                    except ftplib.Error:
                        pass

                # Delete
                if write:
                    try:
                        ftp.delete(filepath)
                        delete = filepath
                    except ftplib.Error:
                        pass

            access_permissions.append(
                AccessPermissions(
                    creds,
                    ach.lines_read,
                    write,
                    read,
                    delete,
                )
            )

        if len(errors) == 0:
            return AccessCheckResult(None, access_permissions)
        else:
            return AccessCheckResult(errors, access_permissions)

    def _on_brute_success(self, cred: Creds) -> None:
        """Callback for real-time streaming of found credentials (thread-safe).
        Streams login success immediately; permissions come from access_check() in output()."""
        with self._output_lock:
            self.ptprint(f"    user: {cred.user}, password: {cred.passw}", Out.TEXT)

    def _path_enum_worker(self, chunk: list[str], creds: Creds) -> list[PathEnumResult]:
        """Worker for path enumeration. Processes a chunk of paths with one FTP connection.
        Respects FTP sticky state: after each test returns to base_path to avoid false results."""
        results: list[PathEnumResult] = []
        ftp = self.connect()
        try:
            ftp.login(creds.user, creds.passw)
            base_path = getattr(self.args, "base_path", "") or ""
            # Resolve effective base: use pwd() if base_path empty (login home)
            if base_path:
                try:
                    ftp.cwd(base_path)
                except ftplib.Error:
                    pass  # server may not support, continue with current dir
                effective_base = base_path
            else:
                try:
                    effective_base = ftp.pwd()
                except (ftplib.Error, AttributeError):
                    effective_base = "/"

            def _reset_to_base() -> None:
                """Return to base to avoid sticky state affecting next path test."""
                try:
                    ftp.cwd(effective_base)
                except ftplib.Error:
                    pass

            for path in chunk:
                path = path.strip().lstrip("/")  # normalize: relative to effective_base
                if not path or path.startswith("#"):
                    continue
                _reset_to_base()
                # Try CWD first (directory) – 250 = exists
                try:
                    ftp.cwd(path)
                    results.append(
                        PathEnumResult(path=path, exists=True, is_directory=True, size=None)
                    )
                    continue  # _reset_to_base done at loop start
                except ftplib.error_perm as e:
                    err_str = str(e)
                    if "550" not in err_str and "550" not in str(e.args):
                        continue  # other permission error, skip
                except ftplib.Error:
                    continue
                # CWD failed (550) – try SIZE (file). Note: SIZE is RFC 3659; some older
                # servers may not support it and return error even when file exists.
                try:
                    size = ftp.size(path)
                    results.append(
                        PathEnumResult(path=path, exists=True, is_directory=False, size=size)
                    )
                except ftplib.Error:
                    pass  # path does not exist
        finally:
            try:
                ftp.close()
            except Exception:
                pass
        return results

    def path_enumeration(self, creds: Creds, paths: list[str]) -> list[PathEnumResult]:
        """Dictionary attack for path discovery. Each thread uses one connection and processes
        a chunk of paths, resetting to base_path after each test (FTP sticky state)."""
        if not paths:
            return []
        enum_threads = max(1, getattr(self.args, "enum_threads", 5))
        # Split paths into chunks (one per thread)
        k, m = divmod(len(paths), enum_threads)
        chunks = [
            paths[i * k + min(i, m) : (i + 1) * k + min(i + 1, m)]
            for i in range(enum_threads)
        ]
        chunks = [c for c in chunks if c]

        def worker(chunk: list[str]) -> list[PathEnumResult]:
            return self._path_enum_worker(chunk, creds)

        pt = ptthreads.PtThreads(print_errors=False)
        raw_returns = pt.threads(chunks, worker, min(len(chunks), enum_threads)) or []
        # Flatten and deduplicate by path
        seen: set[str] = set()
        flat: list[PathEnumResult] = []
        for r in raw_returns:
            if isinstance(r, list):
                for p in r:
                    if p.path not in seen:
                        seen.add(p.path)
                        flat.append(p)
        return flat

    def _parse_pasv_ip(self, reply: str) -> str | None:
        """Extract IP from PASV 227 reply. RFC 1123: format varies, scan for digits."""
        m = re.search(r"(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)", reply)
        if m:
            return f"{m.group(1)}.{m.group(2)}.{m.group(3)}.{m.group(4)}"
        return None

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private ranges (10.x, 172.16-31.x, 192.168.x)."""
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private
        except ValueError:
            return False

    def test_modes(self, creds: Creds) -> ModesResult:
        """
        Test passive and active mode availability. Requires data transfer (LIST/NLST).
        Checks PASV response for IP leakage (internal IP advertised when connecting from outside).
        """
        passive_ok = False
        active_ok = False
        pasv_ip_leak: str | None = None
        target_ip = self.args.target.ip
        try:
            ipaddress.ip_address(target_ip)
        except ValueError:
            try:
                target_ip = socket.gethostbyname(target_ip)
            except Exception:
                target_ip = ""

        # Test passive mode + IP leakage
        ftp = self.connect()
        try:
            ftp.login(creds.user, creds.passw)
            ftp.set_pasv(True)
            # Get raw 227 reply for IP leakage check. ftplib processes PASV internally in
            # transfercmd(), but sendcmd("PASV") returns the raw response string for parsing.
            # voidcmd("PASV") would also return it for 2xx; we use sendcmd for explicitness.
            try:
                reply = ftp.sendcmd("PASV")
                pasv_ip = self._parse_pasv_ip(reply)
                # IP leak: PASV IP differs from target (e.g. internal IP exposed when connecting from outside)
                if pasv_ip and target_ip and pasv_ip != target_ip:
                    pasv_ip_leak = pasv_ip
            except ftplib.Error:
                pass
            # Actual passive data transfer test (sends new PASV, previous was for leak check)
            try:
                ach = AccessCheckHelper()
                ftp.dir(ach.read_callback)
                passive_ok = True
            except ftplib.Error:
                pass
        finally:
            try:
                ftp.close()
            except Exception:
                pass

        # Test active mode (new connection)
        ftp = self.connect()
        try:
            ftp.login(creds.user, creds.passw)
            ftp.set_pasv(False)
            try:
                ach = AccessCheckHelper()
                ftp.dir(ach.read_callback)
                active_ok = True
            except ftplib.Error:
                pass
        finally:
            try:
                ftp.close()
            except Exception:
                pass

        return ModesResult(passive_ok=passive_ok, active_ok=active_ok, pasv_ip_leak=pasv_ip_leak)

    def test_encryption(self) -> EncryptionResult:
        """
        Test encryption options: plaintext (21), AUTH TLS (explicit), implicit TLS (990).
        Uses fresh connections; does not use self.args.tls/starttls.
        AUTH TLS sends AUTH TLS command then TLS handshake (RFC 2228).
        """
        host = self.args.target.ip
        port = self.args.target.port
        timeout = 10.0
        plaintext_ok = False
        auth_tls_ok = False
        tls_ok = False
        _ssl_ctx = ssl._create_unverified_context()
        tls_only_port = port == 990

        if not tls_only_port:
            # 1. Plaintext (no TLS)
            try:
                ftp = ftplib.FTP()
                ftp.connect(host, port, timeout=timeout)
                _ = ftp.welcome
                plaintext_ok = True
                ftp.close()
            except Exception:
                pass

            # 2. AUTH TLS (explicit: plain connect, then AUTH TLS + TLS handshake)
            try:
                ftp = ftplib.FTP_TLS()
                ftp.connect(host, port, timeout=timeout)
                _ = ftp.welcome
                ftp.auth()
                auth_tls_ok = True
                ftp.close()
            except Exception:
                pass

        # 3. Implicit TLS (port 990)
        _connect_timeout = 15.0 if tls_only_port else timeout

        def _try_implicit_tls(sni):
            ftp = FTP_TLS_implicit()
            ftp.context = _ssl_ctx
            try:
                ftp.connect(host, port, timeout=_connect_timeout)
                _ = ftp.welcome
                return True
            except Exception:
                return False
            finally:
                try:
                    ftp.close()
                except Exception:
                    pass

        try:
            try:
                ipaddress.ip_address(host)
                _sni_first, _sni_fallback = None, host
            except ValueError:
                _sni_first, _sni_fallback = host, None
            for _sni in (_sni_first, _sni_fallback):
                if _sni is None and _sni_fallback is None:
                    continue
                try:
                    if _try_implicit_tls(_sni):
                        tls_ok = True
                        break
                except Exception:
                    pass
        except Exception:
            pass

        return EncryptionResult(plaintext_ok, auth_tls_ok, tls_ok)

    def _stream_banner_result(self) -> None:
        if self.use_json or not (info := self.results.info) or info.banner is None:
            return
        with self._output_lock:
            self.ptprint("Banner", Out.INFO)
            sid = identify_service(info.banner)
            if sid is None:
                icon = get_colored_text("[✓]", color="NOTVULN")
            elif sid.version is not None:
                icon = get_colored_text("[✗]", color="VULN")
            else:
                icon = get_colored_text("[!]", color="WARNING")
            self.ptprint(f"    {icon} {info.banner}", Out.TEXT)
            if sid is not None:
                self.ptprint("Service Identification", Out.INFO)
                self.ptprint(f"    Product:  {sid.product}", Out.TEXT)
                self.ptprint(
                    f"    Version:  {sid.version if sid.version else 'unknown'}",
                    Out.TEXT,
                )
                self.ptprint(f"    CPE:      {sid.cpe}", Out.TEXT)
        self._streamed_banner = True

    def _stream_encryption_result(self) -> None:
        if self.use_json:
            return
        with self._output_lock:
            self.ptprint("Encryption", Out.INFO)
            if (err := self.results.encryption_error) is not None:
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} Encryption test failed: {err}", Out.TEXT)
                self._streamed_encryption = True
                return
            enc = self.results.encryption
            if enc is None:
                return
            plaintext_only = enc.plaintext_ok and not enc.auth_tls_ok and not enc.tls_ok
            any_ok = enc.plaintext_ok or enc.auth_tls_ok or enc.tls_ok
            if plaintext_only:
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} Plaintext only", Out.TEXT)
            elif any_ok:
                if enc.plaintext_ok:
                    icon = (
                        get_colored_text("[!]", color="WARNING")
                        if (enc.auth_tls_ok or enc.tls_ok)
                        else get_colored_text("[✓]", color="NOTVULN")
                    )
                    self.ptprint(f"    {icon} Plaintext", Out.TEXT)
                if enc.auth_tls_ok:
                    icon = get_colored_text("[✓]", color="NOTVULN")
                    self.ptprint(f"    {icon} AUTH TLS", Out.TEXT)
                if enc.tls_ok:
                    icon = get_colored_text("[✓]", color="NOTVULN")
                    self.ptprint(f"    {icon} Implicit TLS", Out.TEXT)
            else:
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(
                    f"    {icon} No connection mode available (plaintext, AUTH TLS, implicit TLS failed)",
                    Out.TEXT,
                )
        self._streamed_encryption = True

    def _stream_anonymous_result(self) -> None:
        if self.use_json or (anonymous := self.results.anonymous) is None:
            return
        with self._output_lock:
            self.ptprint("Anonymous authentication", Out.INFO)
            if anonymous:
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} Enabled", Out.TEXT)
                # Basic permissions from access if available (anon + access in run-all)
                if (access := self.results.access) and access.results:
                    try:
                        anon_p = next(p for p in access.results if p.creds.user == "anonymous")
                        perm_str = (
                            f"    (Directory listing: {anon_p.dirlist is not None}, "
                            + f"Write: {anon_p.write}, Read: {anon_p.read}, Delete: {anon_p.delete})"
                        )
                        self.ptprint(perm_str, Out.TEXT)
                    except StopIteration:
                        pass
            else:
                icon = get_colored_text("[✓]", color="NOTVULN")
                self.ptprint(f"    {icon} Disabled", Out.TEXT)
        self._streamed_anonymous = True

    def _stream_brute_result(self) -> None:
        creds = self.results.creds
        if creds is None:
            return
        if not self.use_json and len(creds) > 0:
            with self._output_lock:
                self.ptprint(f"    Found {len(creds)} valid credentials", Out.INFO)
        self._streamed_brute = True

    def _try_login(self, creds: Creds) -> Creds | None:
        """Login attempt function for bruteforce

        Args:
            creds (Creds): Creds to use for login

        Returns:
            Creds | None: Creds if success, None if failed
        """
        ftp = self.connect()
        try:
            ftp.login(creds.user, creds.passw)
            result = creds
        except Exception as e:
            # Valid creds but server-side error?
            if e.args and len(e.args) > 0:
                if "cannot change directory" in str(e.args[0]).lower():
                    result = creds
                else:
                    result = None
            else:
                result = None
        finally:
            ftp.close()
            return result

    def bounce(self) -> BounceResult:
        """
        Attempts to login (anonymous or valid bruteforce creds) and
        perform an FTP bounce attack, either for port scan or
        request via file upload.

        Returns:
            BounceResult: results
        """

        creds: Creds | None = None
        write_path: str | None = None

        # Choose valid creds (any for --bounce, write-permitted for --bounce-file)
        if not self.args.bounce_file:
            # Any creds for port scan
            if self.results.anonymous:
                creds = Creds("anonymous", "")
            elif self.results.creds is not None and len(self.results.creds) > 0:
                for c in self.results.creds:
                    creds = c
                    break
        elif (access := self.results.access) is not None and access.results:
            # Write & Read creds for bounced request
            for p in access.results:
                if p.write is None or p.read is None:
                    continue
                else:
                    creds = p.creds
                    write_path = p.write

        if creds is None:
            return BounceResult(self.args.bounce, None, None, None, None)

        # Use the appropriate creds to connect to the service
        ftp = self.connect()
        ftp.login(creds.user, creds.passw)

        # Bounce setup attempt
        if not self._bounce_setup(ftp, self.args.bounce):
            return BounceResult(self.args.bounce, creds, False, None, None)

        if self.args.bounce_file and write_path is not None:
            # Full bounced request
            stored, uploaded, cleaned = False, False, False
            filename = write_path + ".txt"

            try:
                # Upload request file onto FTP server
                with open(self.args.bounce_file, "rb") as f:
                    # reusing previous filename, with doubled .txt extension
                    p = ftp.storbinary("STOR " + filename, f)
                    stored = True

                # Refresh bounce setup after STOR
                self._bounce_setup(ftp, self.args.bounce)

                # Upload request to bounce target
                # TODO timeout for unreachable ports?
                ftp.sendcmd("RETR " + filename)
                uploaded = True
            except FileNotFoundError:
                raise argparse.ArgumentError(None, f"File not found: '{self.args.bounce_file}'")
            except PermissionError:
                raise argparse.ArgumentError(
                    None, f"Cannot read file (permission denied): '{self.args.bounce_file}'"
                )
            except OSError as e:
                raise argparse.ArgumentError(None, f"Cannot read file '{self.args.bounce_file}': {e}")
            except ftplib.Error:
                pass
            finally:
                if stored:
                    # Cleanup the uploaded request file
                    try:
                        ftp.delete(filename)
                        cleaned = True
                    except ftplib.Error as e:
                        # 226 is success, but ftplib does not account for that
                        if e.args and len(e.args) > 0 and len(str(e.args[0])) >= 3:
                            if str(e.args[0])[:3] == "226":
                                cleaned = True

            return BounceResult(
                self.args.bounce,
                creds,
                True,
                None,
                BounceRequestResult(
                    filename,
                    stored,
                    uploaded,
                    cleaned,
                ),
            )
        else:
            # Just port scan
            try:
                ftp.sendcmd("LIST")

                port_ok = True
            except:
                port_ok = False

            return BounceResult(self.args.bounce, creds, True, port_ok, None)

    def _bounce_setup(self, ftp: ftplib.FTP, target: Target) -> bool:
        """Attempts to negotiate an FTP bounce configuration

        Args:
            ftp (ftplib.FTP): FTP connection
            target (Target): bounce target

        Returns:
            bool: negotiation result
        """
        try:
            ftp.sendport(target.ip, target.port)
        except:
            try:
                ftp.sendeprt(target.ip, target.port)
            except:
                return False

        return True

    # region output

    def output(self) -> None:
        """Formats and outputs module results. Skips streamed sections in text mode; JSON always complete."""
        properties = {
            "software_type": None,
            "name": "ftp",
            "version": None,
            "vendor": None,
            "description": None,
        }
        deferred_vulns = []

        # Connection error: use unified error format (status=error, empty nodes)
        if (info_error := getattr(self.results, "info_error", None)) is not None:
            if self.use_json:
                self.ptjsonlib.end_error(info_error, self.use_json)
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} {info_error}", Out.TEXT)
            properties.update({"infoError": info_error})
            ftp_node = self.ptjsonlib.create_node_object("software", None, None, properties)
            self.ptjsonlib.add_node(ftp_node)
            node_key = ftp_node["key"]
            for v in deferred_vulns:
                self.ptjsonlib.add_vulnerability(node_key=node_key, **v)
            self.ptjsonlib.set_status("finished", "")
            self.ptprint(self.ptjsonlib.get_result_json(), json=True)
            return

        # Banner (skip terminal if streamed; always add to properties for JSON)
        if (info := self.results.info) and info.banner is not None:
            sid = identify_service(info.banner)
            vendor = vendor_from_cpe(sid.cpe) if sid else None
            version = sid.version if sid else None
            properties.update(
                {
                    "description": f"Banner: {info.banner}",
                    "version": version,
                    "vendor": vendor,
                }
            )
            if sid is not None:
                if sid.version is not None:
                    deferred_vulns.append({"vuln_code": "PTV-SVC-BANNER"})
                properties.update({"cpe": sid.cpe})
            if not self.use_json and not self._streamed_banner:
                self.ptprint("Banner", Out.INFO)
                if sid is None:
                    icon = get_colored_text("[✓]", color="NOTVULN")
                elif sid.version is not None:
                    icon = get_colored_text("[✗]", color="VULN")
                else:
                    icon = get_colored_text("[!]", color="WARNING")
                self.ptprint(f"    {icon} {info.banner}", Out.TEXT)
                if sid is not None:
                    self.ptprint("Service Identification", Out.INFO)
                    self.ptprint(f"    Product:  {sid.product}", Out.TEXT)
                    self.ptprint(
                        f"    Version:  {sid.version if sid.version else 'unknown'}",
                        Out.TEXT,
                    )
                    self.ptprint(f"    CPE:      {sid.cpe}", Out.TEXT)

        # HELP, SYST and STAT commands (separate section)
        if self.results.commands_requested:
            if (info := self.results.info) and (info.help_response is not None or info.syst is not None or info.stat is not None):
                if info.help_response is not None:
                    self.ptprint("HELP command", Out.INFO)
                    for line in info.help_response.splitlines():
                        self.ptprint(f"    {line}", Out.TEXT)
                    properties.update({"helpCommand": info.help_response})
                if info.syst is not None:
                    self.ptprint("SYST command", Out.INFO)
                    self.ptprint(f"    {info.syst}")
                    properties.update({"systCommand": info.syst})
                if info.stat is not None:
                    self.ptprint("STAT command", Out.INFO)
                    self.ptprint(f"    {info.stat}")
                    properties.update({"statCommand": info.stat})

        # Encryption (skip terminal if streamed; always add to properties for JSON)
        if (encryption_error := self.results.encryption_error) is not None:
            properties.update({"encryptionError": encryption_error})
            if not self.use_json and not self._streamed_encryption:
                self.ptprint("Encryption", Out.INFO)
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} Encryption test failed: {encryption_error}", Out.TEXT)
        elif (enc := self.results.encryption) is not None:
            properties.update(
                {
                    "encryption": {
                        "plaintext": enc.plaintext_ok,
                        "authTls": enc.auth_tls_ok,
                        "tls": enc.tls_ok,
                    }
                }
            )
            if not self.use_json and not self._streamed_encryption:
                self.ptprint("Encryption", Out.INFO)
                plaintext_only = enc.plaintext_ok and not enc.auth_tls_ok and not enc.tls_ok
                any_ok = enc.plaintext_ok or enc.auth_tls_ok or enc.tls_ok
                if plaintext_only:
                    icon = get_colored_text("[✗]", color="VULN")
                    self.ptprint(f"    {icon} Plaintext only", Out.TEXT)
                elif any_ok:
                    if enc.plaintext_ok:
                        icon = (
                            get_colored_text("[!]", color="WARNING")
                            if (enc.auth_tls_ok or enc.tls_ok)
                            else get_colored_text("[✓]", color="NOTVULN")
                        )
                        self.ptprint(f"    {icon} Plaintext", Out.TEXT)
                    if enc.auth_tls_ok:
                        icon = get_colored_text("[✓]", color="NOTVULN")
                        self.ptprint(f"    {icon} AUTH TLS", Out.TEXT)
                    if enc.tls_ok:
                        icon = get_colored_text("[✓]", color="NOTVULN")
                        self.ptprint(f"    {icon} Implicit TLS", Out.TEXT)
                else:
                    icon = get_colored_text("[✗]", color="VULN")
                    self.ptprint(
                        f"    {icon} No connection mode available (plaintext, AUTH TLS, implicit TLS failed)",
                        Out.TEXT,
                    )

        # Anonymous authentication and access permissions (skip terminal if streamed)
        if (anonymous_error := self.results.anonymous_error) is not None:
            properties.update({"anonymousError": anonymous_error})
            if not self.use_json and not self._streamed_anonymous:
                self.ptprint("Authentication", Out.INFO)
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} Anonymous test failed: {anonymous_error}", Out.TEXT)
        elif (access_error := self.results.access_error) is not None:
            properties.update({"accessError": access_error})
            if not self.use_json and not self._streamed_anonymous:
                self.ptprint("Authentication", Out.INFO)
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} Anonymous authentication is enabled", Out.TEXT)
                self.ptprint(f"    {icon} Access check failed: {access_error}", Out.TEXT)
        elif (anon := self.results.anonymous) is not None:
            if not self.use_json and not self._streamed_anonymous:
                self.ptprint("Authentication", Out.INFO)
                if anon:
                    icon = get_colored_text("[✗]", color="VULN")
                    self.ptprint(f"    {icon} Anonymous authentication is enabled", Out.TEXT)
                else:
                    icon = get_colored_text("[✓]", color="NOTVULN")
                    self.ptprint(f"    {icon} Anonymous authentication is disabled", Out.TEXT)
            if anon:
                response_str = ""
                if (access := self.results.access) is not None:
                    if access.errors is None and access.results is not None:
                        try:
                            anon_p = next(p for p in access.results if p.creds.user == "anonymous")
                            response_str = (
                                f"(Directory listing: {anon_p.dirlist is not None}, "
                                + f"Write: {anon_p.write}, "
                                + f"Read: {anon_p.read}, "
                                + f"Delete: {anon_p.delete})"
                            )
                            if not self.use_json and not self._streamed_anonymous:
                                self.ptprint(f"    {response_str}", Out.TEXT)
                        except StopIteration:
                            pass
                    else:
                        response_str = "Encountered errors during access enumeration:"
                        if not self.use_json and not self._streamed_anonymous:
                            self.ptprint(f"    {response_str}", Out.ERROR)
                            for e in access.errors or []:
                                self.ptprint(f"        {e}", Out.ERROR)
                        if access.errors:
                            response_str += "\n" + "\n".join(access.errors)

                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.Anonymous.value,
                        "vuln_request": "anonymous login",
                        "vuln_response": response_str,
                    }
                )

        # Bruteforced credentials and their access permissions (skip terminal if streamed)
        if (creds := self.results.creds) is not None:
            if not self.use_json and not self._streamed_brute and len(creds) > 0:
                self.ptprint(f"Login bruteforce: {len(creds)} valid credentials", Out.INFO)

            if len(creds) > 0:
                json_lines: list[str] = []
                for cred in creds:
                    cred_str = f"user: {cred.user}, password: {cred.passw}"

                    if (access := self.results.access) is not None:
                        if access.errors is None and access.results is not None:
                            try:
                                cred_p = next(p for p in access.results if p.creds == cred)
                                perm_str = (
                                    f" (Directory listing: {cred_p.dirlist is not None}, "
                                    + f"Write: {cred_p.write}, "
                                    + f"Read: {cred_p.read}, "
                                    + f"Delete: {cred_p.delete})"
                                )
                            except StopIteration:
                                perm_str = ""
                        else:
                            perm_str = " Encountered errors during access enumeration:"
                            if not self.use_json and not self._streamed_brute:
                                self.ptprint(f"    {perm_str}", Out.ERROR)
                            for e in access.errors or []:
                                if not self.use_json and not self._streamed_brute:
                                    self.ptprint(f"        {e}", Out.ERROR)
                                perm_str += f"\n{e}"
                    else:
                        perm_str = ""

                    if not self.use_json and not self._streamed_brute:
                        self.ptprint(f"    {cred_str + perm_str}", Out.TEXT)
                    json_lines.append(cred_str + perm_str)

                if self.args.user is not None:
                    user_str = f"username: {self.args.user}"
                else:
                    user_str = f"usernames: {self.args.users}"

                if self.args.password is not None:
                    passw_str = f"password: {self.args.password}"
                else:
                    passw_str = f"passwords: {self.args.passwords}"

                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.WeakCreds.value,
                        "vuln_request": f"{user_str}\n{passw_str}",
                        "vuln_response": "\n".join(json_lines),
                    }
                )

        # Directory listing
        if (
            self.args.access_list
            and (access := self.results.access) is not None
            and access.results is not None
        ):
            try:
                p = next(p for p in access.results if p.dirlist is not None and len(p.dirlist) > 0)
                self.ptprint("Directory listing", Out.INFO)

                out_str = "\n".join(p.dirlist)
                self.ptprint(f"    {out_str}")
                properties.update({"directoryListing": out_str})
            except StopIteration:
                self.ptprint("Directory listing failed (no access or empty listing)", Out.INFO)
                properties.update({"directoryListing": "no access or empty"})

        # Path enumeration (dictionary attack results)
        if path_enum_error := getattr(self.results, "path_enum_error", None):
            properties.update({"pathEnumError": path_enum_error})
            if not self.use_json:
                self.ptprint("Path enumeration", Out.INFO)
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} {path_enum_error}", Out.TEXT)
        elif (path_list := getattr(self.results, "path_enum", None)) is not None:
            path_enum_json = [
                {
                    "path": p.path,
                    "exists": p.exists,
                    "isDirectory": p.is_directory,
                    "size": p.size,
                }
                for p in path_list
            ]
            properties.update({"pathEnum": path_enum_json})
            if not self.use_json and len(path_list) > 0:
                self.ptprint("Path enumeration", Out.INFO)
                self.ptprint(f"    Found {len(path_list)} path(s)", Out.TEXT)
                for p in path_list:
                    kind = "dir" if p.is_directory else "file"
                    size_str = f" ({p.size} B)" if p.size is not None else ""
                    self.ptprint(f"    [{kind}] {p.path}{size_str}", Out.TEXT)

        # Data mode (passive/active)
        if modes_error := getattr(self.results, "modes_error", None):
            properties.update({"dataModesError": modes_error})
            if not self.use_json:
                self.ptprint("Data mode", Out.INFO)
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} {modes_error}", Out.TEXT)
        elif (modes := getattr(self.results, "modes", None)) is not None:
            modes_json: dict = {"passive": modes.passive_ok, "active": modes.active_ok}
            if modes.pasv_ip_leak:
                modes_json["pasvIpLeak"] = modes.pasv_ip_leak
            properties.update({"dataModes": modes_json})
            if not self.use_json:
                self.ptprint("Data mode", Out.INFO)
                icon_p = get_colored_text("[✓]", color="NOTVULN") if modes.passive_ok else get_colored_text("[✗]", color="VULN")
                icon_a = get_colored_text("[✓]", color="NOTVULN") if modes.active_ok else get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon_p} Passive: {'available' if modes.passive_ok else 'not available'}", Out.TEXT)
                self.ptprint(f"    {icon_a} Active: {'available' if modes.active_ok else 'not available'}", Out.TEXT)
                if not modes.active_ok:
                    warn_icon = get_colored_text("[!]", color="WARNING")
                    self.ptprint(
                        f"    {warn_icon} If active failed: tester may be behind NAT/firewall, not necessarily server error. "
                        "For 100% objective result, tester needs public IP and no local firewall.",
                        Out.TEXT,
                    )
                if modes.pasv_ip_leak:
                    icon = get_colored_text("[✗]", color="VULN")
                    self.ptprint(f"    {icon} PASV Internal IP Leak: server advertised {modes.pasv_ip_leak}", Out.TEXT)

        # Bounce attack
        if bounce := self.results.bounce:
            if (creds := bounce.used_creds) is None:
                self.ptprint(f"Bounce attack failed (no valid credentials)", Out.INFO)
                properties.update({"bounceStatus": "no valid credentials"})
            else:
                self.ptprint("Bounce attack", Out.INFO)
                self.ptprint(f"    Creds used: {creds.user}:{creds.passw}", Out.INFO)

                if bounce.bounce_accepted:
                    icon = get_colored_text("[✗]", color="VULN")
                    self.ptprint(f"    {icon} Bounce is allowed", Out.TEXT)
                else:
                    icon = get_colored_text("[✓]", color="NOTVULN")
                    self.ptprint(f"    {icon} Bounce is denied", Out.TEXT)

                if not bounce.bounce_accepted:
                    properties.update({"bounceStatus": "rejected"})
                else:
                    properties.update({"bounceStatus": "ok"})

                    if (r := bounce.request) is None:
                        out_str = f"Target port reachable: {bounce.port_accessible}"
                        self.ptprint(f"        {out_str}", Out.INFO)
                        deferred_vulns.append(
                            {
                                "vuln_code": VULNS.Bounce.value,
                                "vuln_request": f"Bounce port scan target: {bounce.target.ip}:{bounce.target.port}\nCreds used: {creds.user}:{creds.passw}",
                                "vuln_response": out_str,
                            }
                        )
                    else:
                        res = f"Yes ({r.ftpserver_filepath})" if r.stored else "No"
                        stored_str = "Stored on FTP server: " + res
                        self.ptprint(f"        {stored_str}", Out.INFO)

                        res = "Yes" if r.uploaded else "No"
                        sent_str = "Sent to bounce target: " + res
                        self.ptprint(f"        {sent_str}", Out.INFO)

                        res = "Yes" if r.cleaned else "No"
                        clean_str = "Cleaned up: " + res
                        self.ptprint(f"        {clean_str}", Out.INFO)

                        deferred_vulns.append(
                            {
                                "vuln_code": VULNS.Bounce.value,
                                "vuln_request": f"Bounce request target: {bounce.target.ip}:{bounce.target.port}\nCreds used: {creds.user}:{creds.passw}\nRequest file: {self.args.bounce_file}",
                                "vuln_response": "\n".join([stored_str, sent_str, clean_str]),
                            }
                        )

        # Create node at the end with all collected properties and bind vulnerabilities
        ftp_node = self.ptjsonlib.create_node_object(
            "software",
            None,
            None,
            properties,
        )
        self.ptjsonlib.add_node(ftp_node)
        node_key = ftp_node["key"]
        for v in deferred_vulns:
            self.ptjsonlib.add_vulnerability(node_key=node_key, **v)

        self.ptjsonlib.set_status("finished", "")
        self.ptprint(self.ptjsonlib.get_result_json(), json=True)


# endregion
