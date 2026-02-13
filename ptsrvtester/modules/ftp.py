import argparse, ftplib, re, random
from dataclasses import dataclass
from enum import Enum
from io import BytesIO
from ssl import SSLSocket
from string import ascii_uppercase
from typing import NamedTuple

from ptlibs.ptjsonlib import PtJsonLib

from ._base import BaseModule, BaseArgs, Out
from ptlibs.ptprinthelper import get_colored_text
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

    @staticmethod
    def get_help():
        return [
            {"description": ["FTP Testing Module"]},
            {"usage": ["ptsrvtester ftp <options> <target>"]},
            {"usage_example": [
                "ptsrvtester ftp --starttls -iAal 127.0.0.1",
                "ptsrvtester ftp -u admin -P passwords.txt 127.0.0.1:21"
            ]},
            {"options": [
                ["-i", "--info", "", "Grab banner and inspect HELP, SYST, STAT commands"],
                ["-b", "--banner", "", "Grab banner + Service Identification (product, version, CPE)"],
                ["-c", "--commands", "", "Grab HELP, SYST and STAT commands only"],
                ["-A", "--anonymous", "", "Check anonymous authentication"],
                ["-a", "--access", "", "Check read/write access"],
                ["-l", "--access-list", "", "Display directory listing"],
                ["-B", "--bounce", "", "FTP bounce attack"],
                ["", "--bounce-file", "<file>", "File with request to send (requires --access)"],
                ["", "--active", "", "Use active mode"],
                ["", "--tls", "", "Use implicit SSL/TLS"],
                ["", "--starttls", "", "Use explicit SSL/TLS"],
                ["", "", "", ""],
                ["-u", "--user", "<username>", "Single username for bruteforce"],
                ["-U", "--users", "<wordlist>", "File with usernames"],
                ["-p", "--password", "<password>", "Single password for bruteforce"],
                ["-P", "--passwords", "<wordlist>", "File with passwords"],
                ["", "", "", ""],
                ["-h", "--help", "", "Show this help message and exit"],
            ]}
        ]

    def add_subparser(self, name: str, subparsers) -> None:
        """Adds a subparser of FTP arguments"""

        examples = """example usage:
  ptsrvtester ftp -h
  ptsrvtester ftp --starttls -iAal 127.0.0.1
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

        # Default port number
        if args.target.port == 0:
            if args.tls:
                args.target.port = 990
            else:
                args.target.port = 21

        self.do_brute = check_if_brute(args)

        self.args = args
        self.ptjsonlib = ptjsonlib
        self.results: FTPResults
        self.ftp: ftplib.FTP

    def _is_run_all_mode(self) -> bool:
        """True when only target is given (no test switches). Run all tests in sequence."""
        return not (
            self.args.info
            or self.args.banner
            or self.args.commands
            or self.args.anonymous
            or self.args.access
            or self.args.access_list
            or self.args.bounce
            or self.do_brute
        )

    def _fail(self, msg: str) -> None:
        """In run-all mode: raise TestFailedError. Otherwise: end_error + SystemExit."""
        if hasattr(self, 'run_all_mode') and self.run_all_mode:
            raise TestFailedError(msg)
        else:
            self.ptjsonlib.end_error(msg, self.args.json)
            raise SystemExit

    def run(self) -> None:
        """Executes FTP methods based on module configuration"""
        self.results = FTPResults()
        self.run_all_mode = self._is_run_all_mode()

        if self.run_all_mode:
            self._run_all_tests()
            return

        # Normal mode: run only specified tests
        try:
            self.ftp = self.connect()
        except (TestFailedError, SystemExit):
            raise
        except Exception as e:
            self.results.info_error = str(e)
            return  # Cannot continue without connection

        if self.args.anonymous:
            self.results.anonymous = self.anonymous()

        if self.do_brute:
            self.results.creds = simple_bruteforce(
                self._try_login,
                self.args.user,
                self.args.users,
                self.args.password,
                self.args.passwords,
                self.args.spray,
                self.args.threads,
            )

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
            except Exception as e:
                self.results.info_error = str(e)

        if self.args.access:
            self.results.access = self.access_check()

            # Bounce requires acccess check
            if self.args.bounce:
                self.results.bounce = self.bounce()

    def _run_all_tests(self) -> None:
        """Run all tests in sequence. On failure: print error, continue with next."""
        # 1. Banner + commands (SYST, STAT)
        self.results.banner_requested = True
        self.results.commands_requested = True
        try:
            self.ftp = self.connect()
            self.results.info = self.info(get_commands=True)
        except TestFailedError as e:
            self.results.info_error = str(e)
            return
        except Exception as e:
            self.results.info_error = str(e)
            return

        # 2. Anonymous authentication
        try:
            self.results.anonymous = self.anonymous()
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

    def connect(self) -> ftplib.FTP | ftplib.FTP_TLS | FTP_TLS_implicit:
        """
        Establishes a new FTP connection with the appropriate
        encryption mode according to module arguments

        Returns:
            ftplib.FTP | ftplib.FTP_TLS | FTP_TLS_implicit: new connection
        """
        try:
            if self.args.tls:
                ftp = FTP_TLS_implicit()
                ftp.connect(self.args.target.ip, self.args.target.port)
            elif self.args.starttls:
                ftp = ftplib.FTP_TLS()
                ftp.connect(self.args.target.ip, self.args.target.port)
                ftp.auth()
            else:
                ftp = ftplib.FTP()
                ftp.connect(self.args.target.ip, self.args.target.port)
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
        """Formats and outputs module results, both normal and JSON mode"""
        properties = {
            "software_type": None,
            "name": "ftp",
            "version": None,
            "vendor": None,
            "description": None,
        }
        deferred_vulns = []

        # Connection error: show only the error line, no section headers
        if (info_error := getattr(self.results, "info_error", None)) is not None:
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

        # Banner (separate section)
        if self.results.banner_requested:
            if (info := self.results.info) and info.banner is not None:
                self.ptprint("Banner", Out.INFO)
                sid = identify_service(info.banner)
                if sid is None:
                    icon = get_colored_text("[✓]", color="NOTVULN")
                elif sid.version is not None:
                    icon = get_colored_text("[✗]", color="VULN")
                else:
                    icon = get_colored_text("[!]", color="WARNING")
                self.ptprint(f"    {icon} {info.banner}", Out.TEXT)
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
                    self.ptprint("Service Identification", Out.INFO)
                    self.ptprint(f"    Product:  {sid.product}", Out.TEXT)
                    self.ptprint(
                        f"    Version:  {sid.version if sid.version else 'unknown'}",
                        Out.TEXT,
                    )
                    self.ptprint(f"    CPE:      {sid.cpe}", Out.TEXT)
                    properties.update({"cpe": sid.cpe})

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

        # Anonymous authentication and access permissions
        if (anonymous_error := self.results.anonymous_error) is not None:
            self.ptprint("Authentication", Out.INFO)
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} Anonymous test failed: {anonymous_error}", Out.TEXT)
            properties.update({"anonymousError": anonymous_error})
        elif (access_error := self.results.access_error) is not None:
            self.ptprint("Authentication", Out.INFO)
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} Anonymous authentication is enabled", Out.TEXT)
            self.ptprint(f"    {icon} Access check failed: {access_error}", Out.TEXT)
            properties.update({"accessError": access_error})
        elif (anon := self.results.anonymous) is not None:
            self.ptprint("Authentication", Out.INFO)
            if anon:
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} Anonymous authentication is enabled", Out.TEXT)
            else:
                icon = get_colored_text("[✓]", color="NOTVULN")
                self.ptprint(f"    {icon} Anonymous authentication is disabled", Out.TEXT)
            if anon:
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
                            self.ptprint(f"    {response_str}")
                        except StopIteration:
                            response_str = ""
                    else:
                        response_str = f"Encountered errors during access enumeration:"
                        self.ptprint(response_str, Out.ERROR)

                        for e in access.errors:
                            self.ptprint(e, Out.ERROR)
                            response_str += f"\n{e}"
                else:
                    response_str = ""

                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.Anonymous.value,
                        "vuln_request": "anonymous login",
                        "vuln_response": response_str,
                    }
                )

        # Bruteforced credentials and their access permissions
        if (creds := self.results.creds) is not None:
            self.ptprint(f"Login check: {len(creds)} valid credentials", Out.INFO)

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
                            perm_str = f" Encountered errors during access enumeration:"
                            self.ptprint(f"    {perm_str}", Out.ERROR)

                            for e in access.errors:
                                self.ptprint(f"        {e}", Out.ERROR)
                                perm_str += f"\n{e}"
                    else:
                        perm_str = ""

                    self.ptprint(f"    {cred_str + perm_str}")
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
