import argparse, ftplib, re, random
from dataclasses import dataclass
from enum import Enum
from io import BytesIO
from ssl import SSLSocket
from string import ascii_uppercase
from typing import NamedTuple

from ptlibs.ptjsonlib import PtJsonLib

from ._base import BaseModule, BaseArgs, Out
from .utils.helpers import (
    Target,
    Creds,
    ArgsWithBruteforce,
    check_if_brute,
    get_mode,
    valid_target,
    add_bruteforce_args,
    simple_bruteforce,
)


# region helper methods


def valid_target_bounce(target: str) -> Target:
    """Argparse helper function for argument"""
    return valid_target(target, port_required=True)


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
    syst: str | None
    stat: str | None


@dataclass
class FTPResults:
    info: InfoResult | None = None
    access: AccessCheckResult | None = None
    anonymous: bool | None = None
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

    def add_subparser(self, name: str, subparsers) -> None:
        """Adds a subparser of FTP arguments"""

        examples = """example usage:
  ptsrvtester ftp -h
  ptsrvtester ftp --starttls -iAal 127.0.0.1
  ptsrvtester -j ftp -u admin -P passwords.txt --threads 20 127.0.0.1:21"""

        parser = subparsers.add_parser(
            name,
            epilog=examples,
            add_help=True,
            formatter_class=argparse.RawTextHelpFormatter,
        )

        if not isinstance(parser, argparse.ArgumentParser):
            raise TypeError  # IDE typing

        parser.add_argument(
            "target", type=valid_target, help="IP[:PORT] (e.g. 127.0.0.1 or 127.0.0.1:21)"
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
            help="grab banner and inspect STAT an SYST commands",
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
            "-b",
            "--bounce",
            type=valid_target_bounce,
            help="bounce to the specified IP:PORT service",
        )
        bounce.add_argument(
            "-B",
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

    def run(self) -> None:
        """Executes FTP methods based on module configuration"""
        self.results = FTPResults()
        self.ftp = self.connect()

        if self.args.anonymous:
            self.results.anonymous = self.anonymous()

        if self.do_brute:
            self.results.creds = simple_bruteforce(
                self._try_login,
                self.args.user,
                self.args.users_file,
                self.args.passw,
                self.args.passw_file,
                self.args.spray,
                self.args.threads,
            )

        if self.args.info:
            self.results.info = self.info()

        if self.args.access:
            self.results.access = self.access_check()

            # Bounce requires acccess check
            if self.args.bounce:
                self.results.bounce = self.bounce()

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
            self.ptjsonlib.end_error(
                f"Could not connect to the target server "
                + f"{self.args.target.ip}:{self.args.target.port} ({get_mode(self.args)}): {e}",
                self.args.json,
            )
            raise SystemExit

        # Passive/Active mode
        ftp.set_pasv(not self.args.active)
        return ftp

    def info(self) -> InfoResult:
        """Performs bannergrabbing, SYST and STAT commands

        Returns:
            InfoResult: results
        """

        banner = self.ftp.welcome
        if banner is None:
            banner = ""

        try:
            syst = self.ftp.sendcmd("SYST")

            # Meaningless answer
            if re.match(r"[0-9]+ UNIX Type: L8", syst):
                syst = None
        except:
            syst = None

        try:
            # Executing STAT without login usually fails
            # If there was no anonymous auth, try to login using random valid creds
            if not self.results.anonymous and self.results.creds is not None:
                # use creds without removing them from the set
                for creds in self.results.creds:
                    self.ftp.login(creds.user, creds.passw)
                    break

            stat = self.ftp.sendcmd("STAT")
        except:
            stat = None

        return InfoResult(banner, syst, stat)

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
            if "cannot change directory" in str(e.args[0]).lower():
                result = creds
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
        properties: dict[str, None | str | int | list[str]] = self.ptjsonlib.json_object["results"][
            "properties"
        ]

        # Basic information
        if info := self.results.info:
            self.ptprint("Server information", title=True)

            self.ptprint(f"Banner:", Out.INFO)
            self.ptprint(f"{info.banner}")
            properties["banner"] = info.banner

            self.ptprint(f"SYST command:", Out.INFO)
            self.ptprint(f"{info.syst}")
            properties["systCommand"] = info.syst

            self.ptprint(f"STAT command:", Out.INFO)
            self.ptprint(f"{info.stat}")
            properties["statCommand"] = info.stat

        # Anonymous authentication and access permissions
        if (anon := self.results.anonymous) is not None:
            self.ptprint(f"Anonymous authentication: {anon}", title=True)
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
                            self.ptprint(response_str)
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

                self.ptjsonlib.add_vulnerability(
                    VULNS.Anonymous.value, "anonymous login", response_str
                )

        # Bruteforced credentials and their access permissions
        if (creds := self.results.creds) is not None:
            self.ptprint(f"Login check: {len(creds)} valid credentials", title=True)

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
                            self.ptprint(perm_str, Out.ERROR)

                            for e in access.errors:
                                self.ptprint(e, Out.ERROR)
                                perm_str += f"\n{e}"
                    else:
                        perm_str = ""

                    self.ptprint(cred_str + perm_str)
                    json_lines.append(cred_str + perm_str)

                if self.args.user is not None:
                    user_str = f"username: {self.args.user}"
                else:
                    user_str = f"usernames: {self.args.users_file}"

                if self.args.passw is not None:
                    passw_str = f"password: {self.args.passw}"
                else:
                    passw_str = f"passwords: {self.args.passw_file}"

                self.ptjsonlib.add_vulnerability(
                    VULNS.WeakCreds.value,
                    f"{user_str}\n{passw_str}",
                    "\n".join(json_lines),
                )

        # Directory listing
        if (
            self.args.access_list
            and (access := self.results.access) is not None
            and access.results is not None
        ):
            try:
                p = next(p for p in access.results if p.dirlist is not None and len(p.dirlist) > 0)
                self.ptprint("Directory listing", title=True)

                out_str = "\n".join(p.dirlist)
                self.ptprint(out_str)
                properties["directoryListing"] = out_str
            except StopIteration:
                self.ptprint("Directory listing failed (no access or empty listing)", title=True)
                properties["directoryListing"] = "no access or empty"

        # Bounce attack
        if bounce := self.results.bounce:
            if (creds := bounce.used_creds) is None:
                self.ptprint(f"Bounce attack failed (no valid credentials)", title=True)
                properties["bounceStatus"] = "no valid credentials"
            else:
                self.ptprint("Bounce attack", title=True)
                self.ptprint(f"Creds used: {creds.user}:{creds.passw}", Out.INFO)

                res = "Yes" if bounce.bounce_accepted else "No"
                self.ptprint("Bounce allowed: " + res, Out.INFO)

                if not bounce.bounce_accepted:
                    properties["bounceStatus"] = "rejected"
                else:
                    properties["bounceStatus"] = "ok"

                    if (r := bounce.request) is None:
                        out_str = f"Target port reachable: {bounce.port_accessible}"
                        self.ptprint(out_str, Out.INFO)
                        self.ptjsonlib.add_vulnerability(
                            VULNS.Bounce.value,
                            f"Bounce port scan target: {bounce.target.ip}:{bounce.target.port}\n"
                            + f"Creds used: {creds.user}:{creds.passw}",
                            out_str,
                        )
                    else:
                        res = f"Yes ({r.ftpserver_filepath})" if r.stored else "No"
                        stored_str = "Stored on FTP server: " + res
                        self.ptprint(stored_str, Out.INFO)

                        res = "Yes" if r.uploaded else "No"
                        sent_str = "Sent to bounce target: " + res
                        self.ptprint(sent_str, Out.INFO)

                        res = "Yes" if r.cleaned else "No"
                        clean_str = "Cleaned up: " + res
                        self.ptprint(clean_str, Out.INFO)

                        self.ptjsonlib.add_vulnerability(
                            VULNS.Bounce.value,
                            f"Bounce request target: {bounce.target.ip}:{bounce.target.port}\n"
                            + f"Creds used: {creds.user}:{creds.passw}"
                            + f"Request file: {self.args.bounce_file}",
                            "\n".join([stored_str, sent_str, clean_str]),
                        )

        self.ptjsonlib.set_status("finished", "")
        self.ptprint(self.ptjsonlib.get_result_json(), json=True)


# endregion
