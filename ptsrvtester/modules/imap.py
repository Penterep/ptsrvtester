import argparse, imaplib, random
from base64 import b64decode, b64encode
from dataclasses import dataclass
from enum import Enum
from string import ascii_letters
from typing import NamedTuple

from ptlibs.ptjsonlib import PtJsonLib
from ..ptntlmauth.ptntlmauth import NTLMInfo, get_NegotiateMessage_data, decode_ChallengeMessage_blob

from ._base import BaseModule, BaseArgs, Out
from .utils.helpers import (
    Target,
    Creds,
    ArgsWithBruteforce,
    get_mode,
    valid_target,
    check_if_brute,
    add_bruteforce_args,
    simple_bruteforce,
)


# region data classes


class NTLMResult(NamedTuple):
    success: bool
    ntlm: NTLMInfo | None


class InfoResult(NamedTuple):
    banner: str
    id: str | None
    capability: str | None


@dataclass
class IMAPResults:
    info: InfoResult | None = None
    anonymous: bool | None = None
    ntlm: NTLMResult | None = None
    creds: set[Creds] | None = None


class VULNS(Enum):
    Anonymous = "PTV-GENERAL-ANONYMOUS"
    NTLM = "PTV-GENERAL-NTLMINFORMATION"
    WeakCreds = "PTV-GENERAL-WEAKCREDENTIALS"


# endregion

# region arguments


class IMAPArgs(ArgsWithBruteforce):
    target: Target
    tls: bool
    starttls: bool
    info: bool
    anonymous: bool
    ntlm: bool

    def add_subparser(self, name: str, subparsers) -> None:
        """Adds a subparser of IMAP arguments"""
        examples = """example usage:
  ptsrvtester imap -h
  ptsrvtester imap --tls -iAN 127.0.0.1
  ptsrvtester -j imap -u admin -P passwords.txt --threads 20 127.0.0.1:143"""

        parser = subparsers.add_parser(
            name,
            epilog=examples,
            add_help=True,
            formatter_class=argparse.RawTextHelpFormatter,
        )

        if not isinstance(parser, argparse.ArgumentParser):
            raise TypeError  # IDE typing

        parser.add_argument(
            "target", type=valid_target, help="IP[:PORT] (e.g. 127.0.0.1 or 127.0.0.1:143)"
        )

        parser.add_argument("--tls", action="store_true", help="use implicit SSL/TLS")
        parser.add_argument("--starttls", action="store_true", help="use explicit SSL/TLS")

        recon = parser.add_argument_group("RECON")
        recon.add_argument(
            "-i",
            "--info",
            action="store_true",
            help="grab banner and inspect ID an CAPABILITY commands",
        )
        recon.add_argument(
            "-A", "--anonymous", action="store_true", help="check anonymous authentication"
        )
        recon.add_argument("-N", "--ntlm", action="store_true", help="inspect NTLM authentication")

        add_bruteforce_args(parser)


# endregion


# region main module code


class IMAP(BaseModule):

    @staticmethod
    def module_args():
        return IMAPArgs()

    def __init__(self, args: BaseArgs, ptjsonlib: PtJsonLib):

        if not isinstance(args, IMAPArgs):
            raise argparse.ArgumentError(
                None, f'module "{args.module}" received wrong arguments namespace'
            )

        # Default port number
        if args.target.port == 0:
            if args.tls:
                args.target.port = 993
            else:
                args.target.port = 143

        self.do_brute = check_if_brute(args)

        self.args = args
        self.ptjsonlib = ptjsonlib
        self.results: IMAPResults
        self.imap: imaplib.IMAP4  # Primary IMAP connection used for most enumeration

    def run(self) -> None:
        """Executes IMAP methods based on module configuration"""
        self.results = IMAPResults()
        self.imap = self.connect()

        if self.args.info:
            self.results.info = self.info()

        if self.args.ntlm:
            self.results.ntlm = self.auth_ntlm()

        if self.args.anonymous:
            self.results.anonymous = self.auth_anonymous()

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

    def connect(self) -> imaplib.IMAP4 | imaplib.IMAP4_SSL:
        """
        Establishes a new IMAP connection with the appropriate
        encryption mode according to module arguments

        Returns:
            imaplib.IMAP4 | imaplib.IMAP4_SSL: new connection
        """
        try:
            if self.args.tls:
                imap = imaplib.IMAP4_SSL(self.args.target.ip, self.args.target.port)
            else:
                imap = imaplib.IMAP4(self.args.target.ip, self.args.target.port)
                if self.args.starttls:
                    imap.starttls()
        except Exception as e:
            self.ptjsonlib.end_error(
                f"Could not connect to the target server "
                + f"{self.args.target.ip}:{self.args.target.port} ({get_mode(self.args)}): {e}",
                self.args.json,
            )
            raise SystemExit
        return imap

    def info(self) -> InfoResult:
        """Performs bannergrabbing, ID and CAPABILITY commands

        Returns:
            InfoResult: results
        """
        banner = self.imap.welcome.decode()

        id = None
        try:
            # According to the built-in commands (e.g. IMAP4.capability())
            name = "ID"
            typ, dat = self.imap.xatom(name)
            typ, res = self.imap._untagged_response(typ, dat, name)

            if isinstance(res, list):
                id_ = next((d for d in res), None)
                if isinstance(id_, bytes):
                    id = id_.decode()
        except:
            pass

        capability = ", ".join(self.imap.capabilities)

        return InfoResult(banner, id, capability)

    def auth_anonymous(self) -> bool:
        """Attempts anonymous authentication

        Returns:
            bool: result
        """

        def authobject(b: bytes):
            return b"".join(
                random.choice(ascii_letters).encode() for _ in range(random.randint(5, 10))
            )

        try:
            typ, _ = self.imap.authenticate("ANONYMOUS", authobject)
            return True if typ == "OK" else False
        except:
            return False

    def auth_ntlm(self) -> NTLMResult:
        """
        Performs NTLM authentication to extract internal server
        information from server's challenge response.

        Returns:
            NTLMResult: operation status and disclosed information
        """
        # Manual send/read
        # This operation might corrupt the IMAP connection state, using a separate connection
        imap = self.connect()
        try:
            imap.send(b"a1 AUTHENTICATE NTLM\r\n")
            res = imap.readline().strip()
            if res.startswith(b"+"):
                imap.send(b64encode(get_NegotiateMessage_data()) + b"\r\n")
                res = imap.readline().strip()

                # res = b'+ base64containing+signs '
                b64_ntlm_challenge = b"+".join(res.split(b"+")[1:])

                ntlminfo = decode_ChallengeMessage_blob(b64decode(b64_ntlm_challenge))
                return NTLMResult(True, ntlminfo)
            else:
                return NTLMResult(False, None)
        except:
            return NTLMResult(False, None)

    def _try_login(self, creds: Creds) -> Creds | None:
        """Login attempt function for bruteforce

        Args:
            creds (Creds): Creds to use for login

        Returns:
            Creds | None: Creds if success, None if failed
        """

        imap = self.connect()
        try:
            imap.login(creds.user, creds.passw)
            result = creds
        except:
            result = None
        finally:
            imap.logout()
            return result

    # region output

    def output(self) -> None:
        """Formats and outputs module results, both normal and JSON mode"""
        properties: dict[str, None | str | int | list[str]] = self.ptjsonlib.json_object["results"][
            "properties"
        ]

        # Server information
        if info := self.results.info:
            self.ptprint("Server information", title=True)

            self.ptprint(f"Banner:", Out.INFO)
            self.ptprint(f"{info.banner}")
            properties["banner"] = info.banner

            self.ptprint(f"ID command:", Out.INFO)
            self.ptprint(f"{info.id}")
            properties["idCommand"] = info.id

            self.ptprint(f"CAPABILITY command:", Out.INFO)
            self.ptprint(f"{info.capability}")
            properties["capabilityCommand"] = info.capability

        # Anonymous authentication
        if (anonymous := self.results.anonymous) is not None:
            self.ptprint(f"Anonymous authentication: {anonymous}", title=True)

            if anonymous:
                self.ptjsonlib.add_vulnerability(VULNS.Anonymous.value, "anonymous authentication")

        # NTLM authentication
        if ntlm := self.results.ntlm:
            if not ntlm.success:
                self.ptprint(f"NTLM information failed", title=True)
                properties["ntlmInfoStatus"] = "failed"
            elif ntlm.ntlm is not None:
                self.ptprint(f"NTLM information", title=True)
                properties["ntlmInfoStatus"] = "ok"

                out_lines: list[str] = []
                out_lines.append(f"Target name: {ntlm.ntlm.target_name}")
                out_lines.append(f"NetBios domain name: {ntlm.ntlm.netbios_domain}")
                out_lines.append(f"NetBios computer name: {ntlm.ntlm.netbios_computer}")
                out_lines.append(f"DNS domain name: {ntlm.ntlm.dns_domain}")
                out_lines.append(f"DNS computer name: {ntlm.ntlm.dns_computer}")
                out_lines.append(f"DNS tree: {ntlm.ntlm.dns_tree}")
                out_lines.append(f"OS version: {ntlm.ntlm.os_version}")

                for line in out_lines:
                    self.ptprint(line, Out.INFO)

                self.ptjsonlib.add_vulnerability(
                    VULNS.NTLM.value, "ntlm authentication", "\n".join(out_lines)
                )

        # Login bruteforce
        if (creds := self.results.creds) is not None:
            self.ptprint(f"Login bruteforce: {len(creds)} valid credentials", title=True)

            if len(creds) > 0:
                json_lines: list[str] = []
                for cred in creds:
                    cred_str = f"user: {cred.user}, password: {cred.passw}"

                    self.ptprint(cred_str)
                    json_lines.append(cred_str)

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

        self.ptjsonlib.set_status("finished", "")
        self.ptprint(self.ptjsonlib.get_result_json(), json=True)

    # endregion
