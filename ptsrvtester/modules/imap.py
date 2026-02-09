import argparse, imaplib, random
from base64 import b64decode, b64encode
from dataclasses import dataclass
from enum import Enum
from string import ascii_letters
from typing import NamedTuple

from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.ptprinthelper import get_colored_text
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
from .utils.service_identification import identify_service


def valid_target_imap(target: str) -> Target:
    """Argparse helper: IP or hostname with optional port (like SMTP)."""
    return valid_target(target, domain_allowed=True)


# IMAP CAPABILITY: known capabilities and security classification (IANA RFC 3501, 9051, 4959, etc.)
IMAP_KNOWN_CAPABILITIES = frozenset(
    {
        "IMAP4REV1", "IMAP4REV2", "ACL", "BINARY", "CATENATE", "CHILDREN", "COMPRESS=DEFLATE",
        "CONDSTORE", "ENABLE", "ESEARCH", "ID", "IDLE", "LITERAL+", "LITERAL-", "LOGIN-REFERRALS",
        "LOGINDISABLED", "MAILBOX-REFERRALS", "METADATA", "METADATA-SERVER", "MOVE", "MULTIAPPEND",
        "NAMESPACE", "SASL-IR", "SORT", "STARTTLS", "THREAD", "UIDPLUS", "UNSELECT", "UTF8=ACCEPT",
        "UTF8=ONLY", "WITHIN", "LIST-EXTENDED", "LIST-STATUS", "QRESYNC", "CONTEXT=SEARCH",
        "CONTEXT=SORT", "FILTERS", "NOTIFY", "SPECIAL-USE", "CREATE-SPECIAL-USE", "LIST-MYRIGHTS",
        "RIGHTS=", "QUOTA", "QUOTASET", "APPENDLIMIT", "OBJECTID", "PREVIEW", "SAVEDATE",
    }
)
# AUTH= method -> OK / WARNING / ERROR (same as SMTP/POP3 SASL)
IMAP_AUTH_METHOD_LEVEL = {
    "PLAIN": "ERROR", "LOGIN": "ERROR", "CRAM-MD5": "ERROR", "DIGEST-MD5": "ERROR",
    "NTLM": "ERROR", "ANONYMOUS": "ERROR", "KERBEROS_V4": "ERROR", "GSSAPI": "ERROR",
    "EXTERNAL": "WARNING",
    "XOAUTH2": "OK", "OAUTHBEARER": "OK", "SCRAM-SHA-1": "OK", "SCRAM-SHA-256": "OK",
}


def _parse_capability_commands(capability_list: list[str]) -> list[tuple[str, str]]:
    """
    Parse IMAP CAPABILITY list into (display_string, level) for output.
    Level is OK, WARNING, or ERROR. Expands AUTH=X into separate entries.
    If STARTTLS is not advertised, appends [✗] STARTTLS (is not allowed).
    """
    if not capability_list:
        return []
    result: list[tuple[str, str]] = []
    seen_starttls = False

    for capa in capability_list:
        capa = str(capa or "").strip()
        if not capa:
            continue
        capa_upper = capa.upper()

        if capa_upper == "STARTTLS":
            seen_starttls = True

        if capa_upper.startswith("AUTH="):
            method = capa_upper[5:].strip()
            level = IMAP_AUTH_METHOD_LEVEL.get(method, "OK")
            result.append((capa, level))
            continue

        if capa_upper in IMAP_KNOWN_CAPABILITIES or any(
            capa_upper.startswith(p) for p in ("AUTH=", "THREAD=", "SORT=", "COMPRESS=", "QUOTA=", "RIGHTS=", "I18NLEVEL=", "UTF8=")
        ):
            level = "OK"
        else:
            level = "OK"  # Unknown: show as OK

        result.append((capa, level))

    if not seen_starttls:
        result.append(("STARTTLS (is not allowed)", "ERROR"))

    return result


# region data classes


class NTLMResult(NamedTuple):
    success: bool
    ntlm: NTLMInfo | None


class InfoResult(NamedTuple):
    banner: str | None
    id: str | None
    capability: list[str] | None  # Raw list from imap.capabilities


@dataclass
class IMAPResults:
    info: InfoResult | None = None
    info_error: str | None = None  # When connect/info fails
    banner_requested: bool = False
    commands_requested: bool = False
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
    banner: bool
    commands: bool
    anonymous: bool
    ntlm: bool

    @staticmethod
    def get_help():
        return [
            {"description": ["IMAP Testing Module"]},
            {"usage": ["ptsrvtester imap <options> <target>"]},
            {"usage_example": [
                "ptsrvtester imap --tls -iAN 127.0.0.1",
                "ptsrvtester imap -u admin -P passwords.txt 127.0.0.1:143"
            ]},
            {"options": [
                ["-i", "--info", "", "Grab banner, ID and CAPABILITY"],
                ["-b", "--banner", "", "Grab banner + Service Identification (product, version, CPE)"],
                ["-c", "--commands", "", "Grab ID and CAPABILITY only"],
                ["-A", "--anonymous", "", "Check anonymous authentication"],
                ["-N", "--ntlm", "", "Inspect NTLM authentication"],
                ["", "", "", ""],
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
            "target",
            type=valid_target_imap,
            help="IP[:PORT] or HOST[:PORT] (e.g. 127.0.0.1 or mail.example.com:143)",
        )

        parser.add_argument("--tls", action="store_true", help="use implicit SSL/TLS")
        parser.add_argument("--starttls", action="store_true", help="use explicit SSL/TLS")

        recon = parser.add_argument_group("RECON")
        recon.add_argument(
            "-i",
            "--info",
            action="store_true",
            help="grab banner and inspect ID and CAPABILITY commands",
        )
        recon.add_argument("-b", "--banner", action="store_true", help="grab banner + Service Identification (product, version, CPE)")
        recon.add_argument("-c", "--commands", action="store_true", help="grab ID and CAPABILITY only")
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

    def _is_default_mode(self) -> bool:
        """True when only target is given (no test switches). Run basic info + anonymous."""
        return not (
            self.args.info
            or self.args.banner
            or self.args.commands
            or self.args.ntlm
            or self.args.anonymous
            or self.do_brute
        )

    def run(self) -> None:
        """Executes IMAP methods based on module configuration"""
        self.results = IMAPResults()
        if self._is_default_mode():
            self.results.banner_requested = True
            self.results.commands_requested = True
        self.imap = self.connect()

        if self._is_default_mode():
            # Only target given: run basic tests (banner + commands + anonymous)
            self.results.info = self.info(get_commands=True)
            self.results.anonymous = self.auth_anonymous()
            return

        if self.args.info or self.args.banner or self.args.commands:
            do_banner = self.args.banner or self.args.info
            do_commands = self.args.commands or self.args.info
            self.results.banner_requested = do_banner
            self.results.commands_requested = do_commands
            info = self.info(get_commands=do_commands)
            self.results.info = InfoResult(
                info.banner if do_banner else None,
                info.id if do_commands else None,
                info.capability if do_commands else None,
            )

        if self.args.ntlm:
            self.results.ntlm = self.auth_ntlm()

        if self.args.anonymous:
            self.results.anonymous = self.auth_anonymous()

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
            msg = (
                f"Could not connect to the target server "
                + f"{self.args.target.ip}:{self.args.target.port} ({get_mode(self.args)}): {e}"
            )
            raise OSError(msg) from e
        return imap

    def info(self, get_commands: bool = True) -> InfoResult:
        """Performs bannergrabbing; optionally ID and CAPABILITY commands.

        Returns:
            InfoResult: (banner, id or None, capability or None)
        """
        banner = self.imap.welcome.decode()

        id_val = None
        capability = None
        if get_commands:
            try:
                name = "ID"
                typ, dat = self.imap.xatom(name)
                typ, res = self.imap._untagged_response(typ, dat, name)
                if isinstance(res, list):
                    id_ = next((d for d in res), None)
                    if isinstance(id_, bytes):
                        id_val = id_.decode()
            except Exception:
                pass
            capability = [str(c) for c in self.imap.capabilities]

        return InfoResult(banner, id_val, capability)

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

        try:
            imap = self.connect()
        except OSError:
            return None
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

        # Banner (separate section)
        if self.results.banner_requested:
            if (info_error := self.results.info_error) is not None:
                self.ptprint("Banner", Out.INFO)
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} {info_error}", Out.TEXT)
                properties["infoError"] = info_error
            elif (info := self.results.info) and info.banner is not None:
                self.ptprint("Banner", Out.INFO)
                sid = identify_service(info.banner)
                if sid is None:
                    icon = get_colored_text("[✓]", color="NOTVULN")
                elif sid.version is not None:
                    icon = get_colored_text("[✗]", color="VULN")
                else:
                    icon = get_colored_text("[!]", color="WARNING")
                self.ptprint(f"    {icon} {info.banner}", Out.TEXT)
                properties["banner"] = info.banner
                if sid is not None:
                    self.ptprint("Service Identification", Out.INFO)
                    self.ptprint(f"    Product:  {sid.product}", Out.TEXT)
                    self.ptprint(
                        f"    Version:  {sid.version if sid.version else 'unknown'}",
                        Out.TEXT,
                    )
                    self.ptprint(f"    CPE:      {sid.cpe}", Out.TEXT)
                    properties["serviceIdentification"] = {
                        "product": sid.product,
                        "version": sid.version,
                        "cpe": sid.cpe,
                    }

        # ID and CAPABILITY commands (separate section)
        if self.results.commands_requested:
            if (info_error := self.results.info_error) is not None:
                self.ptprint("ID command", Out.INFO)
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} {info_error}", Out.TEXT)
                if "infoError" not in properties:
                    properties["infoError"] = info_error
                self.ptprint("CAPABILITY command", Out.INFO)
                self.ptprint(f"    {icon} {info_error}", Out.TEXT)
            elif (info := self.results.info) and (info.id is not None or info.capability is not None):
                self.ptprint("ID command", Out.INFO)
                self.ptprint(f"    {info.id}")
                properties["idCommand"] = info.id
                self.ptprint("CAPABILITY command", Out.INFO)
                cap_list = info.capability or []
                parsed = _parse_capability_commands(cap_list)
                json_lines: list[str] = []
                for display_str, level in parsed:
                    if level == "ERROR":
                        icon = get_colored_text("[✗]", color="VULN")
                    elif level == "WARNING":
                        icon = get_colored_text("[!]", color="WARNING")
                    else:
                        icon = get_colored_text("[✓]", color="NOTVULN")
                    self.ptprint(f"    {icon} {display_str}", Out.TEXT)
                    json_lines.append(display_str)
                properties["capabilityCommand"] = "\n".join(json_lines)

        # Anonymous authentication
        if (anonymous := self.results.anonymous) is not None:
            self.ptprint("Anonymous authentication", Out.INFO)
            if anonymous:
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} Enabled", Out.TEXT)
                self.ptjsonlib.add_vulnerability(VULNS.Anonymous.value, "anonymous authentication")
            else:
                icon = get_colored_text("[✓]", color="NOTVULN")
                self.ptprint(f"    {icon} Disabled", Out.TEXT)

        # NTLM authentication
        if ntlm := self.results.ntlm:
            if not ntlm.success:
                self.ptprint(f"NTLM information failed", Out.NOTVULN)
                properties["ntlmInfoStatus"] = "failed"
            elif ntlm.ntlm is not None:
                self.ptprint(f"NTLM information", Out.VULN)
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
                    self.ptprint(f"    {line}", Out.INFO)

                self.ptjsonlib.add_vulnerability(
                    VULNS.NTLM.value, "ntlm authentication", "\n".join(out_lines)
                )

        # Login bruteforce
        if (creds := self.results.creds) is not None:
            self.ptprint(f"Login bruteforce: {len(creds)} valid credentials", Out.INFO)

            if len(creds) > 0:
                json_lines: list[str] = []
                for cred in creds:
                    cred_str = f"user: {cred.user}, password: {cred.passw}"

                    self.ptprint(f"    {cred_str}")
                    json_lines.append(cred_str)

                if self.args.user is not None:
                    user_str = f"username: {self.args.user}"
                else:
                    user_str = f"usernames: {self.args.users}"

                if self.args.password is not None:
                    passw_str = f"password: {self.args.password}"
                else:
                    passw_str = f"passwords: {self.args.passwords}"

                self.ptjsonlib.add_vulnerability(
                    VULNS.WeakCreds.value,
                    f"{user_str}\n{passw_str}",
                    "\n".join(json_lines),
                )

        self.ptjsonlib.set_status("finished", "")
        self.ptprint(self.ptjsonlib.get_result_json(), json=True)

    # endregion
