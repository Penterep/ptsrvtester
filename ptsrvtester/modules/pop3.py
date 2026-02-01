import argparse, poplib
from base64 import b64encode, b64decode
from dataclasses import dataclass
from enum import Enum
from typing import NamedTuple

from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.ptprinthelper import get_colored_text
from ..ptntlmauth.ptntlmauth import NTLMInfo, get_NegotiateMessage_data, decode_ChallengeMessage_blob

from ._base import BaseModule, BaseArgs, Out
from .utils.helpers import (
    Target,
    Creds,
    ArgsWithBruteforce,
    check_if_brute,
    get_mode,
    text,
    valid_target,
    add_bruteforce_args,
    simple_bruteforce,
)


def valid_target_pop3(target: str) -> Target:
    """Argparse helper: IP or hostname with optional port (like SMTP)."""
    return valid_target(target, domain_allowed=True)


# POP3 CAPA: known capabilities and security classification (IANA RFC 2449, 2595, 3206, 5034, 6856)
POP3_KNOWN_CAPABILITIES = frozenset(
    {
        "TOP", "UIDL", "USER", "SASL", "RESP-CODES", "LOGIN-DELAY", "PIPELINING",
        "EXPIRE", "IMPLEMENTATION", "STLS", "AUTH-RESP-CODE", "UTF8", "LANG",
    }
)
# SASL method -> OK / WARNING / ERROR (E=ERROR, W=WARNING, rest OK)
POP3_SASL_METHOD_LEVEL = {
    "PLAIN": "ERROR", "LOGIN": "ERROR", "CRAM-MD5": "ERROR", "DIGEST-MD5": "ERROR",
    "NTLM": "ERROR", "ANONYMOUS": "ERROR", "KERBEROS_V4": "ERROR", "GSSAPI": "ERROR",
    "EXTERNAL": "WARNING",
    "XOAUTH2": "OK", "OAUTHBEARER": "OK", "SCRAM-SHA-1": "OK", "SCRAM-SHA-256": "OK",
}
POP3_CAPA_WARNING = frozenset({"USER", "IMPLEMENTATION"})  # USER=plaintext, IMPLEMENTATION=info disclosure


def _parse_capa_commands(capability: dict[str, list[str]]) -> list[tuple[str, str]]:
    """
    Parse POP3 CAPA dict into list of (display_string, level) for output.
    Level is OK, WARNING, or ERROR. Expands SASL into separate methods.
    If STLS is not advertised, appends [✗] STLS (is not allowed).
    """
    if not capability:
        return []
    result: list[tuple[str, str]] = []
    seen_stls = False

    for capa, vals in sorted(capability.items()):
        capa_upper = str(capa or "").upper().strip()
        vals_str = [str(v) for v in (vals or [])]

        if capa_upper == "STLS":
            seen_stls = True

        if capa_upper == "SASL":
            methods = vals_str
            for method in methods:
                method_upper = method.upper()
                level = POP3_SASL_METHOD_LEVEL.get(method_upper, "OK")
                result.append((f"SASL {method_upper}", level))
            continue

        if capa_upper in POP3_CAPA_WARNING:
            level = "WARNING"
        elif capa_upper in POP3_KNOWN_CAPABILITIES:
            level = "OK"
        else:
            level = "OK"  # Unknown capability: show as OK

        display = f"{capa_upper} {' '.join(vals_str)}".strip() if vals_str else capa_upper
        result.append((display, level))

    if not seen_stls:
        result.append(("STLS (is not allowed)", "ERROR"))

    return result


# region data classes


class NTLMResult(NamedTuple):
    success: bool
    ntlm: NTLMInfo | None


class InfoResult(NamedTuple):
    banner: str | None
    capability: dict[str, list[str]] | None


@dataclass
class POP3Results:
    info: InfoResult | None = None
    info_error: str | None = None  # When connect/info fails
    anonymous: bool | None = None
    ntlm: NTLMResult | None = None
    creds: set[Creds] | None = None


class VULNS(Enum):
    Anonymous = "PTV-GENERAL-ANONYMOUS"
    NTLM = "PTV-GENERAL-NTLMINFORMATION"
    WeakCreds = "PTV-GENERAL-WEAKCREDENTIALS"


# endregion

# region arguments


class POP3Args(ArgsWithBruteforce):
    target: Target
    tls: bool
    starttls: bool
    info: bool
    ntlm: bool
    anonymous: bool

    @staticmethod
    def get_help():
        return [
            {"description": ["POP3 Testing Module"]},
            {"usage": ["ptsrvtester pop3 <options> <target>"]},
            {"usage_example": [
                "ptsrvtester pop3 --tls -iAN 127.0.0.1",
                "ptsrvtester pop3 -u admin -P passwords.txt 127.0.0.1:110"
            ]},
            {"options": [
                ["-i", "--info", "", "Grab banner and capabilities"],
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
  ptsrvtester pop3 -h
  ptsrvtester pop3 --tls -iAN 127.0.0.1
  ptsrvtester -j pop3 -u admin -P passwords.txt --threads 20 127.0.0.1:110"""

        parser = subparsers.add_parser(
            name,
            add_help=True,
            epilog=examples,
            formatter_class=argparse.RawTextHelpFormatter,
        )

        if not isinstance(parser, argparse.ArgumentParser):
            raise TypeError  # IDE typing

        parser.add_argument(
            "target",
            type=valid_target_pop3,
            help="IP[:PORT] or HOST[:PORT] (e.g. 127.0.0.1 or mail.example.com:110)",
        )

        parser.add_argument("--tls", action="store_true", help="use implicit SSL/TLS")
        parser.add_argument("--starttls", action="store_true", help="use explicit SSL/TLS")

        recon = parser.add_argument_group("RECON")
        recon.add_argument(
            "-i",
            "--info",
            action="store_true",
            help="grab banner and capabilities",
        )
        recon.add_argument(
            "-A", "--anonymous", action="store_true", help="check anonymous authentication"
        )
        recon.add_argument("-N", "--ntlm", action="store_true", help="inspect NTLM authentication")

        add_bruteforce_args(parser)


# endregion


# region main module code


class POP3(BaseModule):
    @staticmethod
    def module_args():
        return POP3Args()

    def __init__(self, args: BaseArgs, ptjsonlib: PtJsonLib):

        if not isinstance(args, POP3Args):
            raise argparse.ArgumentError(
                None, f'module "{args.module}" received wrong arguments namespace'
            )

        # Default port number
        if args.target.port == 0:
            if args.tls:
                args.target.port = 990
            else:
                args.target.port = 110

        self.do_brute = check_if_brute(args)

        self.args = args
        self.ptjsonlib = ptjsonlib
        self.results: POP3Results
        self.pop3: poplib.POP3

    def _is_default_mode(self) -> bool:
        """True when only target is given (no test switches). Run basic info + anonymous."""
        return not (
            self.args.info
            or self.args.ntlm
            or self.args.anonymous
            or self.do_brute
        )

    def run(self) -> None:
        """Executes POP3 methods based on module configuration"""
        self.results = POP3Results()
        try:
            self.pop3 = self.connect()
        except (SystemExit, KeyboardInterrupt):
            raise
        except Exception as e:
            self.results.info_error = str(e)
            return

        if self._is_default_mode():
            # Only target given: run basic tests (info + anonymous), like FTP
            self.results.info = self.info()
            self.results.anonymous = self.auth_anonymous()
            return

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
                self.args.users,
                self.args.password,
                self.args.passwords,
                self.args.spray,
                self.args.threads,
            )

    def connect(self) -> poplib.POP3 | poplib.POP3_SSL:
        """
        Establishes a new POP3 connection with the appropriate
        encryption mode according to module arguments

        Returns:
            poplib.POP3 | poplib.POP3_SSL: new connection
        """
        try:
            if self.args.tls:
                pop3 = poplib.POP3_SSL(self.args.target.ip, self.args.target.port)
            else:
                pop3 = poplib.POP3(self.args.target.ip, self.args.target.port)
                if self.args.starttls:
                    pop3.stls()
        except Exception as e:
            msg = (
                f"Could not connect to the target server "
                + f"{self.args.target.ip}:{self.args.target.port} ({get_mode(self.args)}): {e}"
            )
            raise OSError(msg) from e
        return pop3

    def info(self) -> InfoResult:
        """Performs bannergrabbing and CAPA command

        Returns:
            InfoResult: results
        """
        banner = self.pop3.welcome
        try:
            capability = self.pop3.capa()
        except poplib.error_proto:
            capability = None

        return InfoResult(text(banner), capability)

    def auth_anonymous(self) -> bool:
        """Attempts anonymous authentication

        Returns:
            bool: result
        """
        try:
            res: bytes = self.pop3._shortcmd("AUTH ANONYMOUS")

            # Only "+" awaiting further data?
            if len(res.strip()) == 1:
                res = self.pop3._shortcmd(b64encode(b"HELLO").decode())

            return True
        except:
            return False

    def auth_ntlm(self) -> NTLMResult:
        """
        Performs NTLM authentication to extract internal server
        information from server's challenge response.

        Returns:
            NTLMResult: operation status and disclosed information
        """

        try:
            # Separate connection not to corrupt the main socket
            pop3 = self.connect()

            res: bytes = pop3._shortcmd("AUTH NTLM")
            if res.strip().startswith(b"+"):
                b64_ntlm_negotiation = b64encode(get_NegotiateMessage_data()).decode()
                res = pop3._shortcmd(b64_ntlm_negotiation).strip()

                # res = b'+ base64containing+signs'
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
            pop3 = self.connect()
        except OSError:
            return None
        try:
            pop3.user(creds.user)
            pop3.pass_(creds.passw)
            result = creds
        except:
            result = None
        finally:
            pop3.close()
            return result

    # region output

    def output(self) -> None:
        """Formats and outputs module results, both normal and JSON mode"""
        properties: dict[str, None | str | int | list[str]] = self.ptjsonlib.json_object["results"][
            "properties"
        ]

        # Server information
        if (info_error := self.results.info_error) is not None:
            self.ptprint("Server information", Out.INFO)
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} Info test failed: {info_error}", Out.TEXT)
            properties["infoError"] = info_error
        elif info := self.results.info:
            self.ptprint("Server information", Out.INFO)

            self.ptprint("Banner", Out.INFO)
            self.ptprint(f"    {info.banner}")
            properties["banner"] = info.banner

            if capability := info.capability:
                self.ptprint("CAPA command", Out.INFO)
                parsed = _parse_capa_commands(capability)
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
                properties["capability"] = "\n".join(json_lines)

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
