import argparse, ipaddress, poplib, socket, ssl
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
from .utils.service_identification import identify_service


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
# SASL method -> OK / WARNING / ERROR when on PLAIN. Over STLS/TLS all are OK (RFC 8314).
POP3_SASL_METHOD_LEVEL_PLAIN = {
    "PLAIN": "ERROR", "LOGIN": "ERROR", "CRAM-MD5": "ERROR", "DIGEST-MD5": "ERROR",
    "NTLM": "ERROR", "ANONYMOUS": "ERROR", "KERBEROS_V4": "ERROR", "GSSAPI": "ERROR",
    "EXTERNAL": "WARNING",
    "XOAUTH2": "OK", "OAUTHBEARER": "OK", "SCRAM-SHA-1": "OK", "SCRAM-SHA-256": "OK",
}
POP3_CAPA_WARNING = frozenset({"USER", "IMPLEMENTATION"})  # USER=plaintext, IMPLEMENTATION=info disclosure


def _parse_capa_commands(
    capability: dict[str, list[str]], connection_encrypted: bool = False
) -> list[tuple[str, str]]:
    """
    Parse POP3 CAPA dict into list of (display_string, level) for output.
    Level is OK, WARNING, or ERROR. Expands SASL into separate methods.
    When connection_encrypted is True (STLS/TLS), SASL PLAIN/LOGIN etc. are OK (RFC 8314).
    If STLS is not advertised (on plain), appends [✗] STLS (is not allowed).
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
                level = "OK" if connection_encrypted else POP3_SASL_METHOD_LEVEL_PLAIN.get(method_upper, "OK")
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

    if not seen_stls and not connection_encrypted:
        result.append(("STLS (is not allowed)", "ERROR"))

    return result


# region data classes


class NTLMResult(NamedTuple):
    success: bool
    ntlm: NTLMInfo | None


class InfoResult(NamedTuple):
    banner: str | None
    capability: dict[str, list[str]] | None
    capability_stls: dict[str, list[str]] | None = None  # CAPA after STLS upgrade (when PLAIN had STLS)


class EncryptionResult(NamedTuple):
    """
    Result of encryption test: which connection types are available on the port.
    Stored in POP3Results.encryption so that subsequent logic can use it.
    """
    plaintext_ok: bool
    stls_ok: bool
    tls_ok: bool


@dataclass
class POP3Results:
    info: InfoResult | None = None
    info_error: str | None = None  # When connect/info fails
    banner_requested: bool = False
    commands_requested: bool = False
    anonymous: bool | None = None
    ntlm: NTLMResult | None = None
    creds: set[Creds] | None = None
    encryption: EncryptionResult | None = None
    encryption_error: str | None = None


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
    isencrypt: bool

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
                ["-i", "--info", "", "Grab banner and capabilities (CAPA)"],
                ["-b", "--banner", "", "Grab banner + Service Identification (product, version, CPE)"],
                ["-c", "--commands", "", "Grab CAPA (capabilities) only"],
                ["-ie", "--isencrypt", "", "Test encryption options (plaintext, STLS, TLS)"],
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
        """Adds a subparser of POP3 arguments"""
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
        recon.add_argument("-b", "--banner", action="store_true", help="grab banner + Service Identification (product, version, CPE)")
        recon.add_argument("-c", "--commands", action="store_true", help="grab CAPA (capabilities) only")
        recon.add_argument(
            "-ie",
            "--isencrypt",
            action="store_true",
            help="test encryption options on port (plaintext, STLS, TLS)",
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
        """True when only target is given (no test switches). Run basic info + anonymous + encryption."""
        return not (
            self.args.info
            or self.args.banner
            or self.args.commands
            or self.args.isencrypt
            or self.args.ntlm
            or self.args.anonymous
            or self.do_brute
        )

    def run(self) -> None:
        """Executes POP3 methods based on module configuration"""
        self.results = POP3Results()

        # Only -ie: no need to connect; test_encryption() opens its own connections
        if (
            self.args.isencrypt
            and not self.args.info
            and not self.args.ntlm
            and not self.args.anonymous
            and not self.do_brute
        ):
            try:
                self.results.encryption = self.test_encryption()
            except Exception as e:
                self.results.encryption_error = str(e)
            return

        if self._is_default_mode():
            self.results.banner_requested = True
            self.results.commands_requested = True
        try:
            self.pop3 = self.connect()
        except (SystemExit, KeyboardInterrupt):
            raise
        except Exception as e:
            self.results.info_error = str(e)
            return

        if self._is_default_mode():
            # Only target given: run basic tests (banner + commands + anonymous + encryption)
            self.results.info = self.info(get_commands=True)
            self.results.anonymous = self.auth_anonymous()
            # Encryption: on port 995 we connected via TLS, so set tls_ok=True.
            # On other ports: success of info() = plaintext works; STLS from CAPA.
            # Full test_encryption() (all three modes) only with -ie flag.
            if self.args.target.port == 995:
                self.results.encryption = EncryptionResult(
                    plaintext_ok=False, stls_ok=False, tls_ok=True
                )
            elif self.results.info and self.results.info.capability and "STLS" in self.results.info.capability:
                self.results.encryption = EncryptionResult(
                    plaintext_ok=True, stls_ok=True, tls_ok=False
                )
            else:
                self.results.encryption = EncryptionResult(
                    plaintext_ok=True, stls_ok=False, tls_ok=False
                )
            return

        if self.args.info or self.args.banner or self.args.commands:
            do_banner = self.args.banner or self.args.info
            do_commands = self.args.commands or self.args.info
            self.results.banner_requested = do_banner
            self.results.commands_requested = do_commands
            info = self.info(get_commands=do_commands)
            self.results.info = InfoResult(
                info.banner if do_banner else None,
                info.capability if do_commands else None,
                getattr(info, "capability_stls", None) if do_commands else None,
            )

        if self.args.isencrypt:
            try:
                self.results.encryption = self.test_encryption()
            except Exception as e:
                self.results.encryption_error = str(e)

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
        encryption mode according to module arguments.
        Port 995 is implicit TLS only, so we use POP3_SSL even without --tls.
        """
        try:
            if self.args.tls or self.args.target.port == 995:
                ctx = ssl._create_unverified_context()
                pop3 = poplib.POP3_SSL(
                    self.args.target.ip,
                    self.args.target.port,
                    context=ctx,
                )
            else:
                pop3 = poplib.POP3(self.args.target.ip, self.args.target.port)
                if self.args.starttls:
                    pop3.stls()
        except Exception as e:
            mode = "TLS" if (self.args.tls or self.args.target.port == 995) else get_mode(self.args)
            msg = (
                f"Could not connect to the target server "
                + f"{self.args.target.ip}:{self.args.target.port} ({mode}): {e}"
            )
            raise OSError(msg) from e
        return pop3

    def test_encryption(self) -> EncryptionResult:
        """
        Test which encryption options are available on the target port:
        plaintext, STLS (STARTTLS), and implicit TLS (POP3_SSL).
        Uses fresh connections for each test; does not use self.args.tls/starttls.
        Same methodology as SMTP: unverified context and, when connecting by IP,
        server_hostname=None for TLS so SNI does not break hostname-only certs.

        The caller stores the return value in self.results.encryption so that
        subsequent logic can use it to select the appropriate connection type.
        """
        host = self.args.target.ip
        port = self.args.target.port
        timeout = 10.0
        plaintext_ok = False
        stls_ok = False
        tls_ok = False

        _ssl_ctx = ssl._create_unverified_context()
        # Port 995 is implicit TLS only: skip plaintext and STLS (they would hang/timeout).
        tls_only_port = port == 995

        if not tls_only_port:
            # 1. Plaintext (no TLS)
            try:
                pop3 = poplib.POP3(host, port, timeout=timeout)
                try:
                    _ = pop3.welcome
                    plaintext_ok = True
                finally:
                    pop3.close()
            except Exception as e:
                self.ptdebug(f"Plaintext test failed: {e}", Out.INFO)

            # 2. STLS (plain then upgrade). RFC 2595: CAPA, then STLS, then CAPA again.
            try:
                pop3 = poplib.POP3(host, port, timeout=timeout)
                try:
                    _ = pop3.welcome
                    caps = pop3.capa()
                    if "STLS" in caps:
                        resp = pop3._shortcmd("STLS")
                        if resp.startswith(b"+OK"):
                            try:
                                ipaddress.ip_address(host)
                                _sni = None
                            except ValueError:
                                _sni = host
                            sock_ssl = _ssl_ctx.wrap_socket(
                                pop3.sock, server_hostname=_sni
                            )
                            pop3.sock = sock_ssl
                            pop3.file = sock_ssl.makefile("rb")
                            pop3._tls_established = True
                            pop3.capa()
                            stls_ok = True
                finally:
                    pop3.close()
            except Exception as e:
                self.ptdebug(f"STLS test failed: {e}", Out.INFO)

        # 3. Implicit TLS (port 995). Manual connect with SNI control.
        _connect_timeout = 15.0 if tls_only_port else timeout
        def _try_implicit_tls(sni):
            sock = socket.create_connection((host, port), timeout=_connect_timeout)
            try:
                sock_ssl = _ssl_ctx.wrap_socket(sock, server_hostname=sni)
                sock_ssl.settimeout(_connect_timeout)  # SSL socket may not inherit timeout
                try:
                    f = sock_ssl.makefile("rb")
                    line = f.readline()
                    f.close()
                    return line and line.strip().startswith(b"+OK")
                finally:
                    sock_ssl.close()
            finally:
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
                except Exception as e:
                    self.ptdebug(f"Implicit TLS test failed (SNI={_sni!r}): {e}", Out.INFO)
        except Exception as e:
            self.ptdebug(f"Implicit TLS test failed: {e}", Out.INFO)

        return EncryptionResult(plaintext_ok, stls_ok, tls_ok)

    def info(self, get_commands: bool = True) -> InfoResult:
        """Performs bannergrabbing; optionally CAPA (capabilities).
        If on plain connection and CAPA advertises STLS, upgrades and gets second CAPA (STLS).

        Returns:
            InfoResult: (banner, capability or None, capability_stls or None)
        """
        banner = self.pop3.welcome
        capability = None
        capability_stls = None
        if get_commands:
            try:
                capability = self.pop3.capa()
            except poplib.error_proto:
                capability = None

            # If on plain connection and server advertises STLS, upgrade and get CAPA again
            if (
                capability
                and "STLS" in capability
                and self.args.target.port != 995
                and not self.args.tls
                and not isinstance(self.pop3, poplib.POP3_SSL)
            ):
                try:
                    self.pop3.stls()
                    capability_stls = self.pop3.capa()
                except Exception:
                    pass

        return InfoResult(text(banner), capability, capability_stls)

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

        # CAPA command (PLAIN and/or STLS sections)
        if self.results.commands_requested:
            if (info_error := self.results.info_error) is not None:
                self.ptprint("CAPA command", Out.INFO)
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} {info_error}", Out.TEXT)
                if "infoError" not in properties:
                    properties["infoError"] = info_error
            elif info := self.results.info:
                capa_stls = getattr(info, "capability_stls", None)
                encrypted = self.args.target.port == 995 or self.args.tls

                def _emit_capa_section(title: str, capa: dict[str, list[str]], connection_encrypted: bool) -> list[str]:
                    self.ptprint(title, Out.INFO)
                    parsed = _parse_capa_commands(capa, connection_encrypted=connection_encrypted)
                    lines: list[str] = []
                    for display_str, level in parsed:
                        if level == "ERROR":
                            icon = get_colored_text("[✗]", color="VULN")
                        elif level == "WARNING":
                            icon = get_colored_text("[!]", color="WARNING")
                        else:
                            icon = get_colored_text("[✓]", color="NOTVULN")
                        self.ptprint(f"    {icon} {display_str}", Out.TEXT)
                        lines.append(display_str)
                    return lines

                json_lines: list[str] = []
                if info.capability is not None and capa_stls is not None:
                    json_lines = _emit_capa_section("CAPA command (PLAIN)", info.capability, False)
                    json_lines.append("---")
                    json_lines.extend(_emit_capa_section("CAPA command (STLS)", capa_stls, True))
                elif info.capability is not None:
                    title = "CAPA command (TLS)" if encrypted else "CAPA command (PLAIN)"
                    json_lines = _emit_capa_section(title, info.capability, encrypted)
                if json_lines:
                    properties["capability"] = "\n".join(json_lines)

        # Encryption options
        if (encryption_error := self.results.encryption_error) is not None:
            self.ptprint("Encryption", Out.INFO)
            icon = get_colored_text("[✗]", color="VULN")
            self.ptprint(f"    {icon} Encryption test failed: {encryption_error}", Out.TEXT)
            properties["encryptionError"] = encryption_error
        elif (enc := self.results.encryption) is not None:
            self.ptprint("Encryption", Out.INFO)
            plaintext_only = enc.plaintext_ok and not enc.stls_ok and not enc.tls_ok
            any_ok = enc.plaintext_ok or enc.stls_ok or enc.tls_ok
            if plaintext_only:
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} Plaintext only", Out.TEXT)
            elif any_ok:
                if enc.plaintext_ok:
                    icon = get_colored_text("[✓]", color="NOTVULN")
                    self.ptprint(f"    {icon} Plaintext", Out.TEXT)
                if enc.stls_ok:
                    icon = get_colored_text("[✓]", color="NOTVULN")
                    self.ptprint(f"    {icon} STLS", Out.TEXT)
                if enc.tls_ok:
                    icon = get_colored_text("[✓]", color="NOTVULN")
                    self.ptprint(f"    {icon} TLS", Out.TEXT)
            else:
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(
                    f"    {icon} No connection mode available (plaintext, STLS, TLS failed)",
                    Out.TEXT,
                )
            properties["encryption"] = {
                "plaintext": enc.plaintext_ok,
                "stls": enc.stls_ok,
                "tls": enc.tls_ok,
            }

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
