import argparse, imaplib, ipaddress, random, re, socket, ssl, string, threading
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
    vendor_from_cpe,
    check_if_brute,
    add_bruteforce_args,
    simple_bruteforce,
)
from .utils.service_identification import identify_service


def valid_target_imap(target: str) -> Target:
    """Argparse helper: IP or hostname with optional port (like SMTP)."""
    return valid_target(target, domain_allowed=True)


def _extract_capabilities_from_banner(banner: str | None) -> list[str]:
    """
    Extract CAPABILITY list from banner * OK [CAPABILITY X Y Z] ...
    Pre-auth capabilities in banner must not be lost when CAPABILITY is also called.
    """
    if not banner:
        return []
    match = re.search(r"\[CAPABILITY\s+([^\]]*)\]", banner, re.IGNORECASE)
    if not match:
        return []
    return [c.strip() for c in match.group(1).split() if c.strip()]


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
    capability: list[str] | None  # Raw list from imap.capabilities (pre-auth or post-STLS)
    capability_starttls: list[str] | None = None  # CAPABILITY after STARTTLS upgrade


class EncryptionResult(NamedTuple):
    """Result of encryption test: plaintext, STARTTLS, implicit TLS."""
    plaintext_ok: bool
    starttls_ok: bool
    tls_ok: bool


CatchAllResult = str  # "configured" | "not_configured" | "indeterminate"


@dataclass
class IMAPResults:
    info: InfoResult | None = None
    info_error: str | None = None  # When connect/info fails
    banner_requested: bool = False
    commands_requested: bool = False
    anonymous: bool | None = None
    ntlm: NTLMResult | None = None
    creds: set[Creds] | None = None
    encryption: EncryptionResult | None = None
    encryption_error: str | None = None
    catch_all: CatchAllResult | None = None


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
    isencrypt: bool

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
                ["-ie", "--isencrypt", "", "Test encryption options (plaintext, STARTTLS, TLS)"],
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
  ptsrvtester imap -ie 127.0.0.1
  ptsrvtester -j imap -u admin -P passwords.txt --brute-threads 20 127.0.0.1:143"""

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
            "-ie",
            "--isencrypt",
            action="store_true",
            help="test encryption options on port (plaintext, STARTTLS, TLS)",
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

        # Default port: 993 for implicit TLS, 143 for plain/STARTTLS
        if args.target.port == 0:
            if args.tls:
                args.target.port = 993
            else:
                args.target.port = 143

        self.do_brute = check_if_brute(args)
        self.use_json = getattr(args, "json", False)

        self.args = args
        self.ptjsonlib = ptjsonlib
        self.results: IMAPResults
        self.imap: imaplib.IMAP4
        self._output_lock = threading.Lock()
        self._streamed_banner = False
        self._streamed_capa = False
        self._streamed_encryption = False
        self._streamed_catch_all = False
        self._streamed_anonymous = False
        self._streamed_ntlm = False
        self._streamed_brute = False

    def _is_default_mode(self) -> bool:
        """True when only target is given (no test switches). Run basic info + anonymous + encryption."""
        return not (
            self.args.info
            or self.args.banner
            or self.args.commands
            or getattr(self.args, "isencrypt", False)
            or self.args.ntlm
            or self.args.anonymous
            or self.do_brute
        )

    def _test_catch_all(self) -> CatchAllResult:
        """Test if server accepts invalid credentials (LOGIN with random user/pass)."""
        try:
            fake_user = "".join(random.choices(string.ascii_letters + string.digits, k=24))
            fake_pass = "".join(random.choices(string.ascii_letters + string.digits, k=24))
            imap = self.connect()
            try:
                imap.login(fake_user, fake_pass)
                return "indeterminate"
            except Exception:
                return "not_configured"
            finally:
                try:
                    imap.logout()
                except Exception:
                    pass
        except Exception:
            return "not_configured"

    def _do_info(
        self, imap: imaplib.IMAP4 | imaplib.IMAP4_SSL, get_commands: bool = True
    ) -> InfoResult:
        """
        Core info logic: banner, ID, CAPABILITY.
        Merges pre-auth CAPABILITY from banner [CAPABILITY ...] with imap.capabilities.
        If on plain and STARTTLS in capabilities, upgrades and gets CAPABILITY again.
        """
        banner = imap.welcome.decode() if imap.welcome else None
        id_val = None
        capability = None
        capability_starttls = None

        if get_commands:
            capa_from_imap = [str(c) for c in imap.capabilities] if imap.capabilities else []
            capa_from_banner = _extract_capabilities_from_banner(banner)
            capability = list(dict.fromkeys(capa_from_imap + capa_from_banner)) or capa_from_imap or capa_from_banner

            try:
                typ, dat = imap.xatom("ID")
                typ, res = imap._untagged_response(typ, dat, "ID")
                if isinstance(res, list):
                    id_ = next((d for d in res), None)
                    if isinstance(id_, bytes):
                        id_val = id_.decode()
                    elif id_ is not None:
                        id_val = str(id_)
            except Exception:
                pass

            if (
                capability
                and "STARTTLS" in [c.upper() for c in capability]
                and self.args.target.port != 993
                and not self.args.tls
                and not isinstance(imap, imaplib.IMAP4_SSL)
            ):
                try:
                    imap.starttls()
                    capability_starttls = [str(c) for c in imap.capabilities] if imap.capabilities else []
                except Exception:
                    pass

        return InfoResult(banner, id_val, capability, capability_starttls)

    def _silent_info(self) -> InfoResult | None:
        """Load banner, ID and CAPABILITY (for brute-only when -i not set)."""
        try:
            imap = self.connect()
            try:
                return self._do_info(imap, get_commands=True)
            finally:
                try:
                    imap.logout()
                except Exception:
                    pass
        except Exception:
            return None

    def test_encryption(self) -> EncryptionResult:
        """
        Test encryption options: plaintext (143), STARTTLS (143), implicit TLS (993).
        Uses fresh connections; does not use self.args.tls/starttls.
        """
        host = self.args.target.ip
        port = self.args.target.port
        timeout = 10.0
        plaintext_ok = False
        starttls_ok = False
        tls_ok = False
        _ssl_ctx = ssl._create_unverified_context()
        tls_only_port = port == 993

        if not tls_only_port:
            try:
                imap = imaplib.IMAP4(host, port)
                imap.sock.settimeout(timeout)
                _ = imap.welcome
                plaintext_ok = True
                imap.logout()
            except Exception:
                pass

            try:
                imap = imaplib.IMAP4(host, port)
                imap.sock.settimeout(timeout)
                _ = imap.welcome
                caps = [str(c).upper() for c in (imap.capabilities or [])]
                if "STARTTLS" in caps:
                    imap.starttls()
                    _ = imap.capabilities
                    starttls_ok = True
                imap.logout()
            except Exception:
                pass

        _connect_timeout = 15.0 if tls_only_port else timeout
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
                    sock = socket.create_connection((host, port), timeout=_connect_timeout)
                    sock_ssl = _ssl_ctx.wrap_socket(sock, server_hostname=_sni)
                    sock_ssl.settimeout(_connect_timeout)
                    sock_ssl.sendall(b"a001 CAPABILITY\r\n")
                    line = sock_ssl.recv(1024).decode(errors="replace")
                    sock_ssl.close()
                    if line and ("OK" in line or "CAPABILITY" in line):
                        tls_ok = True
                        break
                except Exception:
                    pass
        except Exception:
            pass

        return EncryptionResult(plaintext_ok, starttls_ok, tls_ok)

    def run(self) -> None:
        """Executes IMAP methods based on module configuration. All results streamed immediately."""
        self.results = IMAPResults()

        isencrypt = getattr(self.args, "isencrypt", False)
        if (
            isencrypt
            and not self.args.info
            and not self.args.banner
            and not self.args.commands
            and not self.args.ntlm
            and not self.args.anonymous
            and not self.do_brute
        ):
            try:
                self.results.encryption = self.test_encryption()
            except Exception as e:
                self.results.encryption_error = str(e)
            self._stream_encryption_result()
            return

        if self._is_default_mode():
            self.results.banner_requested = True
            self.results.commands_requested = True
        try:
            self.imap = self.connect()
        except (SystemExit, KeyboardInterrupt):
            raise
        except Exception as e:
            self.results.info_error = str(e)
            return

        if self._is_default_mode():
            self.results.info = self.info(get_commands=True)
            self._stream_banner_result()
            self._stream_capa_result()
            if self.args.target.port == 993:
                self.results.encryption = EncryptionResult(
                    plaintext_ok=False, starttls_ok=False, tls_ok=True
                )
            elif self.results.info and self.results.info.capability and any(
                "STARTTLS" in str(c).upper() for c in self.results.info.capability
            ):
                self.results.encryption = EncryptionResult(
                    plaintext_ok=True, starttls_ok=True, tls_ok=False
                )
            else:
                self.results.encryption = EncryptionResult(
                    plaintext_ok=True, starttls_ok=False, tls_ok=False
                )
            self._stream_encryption_result()
            self.results.anonymous = self.auth_anonymous()
            self._stream_anonymous_result()
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
                getattr(info, "capability_starttls", None) if do_commands else None,
            )
            self._stream_banner_result()
            self._stream_capa_result()

        if isencrypt:
            try:
                self.results.encryption = self.test_encryption()
            except Exception as e:
                self.results.encryption_error = str(e)
            self._stream_encryption_result()

        if self.args.ntlm:
            self.results.ntlm = self.auth_ntlm()
            self._stream_ntlm_result()

        if self.args.anonymous:
            self.results.anonymous = self.auth_anonymous()
            self._stream_anonymous_result()

        if self.do_brute:
            if not (
                self.args.info or self.args.banner or self.args.commands
                or isencrypt or self.args.ntlm or self.args.anonymous
            ):
                silent = self._silent_info()
                if silent:
                    self.results.info = silent
                    self.results.banner_requested = True
                    self.results.commands_requested = True
                    self._stream_banner_result()
                    self._stream_capa_result()

            self.results.catch_all = self._test_catch_all()
            self._stream_catch_all_result()

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
        """Performs bannergrabbing; optionally ID and CAPABILITY commands."""
        return self._do_info(self.imap, get_commands)

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
        # Manual send/read; use dynamic tag to avoid threading conflicts
        imap = self.connect()
        try:
            tag = imap._new_tag().decode()
            imap.send(f"{tag} AUTHENTICATE NTLM\r\n".encode())
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

    def _on_brute_success(self, cred: Creds) -> None:
        """Callback for real-time streaming of found credentials (thread-safe)."""
        with self._output_lock:
            self.ptprint(f"    user: {cred.user}, password: {cred.passw}", Out.TEXT)

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

    def _stream_capa_result(self) -> None:
        if self.use_json or not (info := self.results.info):
            return
        capa = info.capability or getattr(info, "capability_starttls", None)
        if not capa and not info.id:
            return
        with self._output_lock:
            if info.id is not None:
                self.ptprint("ID command", Out.INFO)
                self.ptprint(f"    {info.id}", Out.TEXT)
            if capa:
                capa_stls = getattr(info, "capability_starttls", None)
                if capa_stls is not None:
                    self.ptprint("CAPABILITY command (PLAIN)", Out.INFO)
                    for display_str, level in _parse_capability_commands(info.capability or []):
                        icon = get_colored_text("[✗]", color="VULN") if level == "ERROR" else (
                            get_colored_text("[!]", color="WARNING") if level == "WARNING"
                            else get_colored_text("[✓]", color="NOTVULN")
                        )
                        self.ptprint(f"    {icon} {display_str}", Out.TEXT)
                    self.ptprint("CAPABILITY command (STARTTLS)", Out.INFO)
                    for display_str, level in _parse_capability_commands(capa_stls):
                        icon = get_colored_text("[✗]", color="VULN") if level == "ERROR" else (
                            get_colored_text("[!]", color="WARNING") if level == "WARNING"
                            else get_colored_text("[✓]", color="NOTVULN")
                        )
                        self.ptprint(f"    {icon} {display_str}", Out.TEXT)
                else:
                    encrypted = self.args.target.port == 993 or self.args.tls
                    title = "CAPABILITY command (TLS)" if encrypted else "CAPABILITY command (PLAIN)"
                    self.ptprint(title, Out.INFO)
                    for display_str, level in _parse_capability_commands(capa):
                        icon = get_colored_text("[✗]", color="VULN") if level == "ERROR" else (
                            get_colored_text("[!]", color="WARNING") if level == "WARNING"
                            else get_colored_text("[✓]", color="NOTVULN")
                        )
                        self.ptprint(f"    {icon} {display_str}", Out.TEXT)
        self._streamed_capa = True

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
            plaintext_only = enc.plaintext_ok and not enc.starttls_ok and not enc.tls_ok
            any_ok = enc.plaintext_ok or enc.starttls_ok or enc.tls_ok
            if plaintext_only:
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} Plaintext only", Out.TEXT)
            elif any_ok:
                if enc.plaintext_ok:
                    icon = (
                        get_colored_text("[!]", color="WARNING")
                        if (enc.starttls_ok or enc.tls_ok)
                        else get_colored_text("[✓]", color="NOTVULN")
                    )
                    self.ptprint(f"    {icon} Plaintext", Out.TEXT)
                if enc.starttls_ok:
                    icon = get_colored_text("[✓]", color="NOTVULN")
                    self.ptprint(f"    {icon} STARTTLS", Out.TEXT)
                if enc.tls_ok:
                    icon = get_colored_text("[✓]", color="NOTVULN")
                    self.ptprint(f"    {icon} TLS", Out.TEXT)
            else:
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(
                    f"    {icon} No connection mode available (plaintext, STARTTLS, TLS failed)",
                    Out.TEXT,
                )
        self._streamed_encryption = True

    def _stream_catch_all_result(self) -> None:
        if self.use_json or (catch_all := getattr(self.results, "catch_all", None)) is None:
            return
        with self._output_lock:
            self.ptprint("Catch-all test", Out.INFO)
            if catch_all == "indeterminate":
                icon = get_colored_text("[!]", color="WARNING")
                self.ptprint(
                    f"    {icon} Server accepted invalid credentials (indeterminate). Results may be false positives.",
                    Out.TEXT,
                )
            else:
                icon = get_colored_text("[✓]", color="NOTVULN")
                self.ptprint(f"    {icon} Not configured (server rejects invalid creds)", Out.TEXT)
        self._streamed_catch_all = True

    def _stream_anonymous_result(self) -> None:
        if self.use_json or (anonymous := self.results.anonymous) is None:
            return
        with self._output_lock:
            self.ptprint("Anonymous authentication", Out.INFO)
            if anonymous:
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} Enabled", Out.TEXT)
            else:
                icon = get_colored_text("[✓]", color="NOTVULN")
                self.ptprint(f"    {icon} Disabled", Out.TEXT)
        self._streamed_anonymous = True

    def _stream_ntlm_result(self) -> None:
        if self.use_json or (ntlm := self.results.ntlm) is None:
            return
        with self._output_lock:
            self.ptprint("NTLM information", Out.INFO)
            if not ntlm.success:
                self.ptprint("    NTLM information failed", Out.TEXT)
            elif ntlm.ntlm is not None:
                for line in [
                    f"Target name: {ntlm.ntlm.target_name}",
                    f"NetBios domain name: {ntlm.ntlm.netbios_domain}",
                    f"NetBios computer name: {ntlm.ntlm.netbios_computer}",
                    f"DNS domain name: {ntlm.ntlm.dns_domain}",
                    f"DNS computer name: {ntlm.ntlm.dns_computer}",
                    f"DNS tree: {ntlm.ntlm.dns_tree}",
                    f"OS version: {ntlm.ntlm.os_version}",
                ]:
                    self.ptprint(f"    {line}", Out.TEXT)
        self._streamed_ntlm = True

    def _stream_brute_result(self) -> None:
        creds = self.results.creds
        if creds is None:
            return
        if not self.use_json and len(creds) > 0:
            with self._output_lock:
                self.ptprint(f"    Found {len(creds)} valid credentials", Out.INFO)
        self._streamed_brute = True

    # region output

    def output(self) -> None:
        """Formats and outputs module results. Skips streamed sections in text mode; JSON always complete."""
        properties = {
            "software_type": None,
            "name": "imap",
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
            imap_node = self.ptjsonlib.create_node_object("software", None, None, properties)
            self.ptjsonlib.add_node(imap_node)
            node_key = imap_node["key"]
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

        # ID and CAPABILITY (skip terminal if streamed; always add to properties for JSON)
        if (info := self.results.info) and (info.id is not None or info.capability or getattr(info, "capability_starttls", None)):
            capa = info.capability or []
            capa_stls = getattr(info, "capability_starttls", None)
            if info.id is not None:
                properties.update({"idCommand": info.id})
            if capa or capa_stls:
                def _capa_to_lines(cl: list[str]) -> list[str]:
                    return [d for d, _ in _parse_capability_commands(cl)]
                if capa_stls is not None:
                    json_lines = _capa_to_lines(capa) + ["---"] + _capa_to_lines(capa_stls)
                else:
                    json_lines = _capa_to_lines(capa)
                properties.update({"capabilityCommand": "\n".join(json_lines)})
            if not self.use_json and not self._streamed_capa:
                if info.id is not None:
                    self.ptprint("ID command", Out.INFO)
                    self.ptprint(f"    {info.id}", Out.TEXT)
                if capa or capa_stls:
                    if capa_stls is not None:
                        self.ptprint("CAPABILITY command (PLAIN)", Out.INFO)
                        for display_str, level in _parse_capability_commands(capa):
                            icon = get_colored_text("[✗]", color="VULN") if level == "ERROR" else (
                                get_colored_text("[!]", color="WARNING") if level == "WARNING"
                                else get_colored_text("[✓]", color="NOTVULN")
                            )
                            self.ptprint(f"    {icon} {display_str}", Out.TEXT)
                        self.ptprint("CAPABILITY command (STARTTLS)", Out.INFO)
                        for display_str, level in _parse_capability_commands(capa_stls):
                            icon = get_colored_text("[✗]", color="VULN") if level == "ERROR" else (
                                get_colored_text("[!]", color="WARNING") if level == "WARNING"
                                else get_colored_text("[✓]", color="NOTVULN")
                            )
                            self.ptprint(f"    {icon} {display_str}", Out.TEXT)
                    else:
                        encrypted = self.args.target.port == 993 or self.args.tls
                        title = "CAPABILITY command (TLS)" if encrypted else "CAPABILITY command (PLAIN)"
                        self.ptprint(title, Out.INFO)
                        for display_str, level in _parse_capability_commands(capa):
                            icon = get_colored_text("[✗]", color="VULN") if level == "ERROR" else (
                                get_colored_text("[!]", color="WARNING") if level == "WARNING"
                                else get_colored_text("[✓]", color="NOTVULN")
                            )
                            self.ptprint(f"    {icon} {display_str}", Out.TEXT)

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
                        "starttls": enc.starttls_ok,
                        "tls": enc.tls_ok,
                    }
                }
            )
            if not self.use_json and not self._streamed_encryption:
                self.ptprint("Encryption", Out.INFO)
                plaintext_only = enc.plaintext_ok and not enc.starttls_ok and not enc.tls_ok
                any_ok = enc.plaintext_ok or enc.starttls_ok or enc.tls_ok
                if plaintext_only:
                    icon = get_colored_text("[✗]", color="VULN")
                    self.ptprint(f"    {icon} Plaintext only", Out.TEXT)
                elif any_ok:
                    if enc.plaintext_ok:
                        icon = (
                            get_colored_text("[!]", color="WARNING")
                            if (enc.starttls_ok or enc.tls_ok)
                            else get_colored_text("[✓]", color="NOTVULN")
                        )
                        self.ptprint(f"    {icon} Plaintext", Out.TEXT)
                    if enc.starttls_ok:
                        icon = get_colored_text("[✓]", color="NOTVULN")
                        self.ptprint(f"    {icon} STARTTLS", Out.TEXT)
                    if enc.tls_ok:
                        icon = get_colored_text("[✓]", color="NOTVULN")
                        self.ptprint(f"    {icon} TLS", Out.TEXT)
                else:
                    icon = get_colored_text("[✗]", color="VULN")
                    self.ptprint(
                        f"    {icon} No connection mode available (plaintext, STARTTLS, TLS failed)",
                        Out.TEXT,
                    )

        # Catch-all (skip terminal if streamed; always add to properties for JSON)
        if (catch_all := getattr(self.results, "catch_all", None)) is not None:
            if catch_all == "indeterminate":
                properties.update({"catchAll": "indeterminate"})
            if not self.use_json and not self._streamed_catch_all:
                self.ptprint("Catch-all test", Out.INFO)
                if catch_all == "indeterminate":
                    icon = get_colored_text("[!]", color="WARNING")
                    self.ptprint(
                        f"    {icon} Server accepted invalid credentials (indeterminate). Results may be false positives.",
                        Out.TEXT,
                    )
                else:
                    icon = get_colored_text("[✓]", color="NOTVULN")
                    self.ptprint(f"    {icon} Not configured (server rejects invalid creds)", Out.TEXT)

        # Anonymous (skip terminal if streamed; always add vuln to deferred for JSON)
        if (anonymous := self.results.anonymous) is not None:
            if anonymous:
                deferred_vulns.append(
                    {"vuln_code": VULNS.Anonymous.value, "vuln_request": "anonymous authentication"}
                )
            if not self.use_json and not self._streamed_anonymous:
                self.ptprint("Anonymous authentication", Out.INFO)
                if anonymous:
                    icon = get_colored_text("[✗]", color="VULN")
                    self.ptprint(f"    {icon} Enabled", Out.TEXT)
                else:
                    icon = get_colored_text("[✓]", color="NOTVULN")
                    self.ptprint(f"    {icon} Disabled", Out.TEXT)

        # NTLM (skip terminal if streamed; always add to properties and deferred for JSON)
        if ntlm := self.results.ntlm:
            if not ntlm.success:
                properties.update({"ntlmInfoStatus": "failed"})
            elif ntlm.ntlm is not None:
                properties.update({"ntlmInfoStatus": "ok"})
                out_lines: list[str] = [
                    f"Target name: {ntlm.ntlm.target_name}",
                    f"NetBios domain name: {ntlm.ntlm.netbios_domain}",
                    f"NetBios computer name: {ntlm.ntlm.netbios_computer}",
                    f"DNS domain name: {ntlm.ntlm.dns_domain}",
                    f"DNS computer name: {ntlm.ntlm.dns_computer}",
                    f"DNS tree: {ntlm.ntlm.dns_tree}",
                    f"OS version: {ntlm.ntlm.os_version}",
                ]
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.NTLM.value,
                        "vuln_request": "ntlm authentication",
                        "vuln_response": "\n".join(out_lines),
                    }
                )
            if not self.use_json and not self._streamed_ntlm:
                self.ptprint("NTLM information", Out.INFO)
                if not ntlm.success:
                    self.ptprint("    NTLM information failed", Out.TEXT)
                elif ntlm.ntlm is not None:
                    for line in [
                        f"Target name: {ntlm.ntlm.target_name}",
                        f"NetBios domain name: {ntlm.ntlm.netbios_domain}",
                        f"NetBios computer name: {ntlm.ntlm.netbios_computer}",
                        f"DNS domain name: {ntlm.ntlm.dns_domain}",
                        f"DNS computer name: {ntlm.ntlm.dns_computer}",
                        f"DNS tree: {ntlm.ntlm.dns_tree}",
                        f"OS version: {ntlm.ntlm.os_version}",
                    ]:
                        self.ptprint(f"    {line}", Out.TEXT)

        # Login bruteforce (skip terminal output if streamed; always add to deferred for JSON)
        if (creds := self.results.creds) is not None and len(creds) > 0:
            if not self.use_json and not self._streamed_brute:
                self.ptprint(f"Login bruteforce: {len(creds)} valid credentials", Out.INFO)
                for cred in creds:
                    self.ptprint(f"    user: {cred.user}, password: {cred.passw}", Out.TEXT)
            json_lines = [f"user: {cred.user}, password: {cred.passw}" for cred in creds]
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

        # Create node at the end with all collected properties and bind vulnerabilities
        imap_node = self.ptjsonlib.create_node_object(
            "software",
            None,
            None,
            properties,
        )
        self.ptjsonlib.add_node(imap_node)
        node_key = imap_node["key"]
        for v in deferred_vulns:
            self.ptjsonlib.add_vulnerability(node_key=node_key, **v)

        self.ptjsonlib.set_status("finished", "")
        self.ptprint(self.ptjsonlib.get_result_json(), json=True)

    # endregion
