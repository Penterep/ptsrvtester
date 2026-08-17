"""MSRPC probes shared by the small modules in ``protocols.msrpc.modules``."""
from __future__ import annotations

import argparse
import socket
import sys
import threading
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from enum import Enum
from itertools import product
from typing import NamedTuple

from impacket import uuid
from impacket.dcerpc.v5 import epm, mgmt, transport
from impacket.dcerpc.v5.epm import MSRPC_UUID_PORTMAP
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_WINNT
from impacket.dcerpc.v5.rpch import RPCProxyClientException
from impacket.http import AUTH_NTLM
from impacket.nt_errors import (
    STATUS_ACCOUNT_DISABLED,
    STATUS_ACCOUNT_EXPIRED,
    STATUS_ACCOUNT_LOCKED_OUT,
    STATUS_ACCOUNT_RESTRICTION,
    STATUS_INVALID_LOGON_HOURS,
    STATUS_INVALID_WORKSTATION,
    STATUS_LOGON_FAILURE,
    STATUS_LOGON_TYPE_NOT_GRANTED,
    STATUS_NO_SUCH_USER,
    STATUS_PASSWORD_EXPIRED,
    STATUS_PASSWORD_MUST_CHANGE,
    STATUS_WRONG_PASSWORD,
    STATUS_WRONG_PASSWORD_CORE,
)
from impacket.smbconnection import SMBConnection, SessionError

from .helpers import text_or_file


class Out(Enum):
    TEXT = "TEXT"
    TITLE = "TITLE"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    OK = "OK"
    VULN = "VULN"
    NOTVULN = "NOTVULN"
    ADDITIONS = "ADDITIONS"


class VULNS(Enum):
    # The MSRCP typo is a historical downstream identifier. Do not rename it
    # without confirming the central vulnerability catalogue.
    NullSession = "PTV-MSRCP-SMBNULLSESSION"
    WeakCreds_pipes = "PTV-MSRPC-WEAKPIPECREDS"
    WeakCreds_SMB = "PTV-MSRPC-WEAKSMBCREDS"
    WeakCreds_TCP = "PTV-MSRPC-WEAKRPCCREDS"
    WeakCreds_HTTP = "PTV-MSRPC-WEAKHTTPCREDS"


class Credential(NamedTuple):
    username: str | None
    password: str | None


@dataclass(frozen=True)
class _AttemptResult:
    credential: Credential
    accepted: bool = False
    rejected: bool = False
    error: Exception | None = None


@dataclass
class MSRPCResult:
    EpmapEndpoints: dict | None = None
    MgmtEndpoints: list[str] | None = None
    Pipes: list[str] | None = None
    PipesCreds: list[Credential] | None = None
    Anonymous: list[str] | None = None
    SMB_Brute: list[Credential] | None = None
    TCP_Brute: list[Credential] | None = None
    HTTP_Brute: list[Credential] | None = None
    module_errors: dict[str, str] = field(default_factory=dict)


KNOWN_INTERFACE_UUIDS: dict[str, dict[str, str]] = {
    "12345778-1234-abcd-ef00-0123456789ab": {
        "pipe": r"\pipe\lsarpc",
        "description": "LSA interface, used to enumerate users.",
    },
    "3919286a-b10c-11d0-9ba8-00c04fd92ef5": {
        "pipe": r"\pipe\lsarpc",
        "description": "LSA Directory Services interface for domains and trusts.",
    },
    "12345778-1234-abcd-ef00-0123456789ac": {
        "pipe": r"\pipe\samr",
        "description": "SAMR interface exposing account-management operations.",
    },
    "1ff70682-0a51-30e8-076d-740be8cee98b": {
        "pipe": r"\pipe\atsvc",
        "description": "Legacy task-scheduler interface.",
    },
    "338cd001-2244-31f1-aaaa-900038001003": {
        "pipe": r"\pipe\winreg",
        "description": "Remote Registry interface.",
    },
    "367abb81-9844-35f1-ad32-98f038001003": {
        "pipe": r"\pipe\svcctl",
        "description": "Service Control Manager interface.",
    },
    "4b324fc8-1670-01d3-1278-5a47bf6ee188": {
        "pipe": r"\pipe\srvsvc",
        "description": "Server service interface.",
    },
}

DEFAULT_PIPES = (
    "epmapper",
    "browser",
    "eventlog",
    "lsarpc",
    "samr",
    "svcctl",
    "spoolss",
    "netlogon",
    "atsvc",
    "wkssvc",
    "ntsvcs",
    "winreg",
    "srvsvc",
)

_AUTH_REJECTION_STATUSES = frozenset(
    {
        STATUS_LOGON_FAILURE,
        STATUS_NO_SUCH_USER,
        STATUS_WRONG_PASSWORD,
        STATUS_WRONG_PASSWORD_CORE,
        STATUS_ACCOUNT_RESTRICTION,
        STATUS_INVALID_LOGON_HOURS,
        STATUS_INVALID_WORKSTATION,
        STATUS_PASSWORD_EXPIRED,
        STATUS_ACCOUNT_DISABLED,
        STATUS_ACCOUNT_EXPIRED,
        STATUS_PASSWORD_MUST_CHANGE,
        STATUS_ACCOUNT_LOCKED_OUT,
        STATUS_LOGON_TYPE_NOT_GRANTED,
    }
)

# Impacket 0.12/0.13 constructs RPC Proxy HTTPConnection objects without
# forwarding DCERPCTransport.connect_timeout.  The standard-library clients do
# honor socket's process default while opening their sockets, so serialize that
# short setup window and restore the previous default immediately afterwards.
_HTTP_PROXY_CONNECT_LOCK = threading.Lock()


class _PrintMixin:
    """Route ported terminal output into the active BaseMain module buffer."""

    def bind_ctx(self, ctx):
        self._ctx = ctx
        self.ptjsonlib = ctx.ptjsonlib
        return self

    def ptprint(self, string="", out=Out.TEXT, title=False, end="\n", json=False):
        if json:
            if self.use_json:
                sys.stdout.write(str(string) + (end if end is not None else "\n"))
                sys.stdout.flush()
            return
        if self.use_json:
            return
        category = Out.TITLE.value if title else (out.value if hasattr(out, "value") else str(out))
        context = getattr(self, "_ctx", None)
        if context is not None:
            context.out(
                str(string),
                category,
                colortext=title or category == Out.INFO.value,
                indent=4,
            )

    def ptdebug(self, string="") -> None:
        context = getattr(self, "_ctx", None)
        if context is not None:
            context.debug(str(string), indent=4)


class MsrpcEngine(_PrintMixin):
    def __init__(self, args, ptjsonlib):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.use_json = bool(getattr(args, "json", False))
        self.results = MSRPCResult()

    @property
    def rpc_port(self) -> int:
        return int(getattr(self.args, "rpc_port", None) or getattr(self.args, "port", 135) or 135)

    @property
    def smb_port(self) -> int:
        return int(getattr(self.args, "smb_port", None) or 445)

    @property
    def http_port(self) -> int:
        return int(getattr(self.args, "http_port", None) or 443)

    @property
    def connect_timeout(self) -> float:
        return float(getattr(self.args, "timeout_seconds", 5.0) or 5.0)

    def record_module_error(self, code: str, error: Exception | str) -> None:
        if isinstance(error, Exception):
            message = f"{type(error).__name__}: {error}"
        else:
            message = str(error)
        self.results.module_errors.setdefault(code, message)
        self.ptdebug(f"{code}: {message}")

    def run(self) -> None:
        """Compatibility dispatcher for callers of the former flat module."""
        command = getattr(self.args, "command", None)
        dispatch = {
            "enumerate-epm": ("EpmapEndpoints", self.enumerate_epm),
            "enumerate-mgmt": ("MgmtEndpoints", self.enumerate_mgmt),
            "enumerate-pipes": ("Pipes", self.enumerate_pipes),
            "anon-smb": ("Anonymous", self.Anonymous_smb),
            "brute-pipe": ("PipesCreds", self.pipe_dictionary_attack),
            "brute-smb": ("SMB_Brute", self.smb_brute),
            "brute-tcp": ("TCP_Brute", self.tcp_brute),
            "brute-http": ("HTTP_Brute", self.http_brute),
        }
        if command not in dispatch:
            raise argparse.ArgumentError(None, "Unknown legacy MSRPC command")
        field_name, probe = dispatch[command]
        setattr(self.results, field_name, probe())

    def drawLine(self):
        self.ptprint("-" * 75)

    def drawDoubleLine(self):
        self.ptprint("=" * 75)

    def write_to_file(self, message_or_messages: str | list[str]) -> None:
        try:
            with open(self.args.output, "a", encoding="utf-8", newline="\n") as stream:
                messages = [message_or_messages] if isinstance(message_or_messages, str) else message_or_messages
                for message in messages:
                    stream.write(str(message) + "\n")
        except FileNotFoundError as exc:
            raise argparse.ArgumentError(None, f"File not found: '{self.args.output}'") from exc
        except PermissionError as exc:
            raise argparse.ArgumentError(
                None, f"Cannot write file (permission denied): '{self.args.output}'"
            ) from exc
        except OSError as exc:
            raise argparse.ArgumentError(None, f"Cannot write file '{self.args.output}': {exc}") from exc

    def _credential_sources(self) -> tuple[list[str], list[str]]:
        usernames = text_or_file(
            getattr(self.args, "username", None), getattr(self.args, "username_file", None)
        )
        passwords = text_or_file(
            getattr(self.args, "password", None), getattr(self.args, "password_file", None)
        )
        return usernames, passwords

    def _iter_credentials(
        self,
        usernames: list[str] | None = None,
        passwords: list[str] | None = None,
    ):
        if usernames is None or passwords is None:
            usernames, passwords = self._credential_sources()
        for username, password in product(usernames, passwords):
            yield Credential(username, password)

    def _generate_credentials(self) -> list[Credential]:
        """Compatibility helper; active tests consume the lazy iterator instead."""
        return list(self._iter_credentials())

    @staticmethod
    def _disconnect(dce) -> None:
        if dce is None:
            return
        try:
            dce.disconnect()
        except Exception:
            # Cleanup is best effort here; the originating probe error remains authoritative.
            pass

    @staticmethod
    def _close_smb(smb) -> None:
        if smb is None:
            return
        try:
            smb.logoff()
        except Exception:
            pass
        close = getattr(smb, "close", None)
        if callable(close):
            try:
                close()
            except Exception:
                pass

    @staticmethod
    def _provider_name(value) -> str:
        if value is None:
            return "N/A"
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value)

    def enumerate_epm(self) -> dict:
        endpoints: dict[str, dict] = {}
        dce = None
        try:
            binding = f"ncacn_ip_tcp:{self.args.ip}[{self.rpc_port}]"
            rpc_transport = transport.DCERPCTransportFactory(binding)
            rpc_transport.set_connect_timeout(self.connect_timeout)
            dce = rpc_transport.get_dce_rpc()
            dce.connect()
            entries = epm.hept_lookup(None, dce=dce)

            for entry in entries:
                floors = entry["tower"]["Floors"]
                endpoint = str(floors[0])
                item = endpoints.setdefault(
                    endpoint,
                    {"Bindings": [], "EXE": "N/A", "annotation": "", "Protocol": "N/A"},
                )
                endpoint_tuple = uuid.string_to_uuidtup(endpoint)
                binary_key = uuid.uuidtup_to_bin(endpoint_tuple)[:18]
                item["EXE"] = self._provider_name(epm.KNOWN_UUIDS.get(binary_key))
                annotation = entry.get("annotation", b"")
                if isinstance(annotation, bytes):
                    annotation = annotation.rstrip(b"\x00").decode("utf-8", errors="replace")
                item["annotation"] = str(annotation).rstrip("\x00")
                item["Protocol"] = self._provider_name(
                    epm.KNOWN_PROTOCOLS.get(endpoint[:36])
                )
                string_binding = str(epm.PrintStringBinding(floors))
                if string_binding not in item["Bindings"]:
                    item["Bindings"].append(string_binding)

            for endpoint, item in endpoints.items():
                self.ptprint(f"Protocol: {item['Protocol']}")
                self.ptprint(f"Provider: {item['EXE']}")
                self.ptprint(f"UUID: {endpoint} {item['annotation']}".rstrip())
                self.ptprint("Bindings:")
                for string_binding in item["Bindings"]:
                    self.ptprint(f"  {string_binding}")
            self.ptprint(f"Total endpoints found: {len(endpoints)}", out=Out.INFO)

            if getattr(self.args, "output", None):
                lines: list[str] = []
                for endpoint, item in endpoints.items():
                    lines.extend(
                        [
                            f"Protocol: {item['Protocol']}",
                            f"Provider: {item['EXE']}",
                            f"UUID: {endpoint} {item['annotation']}".rstrip(),
                            "Bindings:",
                            *(f"  {value}" for value in item["Bindings"]),
                            "",
                        ]
                    )
                lines.append(f"Total endpoints found: {len(endpoints)}")
                self.write_to_file(lines)
            return endpoints
        except Exception as exc:
            self.record_module_error("ENUMEPM", exc)
            self.ptprint(f"Endpoint Mapper enumeration failed: {exc}", out=Out.ERROR)
            return endpoints
        finally:
            self._disconnect(dce)

    def enumerate_mgmt(self) -> list[str]:
        dangerous: list[str] = []
        dce = None
        try:
            binding = f"ncacn_ip_tcp:{self.args.ip}[{self.rpc_port}]"
            rpc_transport = transport.DCERPCTransportFactory(binding)
            rpc_transport.set_connect_timeout(self.connect_timeout)
            dce = rpc_transport.get_dce_rpc()
            dce.connect()
            dce.bind(mgmt.MSRPC_UUID_MGMT)
            response = mgmt.hinq_if_ids(dce)
            vector = response["if_id_vector"]
            interfaces = {
                uuid.bin_to_uuidtup(vector["if_id"][index]["Data"].getData())
                for index in range(vector["count"])
            }
            interfaces.add(("AFA8BD80-7D8A-11C9-BEF4-08002B102989", "1.0"))

            for interface_uuid, version in sorted(interfaces):
                canonical = interface_uuid.lower()
                binary_key = uuid.uuidtup_to_bin((interface_uuid, version))[:18]
                provider = self._provider_name(epm.KNOWN_UUIDS.get(binary_key))
                protocol = self._provider_name(epm.KNOWN_PROTOCOLS.get(canonical))
                self.ptprint(f"Protocol: {protocol}")
                self.ptprint(f"Provider: {provider}")
                self.ptprint(f"UUID: {interface_uuid} v{version}")
                details = KNOWN_INTERFACE_UUIDS.get(canonical)
                if details is not None:
                    dangerous.append(canonical)
                    self.ptprint(f"Named Pipe: {details['pipe']}")
                    self.ptprint(f"Description: {details['description']}")

            self.ptprint(f"Interfaces found: {len(interfaces)}", out=Out.INFO)
            if getattr(self.args, "output", None):
                self.write_to_file(dangerous)
            return dangerous
        except Exception as exc:
            self.record_module_error("ENUMMGMT", exc)
            self.ptprint(f"RPC management enumeration failed: {exc}", out=Out.ERROR)
            return []
        finally:
            self._disconnect(dce)

    def _pipe_attempt(
        self,
        pipe: str,
        credential: Credential,
        *,
        require_identity: bool = False,
        strict_session_errors: bool = False,
    ) -> _AttemptResult:
        dce = None
        smb = None
        try:
            smb = SMBConnection(
                self.args.ip,
                self.args.ip,
                sess_port=self.smb_port,
                timeout=self.connect_timeout,
            )
            smb.login(
                credential.username or "",
                credential.password or "",
                getattr(self.args, "domain", "") or "",
            )
            if require_identity and smb.isGuestSession():
                return _AttemptResult(credential, rejected=True)

            binding = f"ncacn_np:{self.args.ip}[\\pipe\\{pipe}]"
            rpc_transport = transport.DCERPCTransportFactory(binding)
            rpc_transport.set_dport(self.smb_port)
            rpc_transport.set_connect_timeout(self.connect_timeout)
            rpc_transport.setRemoteHost(self.args.ip)
            rpc_transport.set_smb_connection(smb)
            dce = rpc_transport.get_dce_rpc()
            dce.connect()
            return _AttemptResult(credential, accepted=True)
        except SessionError as exc:
            if exc.getErrorCode() in _AUTH_REJECTION_STATUSES:
                return _AttemptResult(credential, rejected=True)
            if not strict_session_errors:
                return _AttemptResult(credential, rejected=True)
            return _AttemptResult(credential, error=exc)
        except Exception as exc:
            return _AttemptResult(credential, error=exc)
        finally:
            self._disconnect(dce)
            self._close_smb(smb)

    def try_authenticated_pipe_bind(self, pipe, username, password, domain=""):
        previous_domain = getattr(self.args, "domain", "")
        self.args.domain = domain
        try:
            outcome = self._pipe_attempt(pipe, Credential(username, password))
        finally:
            self.args.domain = previous_domain
        if outcome.error is not None:
            raise outcome.error
        return outcome.accepted

    def enumerate_pipes(self) -> list[str]:
        pipes = getattr(self.args, "pipes", None) or list(DEFAULT_PIPES)
        credential = Credential(
            getattr(self.args, "username", None) or "",
            getattr(self.args, "password", None) or "",
        )
        found: list[str] = []
        connection_errors: list[Exception] = []
        for pipe in pipes:
            try:
                if self.try_authenticated_pipe_bind(
                    pipe,
                    credential.username,
                    credential.password,
                    getattr(self.args, "domain", "") or "",
                ):
                    found.append(pipe)
            except Exception as exc:
                connection_errors.append(exc)
                self.ptprint(f"Could not test named pipe '{pipe}': {exc}", out=Out.WARNING)
        if connection_errors and not found:
            self.record_module_error("ENUMPIPES", connection_errors[0])
        self.ptprint(f"Reachable named pipes: {len(found)}", out=Out.INFO)
        for pipe in found:
            self.ptprint(pipe)
        if getattr(self.args, "output", None):
            self.write_to_file(found)
        return found

    def _run_credential_attempts(self, code: str, attempt) -> list[Credential]:
        usernames, passwords = self._credential_sources()
        total = len(usernames) * len(passwords)
        if total == 0:
            raise argparse.ArgumentError(None, f"{code} has no credentials to test")

        max_attempts = int(getattr(self.args, "max_attempts", 1000) or 1000)
        if total > max_attempts:
            raise argparse.ArgumentError(
                None,
                f"{code} would perform {total} credential attempts, exceeding "
                f"--max-attempts {max_attempts}",
            )

        workers = min(int(getattr(self.args, "threads", 10) or 10), total)
        pending_limit = max(1, workers * 2)
        credentials = enumerate(self._iter_credentials(usernames, passwords))
        accepted: list[tuple[int, Credential]] = []
        error_count = 0
        first_error: tuple[int, Exception] | None = None

        def resolve(future, index: int, credential: Credential) -> None:
            nonlocal error_count, first_error
            try:
                outcome = future.result()
            except Exception as exc:
                outcome = _AttemptResult(credential, error=exc)
            if not isinstance(outcome, _AttemptResult):
                outcome = _AttemptResult(
                    credential,
                    error=TypeError("credential attempt returned an invalid result"),
                )
            if outcome.accepted:
                accepted.append((index, outcome.credential))
            if outcome.error is not None:
                error_count += 1
                if first_error is None or index < first_error[0]:
                    first_error = (index, outcome.error)

        with ThreadPoolExecutor(max_workers=workers) as executor:
            pending = {}

            def submit_next() -> bool:
                try:
                    index, credential = next(credentials)
                except StopIteration:
                    return False
                pending[executor.submit(attempt, credential)] = (index, credential)
                return True

            while len(pending) < pending_limit and submit_next():
                pass
            while pending:
                completed, _ = wait(pending, return_when=FIRST_COMPLETED)
                for future in completed:
                    index, credential = pending.pop(future)
                    resolve(future, index, credential)
                while len(pending) < pending_limit and submit_next():
                    pass

        found = [credential for _, credential in sorted(accepted)]
        if first_error is not None:
            self.record_module_error(code, first_error[1])
            self.ptprint(
                f"{error_count} credential attempt(s) failed before an authentication verdict",
                out=Out.WARNING,
            )
        self.ptprint(f"Valid credentials found: {len(found)}", out=Out.INFO)
        for credential in found:
            self.ptprint(f"{credential.username}:{credential.password}", out=Out.OK)
        if getattr(self.args, "output", None) and found:
            self.write_to_file(
                [f"{credential.username}:{credential.password}" for credential in found]
            )
        return found

    def pipe_dictionary_attack(self) -> list[Credential]:
        pipe = getattr(self.args, "pipe", None)
        if not pipe:
            raise argparse.ArgumentError(None, "BRUTEPIPE requires --pipe")
        return self._run_credential_attempts(
            "BRUTEPIPE",
            lambda credential: self._pipe_attempt(
                pipe,
                credential,
                require_identity=True,
                strict_session_errors=True,
            ),
        )

    def Anonymous_smb(self) -> list[str]:
        smb = None
        logged_in = False
        try:
            smb = SMBConnection(
                self.args.ip,
                self.args.ip,
                sess_port=self.smb_port,
                timeout=self.connect_timeout,
            )
            try:
                smb.login("", "")
                logged_in = True
            except SessionError:
                self.ptprint("Anonymous SMB login is denied", out=Out.NOTVULN)
                return []

            # Verify the exact IPC$ access represented by the second legacy flag.
            try:
                smb.connectTree("IPC$")
            except SessionError:
                self.ptprint(
                    "Anonymous SMB login is allowed, but IPC$ access is denied",
                    out=Out.VULN,
                )
                return ["True", "False"]

            self.ptprint("Anonymous SMB login and IPC$ access are allowed", out=Out.VULN)
            try:
                shares = smb.listShares()
            except SessionError as exc:
                shares = []
                self.ptprint(
                    f"Anonymous share enumeration is denied: {exc}",
                    out=Out.WARNING,
                )
            for share in shares:
                try:
                    name = share["shi1_netname"]
                except (KeyError, TypeError):
                    continue
                self.ptprint(f"Share: {str(name).rstrip(chr(0))}")
            return ["True", "True"]
        finally:
            if smb is not None and logged_in:
                self._close_smb(smb)
            elif smb is not None:
                # Failed logins can still leave a transport object that needs closing.
                close = getattr(smb, "close", None)
                if callable(close):
                    try:
                        close()
                    except Exception:
                        pass

    def _smb_attempt(self, credential: Credential) -> _AttemptResult:
        smb = None
        logged_in = False
        try:
            smb = SMBConnection(
                self.args.ip,
                self.args.ip,
                sess_port=self.smb_port,
                timeout=self.connect_timeout,
            )
            smb.login(
                credential.username or "",
                credential.password or "",
                getattr(self.args, "domain", "") or "",
            )
            logged_in = True
            if smb.isGuestSession():
                return _AttemptResult(credential, rejected=True)
            return _AttemptResult(credential, accepted=True)
        except SessionError as exc:
            if exc.getErrorCode() in _AUTH_REJECTION_STATUSES:
                return _AttemptResult(credential, rejected=True)
            return _AttemptResult(credential, error=exc)
        except Exception as exc:
            return _AttemptResult(credential, error=exc)
        finally:
            if smb is not None and logged_in:
                self._close_smb(smb)
            elif smb is not None:
                close = getattr(smb, "close", None)
                if callable(close):
                    try:
                        close()
                    except Exception:
                        pass

    def smb_brute(self) -> list[Credential]:
        return self._run_credential_attempts("BRUTESMB", self._smb_attempt)

    @staticmethod
    def _interface_uuid_binary(interface: str) -> bytes:
        raw = str(interface).strip()
        version = "1.0"
        uuid_text = raw
        if ":" in raw:
            uuid_text, version = raw.rsplit(":", 1)
        try:
            binary = uuid.uuidtup_to_bin((uuid_text, version))
        except Exception as exc:
            raise argparse.ArgumentError(None, f"Invalid RPC interface UUID '{interface}'") from exc
        if binary is None or len(binary) != 20:
            raise argparse.ArgumentError(None, f"Invalid RPC interface UUID '{interface}'")
        return binary

    def _tcp_attempt(
        self,
        host: str,
        port: int,
        credential: Credential,
        interface: str,
        domain: str,
    ) -> _AttemptResult:
        interface_binary = self._interface_uuid_binary(interface)
        dce = None
        try:
            rpc_transport = transport.DCERPCTransportFactory(f"ncacn_ip_tcp:{host}[{port}]")
            rpc_transport.set_connect_timeout(self.connect_timeout)
            rpc_transport.set_credentials(
                credential.username or "", credential.password or "", domain or ""
            )
            dce = rpc_transport.get_dce_rpc()
            dce.set_credentials(
                credential.username or "", credential.password or "", domain or ""
            )
            dce.set_auth_type(RPC_C_AUTHN_WINNT)
            dce.connect()
            dce.bind(interface_binary)
            return _AttemptResult(credential, accepted=True)
        except SessionError:
            return _AttemptResult(credential, rejected=True)
        except Exception as exc:
            error_code = getattr(exc, "error_code", None)
            if error_code == 5:
                return _AttemptResult(credential, rejected=True)
            return _AttemptResult(credential, error=exc)
        finally:
            self._disconnect(dce)

    def try_authenticated_bind(self, host, port, username, password, uuid, domain=""):
        outcome = self._tcp_attempt(
            host, int(port), Credential(username, password), uuid, domain
        )
        return outcome.accepted

    def tcp_brute(self) -> list[Credential]:
        interface = getattr(self.args, "uuid", None)
        if not interface:
            raise argparse.ArgumentError(None, "BRUTETCP requires --uuid")
        return self._run_credential_attempts(
            "BRUTETCP",
            lambda credential: self._tcp_attempt(
                self.args.ip,
                self.rpc_port,
                credential,
                interface,
                getattr(self.args, "domain", "") or "",
            ),
        )

    def _http_attempt(self, credential: Credential) -> _AttemptResult:
        dce = None
        try:
            proxy_host = getattr(self.args, "host", None) or self.args.ip
            rpc_transport = transport.DCERPCTransportFactory(
                f"ncacn_http:[593,RpcProxy={proxy_host}:{self.http_port}]"
            )
            rpc_transport.set_connect_timeout(self.connect_timeout)
            rpc_transport.set_credentials(
                credential.username or "",
                credential.password or "",
                getattr(self.args, "domain", "") or "",
            )
            rpc_transport.set_auth_type(AUTH_NTLM)
            dce = rpc_transport.get_dce_rpc()
            dce.set_credentials(
                credential.username or "",
                credential.password or "",
                getattr(self.args, "domain", "") or "",
            )
            dce.set_auth_type(RPC_C_AUTHN_WINNT)
            with _HTTP_PROXY_CONNECT_LOCK:
                previous_timeout = socket.getdefaulttimeout()
                socket.setdefaulttimeout(self.connect_timeout)
                try:
                    dce.connect()
                finally:
                    socket.setdefaulttimeout(previous_timeout)
            dce.bind(MSRPC_UUID_PORTMAP)
            return _AttemptResult(credential, accepted=True)
        except SessionError:
            return _AttemptResult(credential, rejected=True)
        except RPCProxyClientException as exc:
            if "401 Unauthorized" in str(exc):
                return _AttemptResult(credential, rejected=True)
            return _AttemptResult(credential, error=exc)
        except Exception as exc:
            error_code = getattr(exc, "error_code", None)
            if error_code == 5:
                return _AttemptResult(credential, rejected=True)
            return _AttemptResult(credential, error=exc)
        finally:
            self._disconnect(dce)

    def http_brute(self) -> list[Credential]:
        return self._run_credential_attempts("BRUTEHTTP", self._http_attempt)

    @staticmethod
    def _credentials_to_string(credentials: list[Credential] | None) -> str | None:
        if not credentials:
            return None
        return ", ".join(
            f"{credential.username or 'None'}:{credential.password or 'None'}"
            for credential in credentials
        )

    def output(self) -> None:
        properties = {
            "software_type": None,
            "name": "msrpc",
            "version": None,
            "vendor": None,
            "description": None,
            "epmapEndpoints": self.results.EpmapEndpoints,
            "mgmtEndpoints": self.results.MgmtEndpoints,
            "pipes": self.results.Pipes,
            "anonymous": (
                ",".join(self.results.Anonymous) if self.results.Anonymous else None
            ),
            "pipesCreds": self._credentials_to_string(self.results.PipesCreds),
            "smbBrute": self._credentials_to_string(self.results.SMB_Brute),
            "tcpBrute": self._credentials_to_string(self.results.TCP_Brute),
            "httpBrute": self._credentials_to_string(self.results.HTTP_Brute),
        }
        if self.results.module_errors:
            properties["moduleErrors"] = [
                {"test": code, "error": error}
                for code, error in self.results.module_errors.items()
            ]

        deferred_vulnerabilities: list[dict[str, str]] = []
        if self.results.Anonymous:
            deferred_vulnerabilities.append(
                {
                    "vuln_code": VULNS.NullSession.value,
                    "vuln_request": "Testing anonymous SMB access and IPC$ share.",
                    "vuln_response": ",".join(self.results.Anonymous),
                }
            )
        credential_findings = (
            (
                self.results.PipesCreds,
                VULNS.WeakCreds_pipes,
                "Bruteforcing credentials for specific pipes",
            ),
            (
                self.results.SMB_Brute,
                VULNS.WeakCreds_SMB,
                "Bruteforcing SMB credentials",
            ),
            (
                self.results.TCP_Brute,
                VULNS.WeakCreds_TCP,
                "Bruteforcing RPC credentials for specific UUID",
            ),
            (
                self.results.HTTP_Brute,
                VULNS.WeakCreds_HTTP,
                "Bruteforcing HTTP credentials",
            ),
        )
        for credentials, vulnerability, request in credential_findings:
            response = self._credentials_to_string(credentials)
            if response:
                deferred_vulnerabilities.append(
                    {
                        "vuln_code": vulnerability.value,
                        "vuln_request": request,
                        "vuln_response": response,
                    }
                )

        node = self.ptjsonlib.create_node_object("software", None, None, properties)
        self.ptjsonlib.add_node(node)
        for vulnerability in deferred_vulnerabilities:
            self.ptjsonlib.add_vulnerability(node_key=node["key"], **vulnerability)

        if self.results.module_errors:
            failed = ", ".join(self.results.module_errors)
            self.ptjsonlib.set_status("error", f"MSRPC module failure(s): {failed}")
        else:
            self.ptjsonlib.set_status("finished", "")
        if self.use_json:
            print(self.ptjsonlib.get_result_json())


__all__ = [
    "Credential",
    "KNOWN_INTERFACE_UUIDS",
    "MSRPCResult",
    "MsrpcEngine",
    "Out",
    "VULNS",
]
