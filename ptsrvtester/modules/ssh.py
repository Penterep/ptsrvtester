import argparse, ipaddress, json, paramiko, paramiko.ssh_exception, socket, sys, threading
from dataclasses import dataclass
from enum import Enum
from io import StringIO
from typing import NamedTuple

from ptlibs.ptjsonlib import PtJsonLib

from ssh_audit import ssh_audit

from ._base import BaseModule, BaseArgs, Out
from ptlibs.ptprinthelper import get_colored_text
from .utils.helpers import (
    Target,
    Creds,
    ArgsWithBruteforce,
    check_if_brute,
    filepaths,
    text_or_file,
    threaded_bruteforce,
    valid_target,
    vendor_from_cpe,
    add_bruteforce_args,
)
from .utils.service_identification import identify_service


def valid_target_ssh(target: str) -> Target:
    """Argparse helper: IP or hostname with optional port (like SMTP)."""
    return valid_target(target, domain_allowed=True)


# region data classes


class TestFailedError(Exception):
    """Custom exception for run-all mode: test failed but continue with next test."""
    pass


class PrivKeyDetails(NamedTuple):
    keypath: str
    passphrase: str | None


@dataclass(frozen=True)
class SSHCreds(Creds):
    privkey: PrivKeyDetails | None


class BruteResult(NamedTuple):
    creds: set[SSHCreds]
    errors: bool


class BadPubkeyResult(NamedTuple):
    bad: bool
    path: str


class CVE(NamedTuple):
    name: str
    description: str
    severity: float


class CryptoFinding(NamedTuple):
    level: str
    action: str
    category: str
    name: str
    notes: str


class SSHAuditResult(NamedTuple):
    err: str | int | None  # sys._ExitCode
    cryptofindings: list[CryptoFinding]
    cves: list[CVE]


class InfoResult(NamedTuple):
    banner: str | None
    host_key: str | None
    auth_methods: list[str] | None


@dataclass
class SSHResults:
    info: InfoResult | None = None
    info_error: str | None = None  # When run-all info test fails
    banner_requested: bool = False
    host_key_requested: bool = False
    ssh_audit: SSHAuditResult | None = None
    ssh_audit_error: str | None = None  # When run-all ssh-audit test fails (exception)
    bad_pubkey: BadPubkeyResult | None = None
    bad_authkeys: list[str] | None = None
    brute: BruteResult | None = None


class VULNS(Enum):
    CVE = "PTV-GENERAL-VULNERABLEVERSION"
    InsecureCrypto = "PTV-GENERAL-INSECURECRYPTO"
    BadHostKey = "PTV-SSH-BADHOSTKEY"
    BadAuthKeys = "PTV-SSH-BADAUTHKEYS"
    WeakCreds = "PTV-GENERAL-WEAKCREDENTIALS"


# endregion


# region arguments


class SSHArgs(ArgsWithBruteforce):
    target: Target
    info: bool
    banner: bool
    auth_methods: bool
    ssh_audit: bool
    bad_pubkeys: str | None
    bad_authkeys: str | None
    privkeys: str | None

    @staticmethod
    def get_help():
        return [
            {"description": ["SSH Testing Module"]},
            {"usage": ["ptsrvtester ssh <options> <target>"]},
            {"usage_example": [
                "ptsrvtester ssh -ia --bad-pubkeys ./hostkeys/ 127.0.0.1",
                "ptsrvtester ssh -u admin -P passwords.txt 127.0.0.1:22",
                "ptsrvtester ssh --ssh-audit 127.0.0.1"
            ]},
            {"options": [
                ["-i", "--info", "", "Get service banner, host key and auth methods"],
                ["-b", "--banner", "", "Grab banner + Service Identification (product, version, CPE)"],
                ["-a", "--auth-methods", "", "Get supported auth methods (warns if keyboard-interactive may affect password bruteforce)"],
                ["-H", "--bad-pubkeys", "", "Check for static/known host keys"],
                ["-A", "--bad-authkeys", "", "Check for static user SSH keys"],
                ["", "--ssh-audit", "", "Run ssh-audit for CVEs and config"],
                ["", "", "", ""],
                ["-u", "--user", "<username>", "Single username for bruteforce"],
                ["-U", "--users", "<wordlist>", "File with usernames"],
                ["-p", "--password", "<password>", "Single password for bruteforce"],
                ["-P", "--passwords", "<wordlist>", "File with passwords"],
                ["", "--privkeys", "<directory>", "Directory with private keys"],
                ["", "", "", ""],
                ["-h", "--help", "", "Show this help message and exit"],
                ["-vv", "--verbose", "", "Enable verbose mode"],
            ]}
        ]

    def add_subparser(self, name: str, subparsers) -> None:
        examples = """example usage:
  ptsrvtester ssh -h
  ptsrvtester ssh -ia --bad-pubkeys ./hostkeys/ 127.0.0.1
  ptsrvtester -j ssh -u admin -P passwords.txt --brute-threads 20 127.0.0.1:22
  ptsrvtester ssh --ssh-audit 127.0.0.1"""

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
            type=valid_target_ssh,
            help="IP[:PORT] or HOST[:PORT] (e.g. 127.0.0.1 or ssh.example.com:22)",
        )

        recon = parser.add_argument_group("RECON")
        recon.add_argument(
            "-i",
            "--info",
            action="store_true",
            help="get service banner and host key (recommended for connectivity testing)",
        )
        recon.add_argument("-b", "--banner", action="store_true", help="grab banner + Service Identification (product, version, CPE)")
        recon.add_argument(
            "-a",
            "--auth-methods",
            action="store_true",
            help="get the supported authentication methods",
        )
        recon.add_argument(
            "-H",
            "--bad-pubkeys",
            type=str,
            help="check if server's host key is static and known: directory containing <name>.pub public SSH keys (e.g. https://github.com/rapid7/ssh-badkeys/tree/master/host)",
        )
        recon.add_argument(
            "--ssh-audit",
            action="store_true",
            help="utilize the ssh-audit tool to identify CVEs and insecure SSH configuration",
        )

        add_bruteforce_args(parser)

        # Add privatekey arguments and change description accordingly
        bruteforce = next(g for g in parser._action_groups if "BRUTEFORCE" in g.title)
        bruteforce.description = "user/users-file + passw/passw-file/privkeys"
        bruteforce.add_argument(
            "-A",
            "--bad-authkeys",
            type=str,
            help="check static user SSH keys: directory containing <name>.key private SSH keys with <name>.yml YAML descriptions (e.g. https://github.com/rapid7/ssh-badkeys/tree/master/authorized)",
        )

        brutepass = next(g for g in bruteforce._mutually_exclusive_groups if g.title == "brutepass")
        brutepass.add_argument(
            "--privkeys",
            type=str,
            help="pubkey authentication: directory containing <name>.key private SSH keys. If the keys are password protected, include also <name>.pass files in the directory",
        )


# endregion


# region main module code


class SSH(BaseModule):
    @staticmethod
    def module_args():
        return SSHArgs()

    def __init__(self, args: BaseArgs, ptjsonlib: PtJsonLib):
        """Prepare arguments"""
        if not isinstance(args, SSHArgs):
            raise argparse.ArgumentError(
                None, f'module "{args.module}" received wrong arguments namespace'
            )

        if args.bad_pubkeys and not args.info:
            raise argparse.ArgumentError(None, "--bad-pubkeys requires also --info")

        # Default port number
        if args.target.port == 0:
            args.target.port = 22

        self.do_brute = check_if_brute(args) or bool(
            (args.user or args.users) and getattr(args, "privkeys", None)
        )
        self.use_json = getattr(args, "json", False)

        self.args = args
        self.ptjsonlib = ptjsonlib
        self.results: SSHResults
        self._output_lock = threading.Lock()
        self._streamed_banner = False
        self._streamed_auth_methods = False
        self._streamed_kex = False
        self._streamed_ssh_audit = False
        self._streamed_bad_pubkey = False
        self._streamed_bad_authkeys = False
        self._streamed_brute = False

    def _is_run_all_mode(self) -> bool:
        """True when only target is given (no test switches). Run all tests in sequence."""
        return not (
            self.args.info
            or self.args.banner
            or self.args.auth_methods
            or self.args.ssh_audit
            or self.args.bad_pubkeys
            or self.args.bad_authkeys
            or self.do_brute
        )

    def _fail(self, msg: str) -> None:
        """In run-all mode: raise TestFailedError. Otherwise: end_error + SystemExit."""
        if hasattr(self, 'run_all_mode') and self.run_all_mode:
            raise TestFailedError(msg)
        else:
            self.ptjsonlib.end_error(msg, self.use_json)
            raise SystemExit

    def run(self) -> None:
        """Linear flow: Connect/Info -> Stream Banner -> Stream Auth Methods -> KEX/Audit -> Bad Pubkeys -> Bruteforce."""
        self.results = SSHResults()
        self.run_all_mode = self._is_run_all_mode()

        if self.run_all_mode:
            self._run_all_tests()
            return

        # 1. Info (banner, host_key, auth_methods)
        if self.args.info or self.args.banner:
            do_banner = self.args.banner or self.args.info
            do_host_key = self.args.info or bool(self.args.bad_pubkeys)
            self.results.banner_requested = do_banner
            self.results.host_key_requested = do_host_key
            try:
                info = self.info(get_commands=do_host_key, auth_methods=self.args.auth_methods or self.args.info)
                self.results.info = InfoResult(
                    info.banner if do_banner else None,
                    info.host_key if do_host_key else None,
                    info.auth_methods if (do_host_key and (self.args.auth_methods or self.args.info)) else None,
                )
                self._stream_banner_result()
                self._stream_auth_methods_result()
            except (TestFailedError, SystemExit):
                raise
            except Exception as e:
                self.results.info_error = str(e)

        # 2. ssh-audit (KEX, CVEs, weak algorithms)
        if self.args.ssh_audit:
            try:
                self.results.ssh_audit = self.run_ssh_audit()
                self._stream_ssh_audit_result()
            except Exception as e:
                self.results.ssh_audit_error = str(e)
                self._stream_ssh_audit_result()

        # 3. Bad pubkeys (requires info + host_key)
        if self.args.bad_pubkeys and self.results.info and self.results.info.host_key:
            self.results.bad_pubkey = self.bad_pubkey(
                self.args.bad_pubkeys, self.results.info.host_key
            )
            self._stream_bad_pubkey_result()

        # 4. Bad auth keys
        if self.args.bad_authkeys:
            self.results.bad_authkeys = self.bad_authkeys(self.args.bad_authkeys)
            self._stream_bad_authkeys_result()

        # 5. Bruteforce (silent info when brute-only, to stream banner/auth_methods and keyboard-interactive warning)
        if self.do_brute:
            if not (self.args.info or self.args.banner) and self.results.info is None:
                try:
                    silent = self.info(get_commands=True, auth_methods=True)
                    self.results.info = silent
                    self.results.banner_requested = True
                    self.results.host_key_requested = True
                    self._stream_banner_result()
                    self._stream_auth_methods_result()
                except (TestFailedError, SystemExit):
                    raise
                except Exception:
                    pass
            self.results.brute = self.bruteforce()
            self._stream_brute_result()

    def _run_all_tests(self) -> None:
        """Run all tests in sequence. On failure: print error, continue with next. Stream immediately."""
        # 1. Banner + host key (with auth_methods=True)
        self.results.banner_requested = True
        self.results.host_key_requested = True
        try:
            self.results.info = self.info(get_commands=True, auth_methods=True)
            self._stream_banner_result()
            self._stream_auth_methods_result()
        except TestFailedError as e:
            self.results.info_error = str(e)
            return
        except Exception as e:
            self.results.info_error = str(e)
            return

        # 2. ssh-audit (if available)
        try:
            self.results.ssh_audit = self.run_ssh_audit()
            self._stream_ssh_audit_result()
        except TestFailedError as e:
            self.results.ssh_audit_error = str(e)
            self._stream_ssh_audit_result()
        except Exception as e:
            self.results.ssh_audit_error = str(e)
            self._stream_ssh_audit_result()

    def info(self, get_commands: bool = True, auth_methods: bool = False) -> InfoResult:
        """Grab banner; optionally host key and authentication methods."""
        # Raw banner
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.args.target.ip, self.args.target.port))
            banner = sock.recv(4096).strip().splitlines()[0].decode()
            sock.close()
        except Exception as e:
            msg = (
                f"Failed to grab banner from the server "
                + f"{self.args.target.ip}:{self.args.target.port}: {e}"
            )
            self._fail(msg)

        host_key = None
        am = None
        if get_commands:
            try:
                trans = paramiko.Transport((self.args.target.ip, self.args.target.port))
                trans.start_client()
                hk = trans.get_remote_server_key()
                host_key = hk.get_name() + " " + hk.get_base64()
                if auth_methods:
                    try:
                        trans.auth_none("")
                    except paramiko.BadAuthenticationType as e:
                        am = e.allowed_types
                    except Exception:
                        pass
                trans.close()
            except Exception as e:
                msg = (
                    f"Failed to establish SSH connection with server "
                    + f"{self.args.target.ip}:{self.args.target.port}: {e}"
                )
                self._fail(msg)

        return InfoResult(banner, host_key, am)

    def run_ssh_audit(self) -> SSHAuditResult:

        out = ssh_audit.OutputBuffer()
        aconf = ssh_audit.AuditConf(self.args.target.ip, self.args.target.port)
        aconf.json = True

        try:
            # Let ssh-audit perform the scan
            status = ssh_audit.audit(out, aconf)

            if status == ssh_audit.exitcodes.CONNECTION_ERROR:
                return SSHAuditResult(status, [], [])

            buf = out.get_buffer()
            bufj = json.loads(buf)

            # Parse recommendations from JSON
            findings: list[CryptoFinding] = []
            recommendations: dict[str, dict[str, dict[str, list[dict[str, str]]]]] | None = (
                bufj.get("recommendations", None)
            )
            if recommendations is not None:
                # {"critical": {}, "warning": {}, ...}
                for level, actions in recommendations.items():
                    # "critical": {"del": {}, "add": {}, ...}
                    for action, categories in actions.items():
                        # "del": {"key": [], "enc": [], ...}
                        for category, details in categories.items():
                            # "key": [{"name": "", "notes": ""}, {"name": "", "notes": ""}, ...]
                            for detail in details:
                                # {"name": "", "notes": ""}
                                name = detail["name"]
                                notes = detail["notes"]

                                findings.append(CryptoFinding(level, action, category, name, notes))

            # Parse identified CVEs from JSON
            cves: list[CVE] = []
            cves_: list[dict[str, str]] | None = bufj.get("cves", None)
            if cves_ is not None:
                for cve in cves_:
                    cves.append(CVE(cve["name"], cve["description"], float(cve["cvssv2"])))

            return SSHAuditResult(None, findings, cves)
        except SystemExit as e:
            return SSHAuditResult(e.code, [], [])

    def bad_pubkey(self, pubkeys_path: str, host_key: str) -> BadPubkeyResult:
        """Compare supplied host key with a set of known public keys (bad keys)"""

        pubkey_paths = filepaths(pubkeys_path, ".pub")
        for pubkey_path in pubkey_paths:
            with open(pubkey_path, "r") as f:
                line = f.read().strip()
                # Some keys may contain "user@host" on the end of the line
                pubkey = " ".join(line.split(" ")[:2])

                if pubkey == host_key:
                    return BadPubkeyResult(True, pubkey_path)

        return BadPubkeyResult(False, "")

    def bad_authkeys(self, authkeys_path: str) -> list[str]:

        authkey_paths = filepaths(authkeys_path, ".key")
        valid_authkeys: list[str] = []

        for authkey_path in authkey_paths:
            # Parse known username from YAML file
            yml_path = ".".join(authkey_path.split(".")[:-1]) + ".yml"
            with open(yml_path, "r") as f:
                lines = f.read().splitlines()
                # Username property is :user: delimited with a space
                user_line = next(l for l in lines if ":user:" in l)
                username = user_line.split(" ")[-1]

            # Try login
            with open(authkey_path, "r") as f:
                c = paramiko.SSHClient()
                c.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy)

                valid = False
                try:
                    c.connect(
                        self.args.target.ip,
                        self.args.target.port,
                        look_for_keys=False,
                        banner_timeout=10,
                        username=username,
                        key_filename=authkey_path,
                    )
                    valid = True
                except:
                    pass
                finally:
                    c.close()

                if valid:
                    valid_authkeys.append(authkey_path)

        return valid_authkeys

    def bruteforce(self) -> BruteResult:
        """Perform login bruteforce using username/password or username/privatekey/(passphrase)"""
        users = text_or_file(self.args.user, self.args.users)
        passwords = text_or_file(self.args.password, self.args.passwords)

        # Parse private SSH key files
        privkeys: list[PrivKeyDetails] = []
        if self.args.privkeys:
            keypaths = filepaths(self.args.privkeys, ".key")
            passpaths = filepaths(self.args.privkeys, ".pass")

            for keypath in keypaths:
                ppaths = [p for p in passpaths if p == keypath[:-4] + ".pass"]
                if len(ppaths) > 0:
                    with open(ppaths[0], "r") as f:
                        passphrase = f.read().strip()
                        privkeys.append(PrivKeyDetails(keypath, passphrase))
                else:
                    privkeys.append(PrivKeyDetails(keypath, None))

        # Prioritize SSH keys
        secrets = privkeys if self.args.privkeys is not None else passwords

        if self.args.spray:
            creds = [
                SSHCreds(u, s, None) if isinstance(s, str) else SSHCreds(u, "", s)
                for s in secrets
                for u in users
            ]
        else:
            creds = [
                SSHCreds(u, s, None) if isinstance(s, str) else SSHCreds(u, "", s)
                for u in users
                for s in secrets
            ]

        # Redirect stderr to prevent paramiko from printing unwanted output
        err = StringIO("")
        old_write = sys.stderr.write
        sys.stderr.write = err.write

        if not self.use_json:
            self.ptprint("Login bruteforce", Out.INFO)
        on_success = self._on_brute_success if not self.use_json else None
        found_creds = threaded_bruteforce(
            creds, self._try_login, self.args.threads, on_success=on_success
        )

        sys.stderr.write = old_write
        errors = len(err.getvalue()) > 0
        err.close()

        return BruteResult(found_creds, errors)

    def _try_login(self, creds: SSHCreds) -> SSHCreds | None:
        """Attempt login with username/password or username/privatekey/passphrase.
        Returns creds on success even if server requires password change (interactive)."""
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy)

        if creds.privkey is not None:
            keypath = creds.privkey.keypath
            passphrase = creds.privkey.passphrase
            password = None
        else:
            keypath = None
            passphrase = None
            password = creds.passw

        try:
            ssh.connect(
                self.args.target.ip,
                self.args.target.port,
                look_for_keys=False,
                banner_timeout=10,
                username=creds.user,
                password=password,
                key_filename=keypath,
                passphrase=passphrase,
            )
            return creds
        except paramiko.SSHException as e:
            # Password change required - server accepted creds but enforces change
            if "change" in str(e).lower() and "password" in str(e).lower():
                return creds
            return None
        except Exception:
            return None
        finally:
            try:
                ssh.close()
            except Exception:
                pass

    def _on_brute_success(self, cred: SSHCreds) -> None:
        """Callback for real-time streaming of found credentials (thread-safe)."""
        with self._output_lock:
            if cred.privkey:
                if cred.privkey.passphrase is not None:
                    cred_str = f"user: {cred.user}, keypath: {cred.privkey.keypath}, passphrase: {cred.privkey.passphrase}"
                else:
                    cred_str = f"user: {cred.user}, keypath: {cred.privkey.keypath}"
            else:
                cred_str = f"user: {cred.user}, password: {cred.passw}"
            self.ptprint(f"    {cred_str}", Out.TEXT)

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

    def _stream_auth_methods_result(self) -> None:
        if self.use_json or not (info := self.results.info) or info.auth_methods is None:
            return
        with self._output_lock:
            self.ptprint("Authentication methods", Out.INFO)
            has_kb_interactive = False
            for method in info.auth_methods:
                if method.lower() == "keyboard-interactive":
                    has_kb_interactive = True
                if method.lower() == "password":
                    icon = get_colored_text("[✗]", color="VULN")
                else:
                    icon = get_colored_text("[✓]", color="NOTVULN")
                self.ptprint(f"    {icon} {method}", Out.TEXT)
            if has_kb_interactive:
                icon = get_colored_text("[!]", color="WARNING")
                self.ptprint(
                    f"    {icon} Server supports keyboard-interactive; password bruteforce may fail.",
                    Out.TEXT,
                )
        self._streamed_auth_methods = True

    def _stream_kex_result(self) -> None:
        """Stream KEX/crypto findings from ssh-audit. KEX data comes from ssh_audit."""
        if self.use_json:
            return
        audit = self.results.ssh_audit
        if audit is None or audit.err is not None:
            return
        with self._output_lock:
            if audit.cryptofindings or audit.cves:
                self.ptprint("KEX / Crypto (ssh-audit)", Out.INFO)
                for find in audit.cryptofindings:
                    if find.level.upper() == "CRITICAL":
                        icon = get_colored_text("[✗]", color="VULN")
                    elif find.level.upper() == "WARNING":
                        icon = get_colored_text("[!]", color="WARNING")
                    else:
                        icon = find.level.upper()
                    s = f"{icon} {find.category}/{find.action}: {find.name}"
                    if find.notes:
                        s += f" ({find.notes})"
                    self.ptprint(f"    {s}", Out.TEXT)
                for cve in audit.cves:
                    icon = get_colored_text("[✗]", color="VULN")
                    self.ptprint(f"    {icon} {cve.name} ({cve.severity}): {cve.description}", Out.TEXT)
        self._streamed_kex = True

    def _stream_ssh_audit_result(self) -> None:
        if self.use_json:
            return
        if (err := self.results.ssh_audit_error) is not None:
            with self._output_lock:
                self.ptprint("ssh-audit scan results", Out.INFO)
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} SSH-audit test failed: {err}", Out.TEXT)
            self._streamed_ssh_audit = True
            return
        audit = self.results.ssh_audit
        if audit is None:
            return
        with self._output_lock:
            self.ptprint("ssh-audit scan results", Out.INFO)
            if audit.err is not None:
                self.ptprint(f"    ssh-audit failed with error: {audit.err}", Out.TEXT)
            else:
                self.ptprint(f"    Identified {len(audit.cves)} CVEs", Out.TEXT)
                for cve in audit.cves:
                    self.ptprint(f"        {cve.name} ({cve.severity}): {cve.description}", Out.TEXT)
                self.ptprint(f"    Identified {len(audit.cryptofindings)} insecure SSH configurations", Out.TEXT)
                for find in audit.cryptofindings:
                    if find.level.upper() == "CRITICAL":
                        icon = get_colored_text("[✗]", color="VULN")
                    elif find.level.upper() == "WARNING":
                        icon = get_colored_text("[!]", color="WARNING")
                    else:
                        icon = find.level.upper()
                    s = f"{icon} {find.category}/{find.action}: {find.name}"
                    if find.notes:
                        s += f" ({find.notes})"
                    self.ptprint(f"        {s}", Out.TEXT)
        self._streamed_ssh_audit = True

    def _stream_bad_pubkey_result(self) -> None:
        if self.use_json or (bp := self.results.bad_pubkey) is None:
            return
        with self._output_lock:
            self.ptprint("Known static (bad) host key", Out.INFO)
            if bp.bad:
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} Matched key path: {bp.path}", Out.TEXT)
            else:
                icon = get_colored_text("[✓]", color="NOTVULN")
                self.ptprint(f"    {icon} No match", Out.TEXT)
        self._streamed_bad_pubkey = True

    def _stream_bad_authkeys_result(self) -> None:
        if self.use_json or (keys := self.results.bad_authkeys) is None:
            return
        with self._output_lock:
            self.ptprint("Known static (bad) auth keys", Out.INFO)
            if len(keys) > 0:
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} Matched {len(keys)} key(s)", Out.TEXT)
                for k in keys:
                    self.ptprint(f"        {k}", Out.TEXT)
            else:
                icon = get_colored_text("[✓]", color="NOTVULN")
                self.ptprint(f"    {icon} No match", Out.TEXT)
        self._streamed_bad_authkeys = True

    def _stream_brute_result(self) -> None:
        brute = self.results.brute
        if brute is None:
            return
        if not self.use_json and len(brute.creds) > 0:
            with self._output_lock:
                self.ptprint(f"    Found {len(brute.creds)} valid credentials", Out.INFO)
        self._streamed_brute = True

    # endregion

    # region output

    def output(self) -> None:
        """Formats and outputs module results. Skips streamed sections in text mode; JSON always complete."""
        properties = {
            "software_type": None,
            "name": "ssh",
            "version": None,
            "vendor": None,
            "description": None,
        }
        deferred_vulns = []

        # Connection/info error - use unified error format (status=error, empty nodes)
        if (info_error := self.results.info_error) is not None:
            if self.use_json:
                self.ptjsonlib.end_error(info_error, self.use_json)
            if not self.use_json:
                self.ptprint("Banner", Out.INFO)
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} {info_error}", Out.TEXT)
            properties.update({"infoError": info_error})
            ssh_node = self.ptjsonlib.create_node_object("software", None, None, properties)
            self.ptjsonlib.add_node(ssh_node)
            node_key = ssh_node["key"]
            for v in deferred_vulns:
                self.ptjsonlib.add_vulnerability(node_key=node_key, **v)
            self.ptjsonlib.set_status("finished", "")
            self.ptprint(self.ptjsonlib.get_result_json(), json=True)
            return

        # Banner (skip if streamed; always add to properties for JSON)
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

        # Host key (separate section)
        if self.results.host_key_requested and (info := self.results.info) and info.host_key is not None:
            properties.update({"hostKey": info.host_key})
            if not self.use_json:
                self.ptprint("Host key", Out.INFO)
                self.ptprint(f"    {info.host_key}", Out.TEXT)

        # Auth methods (skip if streamed; always add to properties for JSON)
        if (info := self.results.info) and info.auth_methods is not None:
            properties.update({"authMethods": info.auth_methods})
            if not self.use_json and not self._streamed_auth_methods:
                self.ptprint("Authentication methods", Out.INFO)
                for method in info.auth_methods:
                    if method.lower() == "password":
                        icon = get_colored_text("[✗]", color="VULN")
                    else:
                        icon = get_colored_text("[✓]", color="NOTVULN")
                    self.ptprint(f"    {icon} {method}", Out.TEXT)

        # ssh-audit results (skip if streamed; always add to properties for JSON)
        if (ssh_audit_error := self.results.ssh_audit_error) is not None:
            properties.update({"sshauditError": ssh_audit_error})
            if not self.use_json and not self._streamed_ssh_audit:
                self.ptprint("ssh-audit scan results", Out.INFO)
                icon = get_colored_text("[✗]", color="VULN")
                self.ptprint(f"    {icon} SSH-audit test failed: {ssh_audit_error}", Out.TEXT)
        elif (ssh_audit := self.results.ssh_audit) is not None:
            if ssh_audit.err is not None:
                properties.update({"sshauditStatus": ssh_audit.err})
            else:
                properties.update({"sshauditStatus": "ok"})
                json_lines: list[str] = []
                for cve in ssh_audit.cves:
                    json_lines.append(f"{cve.name} ({cve.severity}): {cve.description}")
                if json_lines:
                    deferred_vulns.append(
                        {
                            "vuln_code": VULNS.CVE.value,
                            "vuln_request": "ssh-audit scan",
                            "vuln_response": "\n".join(json_lines),
                        }
                    )
                json_lines = []
                for find in ssh_audit.cryptofindings:
                    json_lines.append(
                        f"{find.level.upper()} {find.category}/{find.action}: {find.name}"
                        + (f" ({find.notes})" if find.notes else "")
                    )
                if json_lines:
                    deferred_vulns.append(
                        {
                            "vuln_code": VULNS.InsecureCrypto.value,
                            "vuln_request": "ssh-audit scan",
                            "vuln_response": "\n".join(json_lines),
                        }
                    )
            if not self.use_json and not self._streamed_ssh_audit:
                self.ptprint("ssh-audit scan results", Out.INFO)
                if ssh_audit.err is not None:
                    self.ptprint(f"    ssh-audit failed with error: {ssh_audit.err}", Out.TEXT)
                else:
                    self.ptprint(f"    Identified {len(ssh_audit.cves)} CVEs", Out.TEXT)
                    for cve in ssh_audit.cves:
                        self.ptprint(f"        {cve.name} ({cve.severity}): {cve.description}", Out.TEXT)
                    self.ptprint(f"    Identified {len(ssh_audit.cryptofindings)} insecure SSH configurations", Out.TEXT)
                    for find in ssh_audit.cryptofindings:
                        if find.level.upper() == "CRITICAL":
                            icon = get_colored_text("[✗]", color="VULN")
                        elif find.level.upper() == "WARNING":
                            icon = get_colored_text("[!]", color="WARNING")
                        else:
                            icon = find.level.upper()
                        s = f"{icon} {find.category}/{find.action}: {find.name}"
                        if find.notes:
                            s += f" ({find.notes})"
                        self.ptprint(f"        {s}", Out.TEXT)

        # Bad host key (skip if streamed)
        if (badpubkey := self.results.bad_pubkey) is not None:
            if badpubkey.bad:
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.BadHostKey.value,
                        "vuln_request": f"matched key from: {self.args.bad_pubkeys}",
                        "vuln_response": badpubkey.path,
                    }
                )
            if not self.use_json and not self._streamed_bad_pubkey:
                self.ptprint("Known static (bad) host key", Out.INFO)
                if badpubkey.bad:
                    icon = get_colored_text("[✗]", color="VULN")
                    self.ptprint(f"    {icon} Matched key path: {badpubkey.path}", Out.TEXT)
                else:
                    icon = get_colored_text("[✓]", color="NOTVULN")
                    self.ptprint(f"    {icon} No match", Out.TEXT)

        # Bad auth keys (skip if streamed)
        if (badauthkeys := self.results.bad_authkeys) is not None:
            if len(badauthkeys) > 0:
                deferred_vulns.append(
                    {
                        "vuln_code": VULNS.BadAuthKeys.value,
                        "vuln_request": f"matched keys from: {self.args.bad_authkeys}",
                        "vuln_response": "\n".join(badauthkeys),
                    }
                )
            if not self.use_json and not self._streamed_bad_authkeys:
                self.ptprint("Known static (bad) auth keys", Out.INFO)
                if len(badauthkeys) > 0:
                    icon = get_colored_text("[✗]", color="VULN")
                    self.ptprint(f"    {icon} Matched {len(badauthkeys)} key(s)", Out.TEXT)
                    for k in badauthkeys:
                        self.ptprint(f"        {k}", Out.TEXT)
                else:
                    icon = get_colored_text("[✓]", color="NOTVULN")
                    self.ptprint(f"    {icon} No match", Out.TEXT)

        # Login bruteforce (skip if streamed; always add to deferred for JSON)
        if (brute := self.results.brute) is not None:
            if brute.errors:
                properties.update({"bruteStatus": "errors"})
            else:
                properties.update({"bruteStatus": "ok"})

            if not self.use_json and not self._streamed_brute:
                if brute.errors:
                    self.ptprint(
                        "WARNING: there were some errors during the bruteforce process."
                        + " Try reducing the --brute-threads parameter",
                        Out.WARNING,
                    )
                self.ptprint("Login bruteforce", Out.INFO)
                if len(brute.creds) > 0:
                    self.ptprint(f"    {len(brute.creds)} valid credentials", Out.INFO)
                for cred in brute.creds:
                    if privkey := cred.privkey:
                        if privkey.passphrase is not None:
                            cred_str = f"user: {cred.user}, keypath: {privkey.keypath}, passphrase: {privkey.passphrase}"
                        else:
                            cred_str = f"user: {cred.user}, keypath: {privkey.keypath}"
                    else:
                        cred_str = f"user: {cred.user}, password: {cred.passw}"
                    self.ptprint(f"    {cred_str}", Out.TEXT)

            if len(brute.creds) > 0:
                json_lines = []
                for cred in brute.creds:
                    if privkey := cred.privkey:
                        if privkey.passphrase is not None:
                            cred_str = f"user: {cred.user}, keypath: {privkey.keypath}, passphrase: {privkey.passphrase}"
                        else:
                            cred_str = f"user: {cred.user}, keypath: {privkey.keypath}"
                    else:
                        cred_str = f"user: {cred.user}, password: {cred.passw}"
                    json_lines.append(cred_str)

                if self.args.user is not None:
                    user_str = f"username: {self.args.user}"
                else:
                    user_str = f"usernames: {self.args.users}"

                if self.args.password is not None:
                    passw_str = f"password: {self.args.password}"
                elif self.args.privkeys is not None:
                    passw_str = f"private keys: {self.args.privkeys}"
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
        ssh_node = self.ptjsonlib.create_node_object(
            "software",
            None,
            None,
            properties,
        )
        self.ptjsonlib.add_node(ssh_node)
        node_key = ssh_node["key"]
        for v in deferred_vulns:
            self.ptjsonlib.add_vulnerability(node_key=node_key, **v)

        self.ptjsonlib.set_status("finished", "")
        self.ptprint(self.ptjsonlib.get_result_json(), json=True)


# endregion
