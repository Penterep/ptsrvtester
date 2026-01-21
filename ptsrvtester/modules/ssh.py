import argparse, paramiko, paramiko.ssh_exception, socket, sys, json
from dataclasses import dataclass
from enum import Enum
from io import StringIO
from typing import NamedTuple

from ptlibs.ptjsonlib import PtJsonLib
from ptlibs.threads import ptthreads

from ssh_audit import ssh_audit

from ._base import BaseModule, BaseArgs, Out
from .utils.helpers import (
    Target,
    Creds,
    ArgsWithBruteforce,
    check_if_brute,
    filepaths,
    text_or_file,
    valid_target,
    add_bruteforce_args,
)


# region data classes


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
    host_key: str
    auth_methods: list[str] | None


@dataclass
class SSHResults:
    info: InfoResult | None = None
    ssh_audit: SSHAuditResult | None = None
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
                ["-i", "--info", "", "Get service banner and host key"],
                ["-a", "--auth-methods", "", "Get supported authentication methods"],
                ["-H", "--bad-pubkeys", "", "Check for static/known host keys"],
                ["-A", "--bad-authkeys", "", "Check for static user SSH keys"],
                ["", "--ssh-audit", "", "Run ssh-audit for CVEs and config"],
                ["", "", "", ""],
                ["-u", "--user", "", "Single username for bruteforce"],
                ["-U", "--users-file", "", "File with usernames"],
                ["-p", "--passw", "", "Single password for bruteforce"],
                ["-P", "--passw-file", "", "File with passwords"],
                ["", "--privkeys", "", "Directory with private keys"],
                ["", "", "", ""],
                ["-h", "--help", "", "Show this help message and exit"],
            ]}
        ]

    def add_subparser(self, name: str, subparsers) -> None:
        examples = """example usage:
  ptsrvtester ssh -h
  ptsrvtester ssh -ia --bad-pubkeys ./hostkeys/ 127.0.0.1
  ptsrvtester -j ssh -u admin -P passwords.txt --threads 20 127.0.0.1:22
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
            "target", type=valid_target, help="IP[:PORT] (e.g. 127.0.0.1 or 127.0.0.1:22)"
        )

        recon = parser.add_argument_group("RECON")
        recon.add_argument(
            "-i",
            "--info",
            action="store_true",
            help="get service banner and host key (recommended for connectivity testing)",
        )
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

        self.do_brute = check_if_brute(args)

        self.args = args
        self.ptjsonlib = ptjsonlib
        self.results: SSHResults

    def run(self) -> None:
        self.results = SSHResults()

        if self.args.info:
            self.results.info = self.info(self.args.auth_methods)

            # Pubkey check requires info (that retrieves the key)
            if self.args.bad_pubkeys:
                self.results.bad_pubkey = self.bad_pubkey(
                    self.args.bad_pubkeys, self.results.info.host_key
                )

        if self.args.ssh_audit:
            self.results.ssh_audit = self.run_ssh_audit()

        if self.args.bad_authkeys:
            self.results.bad_authkeys = self.bad_authkeys(self.args.bad_authkeys)

        if self.do_brute:
            self.results.brute = self.bruteforce()

    def info(self, auth_methods: bool) -> InfoResult:
        """Grab banner and host key, optionally also query the authentication methods"""
        # Raw banner
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.args.target.ip, self.args.target.port))

            # Decode and record the first received line
            banner = sock.recv(4096).strip().splitlines()[0].decode()
            sock.close()
        except Exception as e:
            self.ptjsonlib.end_error(
                f"Failed to grab banner from the server "
                + f"{self.args.target.ip}:{self.args.target.port}: {e}",
                self.args.json,
            )
            raise SystemExit

        # Host key
        try:
            trans = paramiko.Transport((self.args.target.ip, self.args.target.port))
            trans.start_client()
            host_key = trans.get_remote_server_key()
            host_key = host_key.get_name() + " " + host_key.get_base64()
        except Exception as e:
            self.ptjsonlib.end_error(
                f"Failed to establish SSH connection with server "
                + f"{self.args.target.ip}:{self.args.target.port}: {e}",
                self.args.json,
            )
            raise SystemExit

        # Authentication methods
        am = None
        if auth_methods:
            try:
                trans.auth_none("")
            except paramiko.BadAuthenticationType as e:
                am = e.allowed_types
            except:
                pass

        trans.close()

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
        users = text_or_file(self.args.user, self.args.users_file)
        passwords = text_or_file(self.args.passw, self.args.passw_file)

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

        # Redirect stderr to prevent printing unwanted output
        err = StringIO("")
        old_write = sys.stderr.write
        sys.stderr.write = err.write

        # TODO maybe custom without ptthreads because of missing stop-on-success functionality
        threads = ptthreads.PtThreads(True)
        result = threads.threads(creds, self._try_login, self.args.threads)
        found_creds: set[SSHCreds] = set(result)

        sys.stderr.write = old_write
        errors = len(err.getvalue()) > 0
        err.close()

        found_creds.discard(None)

        return BruteResult(found_creds, errors)

    def _try_login(self, creds: SSHCreds) -> SSHCreds | None:
        """Attempt login with username/password or username/privatekey/passphrase"""
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
            result = creds
        except:
            result = None
        finally:
            ssh.close()
            return result

    # endregion

    # region output

    def output(self) -> None:
        properties: dict[str, None | str | int | list[str]] = self.ptjsonlib.json_object["results"][
            "properties"
        ]

        # Server information
        if info := self.results.info:
            self.ptprint("Server information", title=True)

            self.ptprint(f"Banner:", Out.INFO)
            self.ptprint(f"{info.banner}")
            properties["banner"] = info.banner

            self.ptprint(f"Host key:", Out.INFO)
            self.ptprint(info.host_key)
            properties["hostKey"] = info.host_key

            if info.auth_methods is not None:
                self.ptprint(f"Authentication methods:", Out.INFO)
                self.ptprint(", ".join(info.auth_methods))
                properties["authMethods"] = info.auth_methods

        # ssh-audit results
        if ssh_audit := self.results.ssh_audit:

            if ssh_audit.err is not None:
                self.ptprint(f"ssh-audit scan failed with error: {ssh_audit.err}", title=True)
                properties["sshauditStatus"] = ssh_audit.err
            else:
                self.ptprint(f"ssh-audit scan results", title=True)
                properties["sshauditStatus"] = "ok"

                json_lines: list[str] = []
                self.ptprint(f"Identified {len(ssh_audit.cves)} CVEs", Out.INFO)
                for cve in ssh_audit.cves:
                    cve_str = f"{cve.name} ({cve.severity}): {cve.description}"
                    self.ptprint(cve_str)
                    json_lines.append(cve_str)

                if len(json_lines) > 0:
                    self.ptjsonlib.add_vulnerability(
                        VULNS.CVE.value, "ssh-audit scan", "\n".join(json_lines)
                    )

                json_lines = []
                self.ptprint(
                    f"Identified {len(ssh_audit.cryptofindings)} insecure SSH configurations",
                    Out.INFO,
                )
                for find in ssh_audit.cryptofindings:
                    find_str = (
                        f"{find.level.upper()} {find.category}/{find.action}: {find.name}"
                        + (f" ({find.notes})" if find.notes else "")
                    )
                    self.ptprint(find_str)
                    json_lines.append(find_str)

                if len(json_lines) > 0:
                    self.ptjsonlib.add_vulnerability(
                        VULNS.InsecureCrypto.value, "ssh-audit scan", "\n".join(json_lines)
                    )

        # Bad host key
        if badpubkey := self.results.bad_pubkey:
            self.ptprint(f"Known static (bad) host key: {badpubkey.bad}", title=True)

            if badpubkey.bad:
                self.ptprint(f"Matched key path:", Out.INFO)
                self.ptprint(badpubkey.path)
                self.ptjsonlib.add_vulnerability(
                    VULNS.BadHostKey.value,
                    f"matched key from: {self.args.bad_pubkeys}",
                    badpubkey.path,
                )

        # Bad auth keys
        if (badauthkeys := self.results.bad_authkeys) is not None:
            self.ptprint(
                f"Known static (bad) auth keys: {len(badauthkeys) > 0}",
                title=True,
            )

            if len(badauthkeys) > 0:
                self.ptprint("Matched keys:", Out.INFO)

                json_lines = []
                for authkey in badauthkeys:
                    self.ptprint(authkey)
                    json_lines.append(authkey)

                self.ptjsonlib.add_vulnerability(
                    VULNS.BadAuthKeys.value,
                    f"matched keys from: {self.args.bad_authkeys}",
                    "\n".join(json_lines),
                )

        # Login bruteforce
        if brute := self.results.brute:
            self.ptprint(f"Login bruteforce: {len(brute.creds)} valid credentials", title=True)

            if brute.errors:
                self.ptprint(
                    "WARNING: there were some errors during the bruteforce process."
                    + " Try reducing the --threads parameter",
                    Out.WARNING,
                )
                properties["bruteStatus"] = "errors"
            else:
                properties["bruteStatus"] = "ok"

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

                    self.ptprint(cred_str)
                    json_lines.append(cred_str)

                if self.args.user is not None:
                    user_str = f"username: {self.args.user}"
                else:
                    user_str = f"usernames: {self.args.users_file}"

                if self.args.passw is not None:
                    passw_str = f"password: {self.args.passw}"
                elif self.args.privkeys is not None:
                    passw_str = f"private keys: {self.args.privkeys}"
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
