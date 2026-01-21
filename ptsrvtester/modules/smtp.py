import argparse, random, re, smtplib, socket, time, dns.resolver
from base64 import b64decode, b64encode
from dataclasses import dataclass
from enum import Enum
from typing import NamedTuple

from ptlibs import ptmisclib
from ptlibs.ptjsonlib import PtJsonLib
from ..ptntlmauth.ptntlmauth import NTLMInfo, get_NegotiateMessage_data, decode_ChallengeMessage_blob

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
from .utils.blacklist_parser import BlacklistParser


# region helper methods


def valid_target_smtp(target: str) -> Target:
    return valid_target(target, domain_allowed=True)


# endregion

# region data classes


class NTLMResult(NamedTuple):
    success: bool
    ntlm: NTLMInfo | None


class MaxConnectionsResult(NamedTuple):
    max: int | None
    ban_minutes: float | None


class EnumResult(NamedTuple):
    method: str
    vulnerable: bool
    slowdown: bool | None
    results: list[str] | None


class BlacklistEntry(NamedTuple):
    blacklist: str
    reason: str
    ttl: str


class BlacklistResult(NamedTuple):
    listed: bool
    results: list[BlacklistEntry] | None


class InfoResult(NamedTuple):
    banner: str
    ehlo: str


@dataclass
class SMTPResults:
    blacklist: BlacklistResult | None = None
    spf_records: dict[str, list[str]] | None = None
    creds: set[Creds] | None = None
    enum_results: list[EnumResult] | None = None
    info: InfoResult | None = None
    max_connections: MaxConnectionsResult | None = None
    ntlm: NTLMResult | None = None
    open_relay: bool | None = None


class VULNS(Enum):
    Blacklist = "PTV-SMTP-BLACKLIST"
    NTLM = "PTV-GENERAL-NTLMINFORMATION"
    OpenRelay = "PTV-SMTP-OPENRELAY"
    UserEnum = "PTV-SMTP-USERENUMERATION"
    WeakCreds = "PTV-GENERAL-WEAKCREDENTIALS"


# endregion

# region arguments


class SMTPArgs(ArgsWithBruteforce):
    target: Target
    tls: bool
    starttls: bool
    info: bool
    ntlm: bool
    mail_from: str | None
    rcpt_to: str | None
    wordlist: str | None
    fqdn: str | None
    enumerate: list[str] | str | None
    blacklist_test: bool
    max_connections: bool
    slow_down: bool
    spf_test: bool
    open_relay: bool
    interactive: bool

    @staticmethod
    def get_help():
        return [
            {"description": ["SMTP Testing Module"]},
            {"usage": ["ptsrvtester smtp <options> <target>"]},
            {"usage_example": [
                "ptsrvtester smtp -e ALL -sd -w wordlist.txt mail.example.com:25",
                "ptsrvtester smtp --info --ntlm 127.0.0.1"
            ]},
            {"options": [
                ["", "--info", "", "Gather basic information"],
                ["", "--ntlm", "", "Inspect NTLM authentication"],
                ["-e", "--enumerate", "", "User enumeration (VRFY/EXPN/RCPT/ALL)"],
                ["-w", "--wordlist", "", "Wordlist for enumeration"],
                ["-sd", "--slow-down", "", "Test slow-down protection"],
                ["-mc", "--max-connections", "", "Max connections test"],
                ["", "--open-relay", "", "Test open relay"],
                ["-i", "--interactive", "", "Interactive SMTP CLI"],
                ["", "", "", ""],
                ["-b", "--blacklist-test", "", "Test against blacklists"],
                ["-s", "--spf-test", "", "Test SPF records"],
                ["", "", "", ""],
                ["", "--tls", "", "Use implicit SSL/TLS"],
                ["", "--starttls", "", "Use explicit SSL/TLS"],
                ["", "", "", ""],
                ["-h", "--help", "", "Show this help message and exit"],
            ]}
        ]

    def add_subparser(self, name: str, subparsers) -> None:
        examples = """example usage:
  ptsrvtester smtp -h
  ptsrvtester smtp -e ALL -sd -w wordlist.txt mail.example.com:25"""

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
            type=valid_target_smtp,
            help="IP[:PORT] or HOST[:PORT] (e.g. 127.0.0.1 or localhost:25)",
        )

        parser.add_argument("--tls", action="store_true", help="use implicit SSL/TLS")
        parser.add_argument("--starttls", action="store_true", help="use explicit SSL/TLS")
        parser.add_argument("-f", "--fqdn", type=str, help="")

        indirect = parser.add_argument_group(
            "INDIRECT SCANNING",
            "Operations that do NOT communicate directly with the target server",
        )
        indirect.add_argument(
            "-b", "--blacklist-test", action="store_true", help="Test target against blacklists"
        )
        indirect.add_argument("-s", "--spf-test", action="store_true", help="Test SPF records")

        direct = parser.add_argument_group(
            "DIRECT SCANNING", "Operations that communicate directly with the target server"
        )
        direct.add_argument(
            "--info", action="store_true", help="Gather basic information (bannergrabbing)"
        )
        direct.add_argument("--ntlm", action="store_true", help="inspect NTLM authentication")
        direct.add_argument("-w", "--wordlist", type=str, help="Provide wordlist")
        direct.add_argument(
            "-e",
            "--enumerate",
            type=str,
            choices=["VRFY", "EXPN", "RCPT", "ALL"],
            nargs="?",
            help="User enumeration method",
        )
        direct.add_argument(
            "-sd",
            "--slow-down",
            action="store_true",
            help="Test against slow-down protection during enumeration",
        )
        direct.add_argument(
            "-mc", "--max-connections", action="store_true", help="Max connections test"
        )
        direct.add_argument("--open-relay", action="store_true", help="Test Open relay")
        direct.add_argument("-m", "--mail-from", type=str, help="")
        direct.add_argument("-r", "--rcpt-to", type=str, help="")
        direct.add_argument(
            "-i", "--interactive", action="store_true", help="Establish interactive SMTP CLI"
        )

        add_bruteforce_args(parser)


# endregion

# region main module code


class SMTP(BaseModule):
    @staticmethod
    def module_args():
        return SMTPArgs()

    def __init__(self, args: BaseArgs, ptjsonlib: PtJsonLib):
        if not isinstance(args, SMTPArgs):
            raise argparse.ArgumentError(
                None, f'module "{args.module}" received wrong arguments namespace'
            )

        if args.slow_down and args.enumerate == None:
            raise argparse.ArgumentError(None, "--slow-down requires also --enumerate")

        if args.interactive and args.json:
            raise argparse.ArgumentError(None, "--interactive cannot be used together with --json")

        self.use_json = args.json
        self.already_enumerated = None

        self.max_connections_is_error = None
        self.is_slow_down = None
        self.fqdn = "pentereptools.foo" if not args.fqdn else args.fqdn

        self.wordlist = ptmisclib.read_file(args.wordlist) if args.wordlist else None
        self.wordlist = list(filter(lambda x: x != "", self.wordlist)) if args.wordlist else None

        # Default port number
        if args.target.port == 0:
            if args.tls:
                args.target.port = 587
            else:
                args.target.port = 25
        self.target = args.target.ip
        self.port = args.target.port

        self.do_brute = check_if_brute(args)

        try:
            socket.inet_aton(self.target)
            self.target_is_ip = True
        except socket.error as e:
            self.target_is_ip = False
        if self.target_is_ip:
            self.target_ip = self.target
            if args.spf_test:
                raise argparse.ArgumentError(
                    None, "--spf-test requires target specified by a domain name"
                )
        else:
            self.target_ip = socket.gethostbyname(self.target)

        self.args = args
        self.ptjsonlib = ptjsonlib
        self.results: SMTPResults

    def run(self):
        self.results = SMTPResults()
        smtp = None

        # Indirect scanning
        if self.args.blacklist_test:
            self.results.blacklist = self.test_blacklist(self.target)

        if self.args.spf_test:
            self.results.spf_records = self._get_nameservers(self.target)

        # Direct scanning
        # enter only if any of these arguments were explicitly specified
        if (
            self.args.info
            or self.args.interactive
            or self.args.ntlm
            or self.args.open_relay
            or self.args.enumerate
            or self.args.max_connections
            or self.do_brute
        ):
            smtp, info = self.initial_info()

            if self.args.info:
                self.results.info = info

            if self.args.interactive and not self.use_json:
                self.start_interactive_mode(smtp)

            if self.args.ntlm:
                self.results.ntlm = self.auth_ntlm(smtp)

            if self.args.open_relay:
                self.results.open_relay = self.open_relay_test(
                    smtp, "TEST", self.args.mail_from, self.args.rcpt_to
                )

            if self.args.enumerate is not None:
                self.results.enum_results = self.enumeration(smtp)

            if self.args.max_connections:
                self.results.max_connections = self.max_connections_test()

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

    def connect(self) -> tuple[smtplib.SMTP | smtplib.SMTP_SSL, int, bytes]:
        try:
            if self.args.tls:
                smtp = smtplib.SMTP_SSL(timeout=15.0)
            else:
                smtp = smtplib.SMTP(timeout=15.0)

            status, reply = smtp.connect(self.args.target.ip, self.args.target.port)
            if self.args.starttls:
                smtp.starttls()

            return smtp, status, reply
        except Exception as e:
            self.ptjsonlib.end_error(
                f"Could not connect to the target server "
                + f"{self.args.target.ip}:{self.args.target.port} ({get_mode(self.args)}): {e}",
                self.use_json,
            )
            raise SystemExit

    def get_smtp_handler(self) -> smtplib.SMTP:
        smtp_handler, status, reply = self.connect()
        if status == 220:
            return smtp_handler
        else:
            self.ptjsonlib.end_error(
                f"SMTP Info - [{status}] {self.bytes_to_str(reply)}", self.use_json
            )

    def _get_smtp_connection(self):
        smtp, status, reply = self.connect()

        if status == 220:
            status, reply = smtp.docmd("EHLO", f"{self.fqdn}")
            if status == 250:
                # print("OK CONNECTION", reply)
                return smtp
            else:
                raise Exception("Error when EHLOing")
        else:
            raise Exception("Max connection error")

    def wait_for_unban(self, seconds, ban_duration=0):
        self.noop_smtp_connections()
        ban_duration += seconds
        time.sleep(seconds)
        # print(ban_duration/60)
        try:
            self.ptdebug(f">", end="")
            self._get_smtp_connection()
            self.ptdebug(f"\r", end="")
            return ban_duration / 60
        except Exception as e:
            return self.wait_for_unban(5, ban_duration)

    def noop_smtp_connections(self):
        for smtp in self.smtp_list:
            status, reply = smtp.docmd("noop")
            if status != 250:
                return True
        return False

    def close_smtp_connections(
        self,
    ):
        for smtp in self.smtp_list:
            try:
                smtp.quit()
            except Exception as e:
                # print("error closing smtp connections:", e)
                continue
        del self.smtp_list

    def max_connections_test(self) -> MaxConnectionsResult:
        self.smtp_list = []
        allowed_connections = None
        is_disconnect = False
        ban_duration = None

        self.ptdebug(f"Max smtp connections test", title=True)
        start_time = time.time()
        self.ptdebug(f"", Out.INFO, end="")
        for index, i in enumerate(range(100)):
            try:
                self.ptdebug(f">", end="")
                self.smtp_list.append(self._get_smtp_connection())
                if self.noop_smtp_connections() and not is_disconnect:
                    is_disconnect = time.time() - start_time
            except Exception as e:
                # ve chvili kdy uz neni mozne navazat spojeni
                allowed_connections = len(self.smtp_list)
                self.ptdebug(f"\r", end="")
                self.ptdebug(
                    f"Maximum number of estabilished connections: {allowed_connections} {' '*(allowed_connections-35)}",
                    Out.INFO,
                )
                if index == 0:
                    self.ptjsonlib.end_error(
                        f"Could not retrieve initial smtp connection - {e}", self.use_json
                    )
                self.smtp_list.pop()
                try:
                    # self.noop_smtp_connections()
                    self.smtp_list.append(self._get_smtp_connection())
                except Exception as e:
                    self.ptdebug(f"You're banned, reconnecting in 60 seconds ...", Out.INFO)
                    self.ptdebug(f"", Out.INFO, end="")
                    ban_duration = self.wait_for_unban(60)
                break

        # close all smtp connections and delete *self.smtp_list*
        self.close_smtp_connections()

        if is_disconnect:
            self.ptdebug(
                f"Refreshed connection is disconnected after: {round(is_disconnect)} seconds",
                Out.INFO,
            )
        if ban_duration:
            self.ptdebug(f"Unblocked after {ban_duration} minutes", Out.INFO)
        else:
            self.ptdebug(f"Not banned", Out.INFO)

        return MaxConnectionsResult(allowed_connections, ban_duration)

    def open_relay_test(self, smtp, msg, mail_from, rcpt_to) -> bool:
        self.ptdebug(f"Open Relay Test:", title=True)
        try:
            smtp.sendmail(mail_from, rcpt_to, msg)
            self.ptdebug("Server is vulnerable to Open relay", Out.VULN)
            return True
        except:
            self.ptdebug("Server is not vulnerable to Open relay", Out.NOTVULN)
            return False

    def start_interactive_mode(self, smtp: smtplib.SMTP):
        self.ptprint("\n", end="")
        while True:
            user_input = input("[*] INTERACTIVE MODE: ").upper()
            status, reply = smtp.docmd(user_input)
            if user_input in ("EXIT", "QUIT"):
                break
            if user_input == "HELP":
                self.ptprint(f"[{status}] " + self.bytes_to_str(reply))
            if not self.bytes_to_str(reply).endswith("\n"):
                self.ptprint(f"[{status}] " + self.bytes_to_str(reply))
                self.ptprint(f" ")
            else:
                self.ptprint(f"[{status}] " + self.bytes_to_str(reply).replace("\n", "\n      "))

    def expn_vrfy_slow_down_test(self, method: str, smtp):
        if sum(self.slow_down_results.values()) >= 1:
            self.ptdebug(f"New smtp handle required, initiating new smtp connection ...", Out.INFO)
            smtp = self.get_smtp_handler()
            smtp.docmd("EHLO", f"{self.fqdn}")

        self.ptdebug(f"[{method}] SLOW DOWN TEST {' '*6}", Out.INFO, end="\r")

        dummy_data = [
            "".join(random.choices("abcdefghijk", k=random.randint(1, 5))) for i in range(29)
        ]
        half = int(len(dummy_data) / 2)
        is_slow_down = False
        initial_time = 0
        last_request_time = 0
        first_half_time = 0
        second_half_time = 0
        for index, user in enumerate(dummy_data):
            endl = "\n" if index + 1 == len(dummy_data) else "\r"
            self.ptdebug(
                f"[{method}] SLOW DOWN TEST [{index+1}/{len(dummy_data)}]", Out.INFO, end=endl
            )
            start_time = time.time()
            try:
                smtp.docmd(method, user)
            except:
                return {method.lower(): True}

            end_time = time.time() - start_time

            last_request_time = end_time
            if index == 0:
                initial_time += end_time

            if index < half:
                first_half_time += end_time
            else:
                second_half_time += end_time

            if end_time >= 3:
                is_unstable_response = True
            if end_time >= 3 and is_unstable_response:
                self.ptdebug(f"[{method}] SLOW DOWN TEST [{index+1}/{index+1}]", Out.INFO)
                self.ptdebug(f"Unstable response (>3sec), break", Out.VULN)
                is_slow_down = True
                break

        if (second_half_time - first_half_time) > initial_time * 10:
            is_slow_down = True
        if is_slow_down:
            self.ptdebug(f"{method} Method have slow-down protection implemented", Out.NOTVULN)
        self.ptdebug(f"First request response time: {str(initial_time)[:8]}", Out.INFO)
        self.ptdebug(f"Last request response time:  {str(last_request_time)[:8]}", Out.INFO)

        return {method.lower(): is_slow_down}

    def rcpt_slow_down_test(self, smtp):
        if sum(self.slow_down_results.values()) >= 1:
            # print("Retrieving new smtp handle ... for rcpt test")
            smtp = self.get_smtp_handler()
            smtp.docmd("EHLO", f"{self.fqdn}")

        self.ptdebug(f"[RCPT] SLOW DOWN TEST {' '*6}", Out.INFO, end="\r")
        status, reply = smtp.docmd("MAIL FROM:", "<mail@from.me>")

        dummy_data = [
            "".join(random.choices("abcdefghijk", k=random.randint(1, 5))) for i in range(20)
        ]
        half = int(len(dummy_data) / 2)
        time_data = []
        is_slow_down = False

        first_half_time = 0
        initial_time = 0
        second_half_time = 0
        last_request_time = 0

        is_unstable_response = False
        for index, user in enumerate(dummy_data):
            endl = "\n" if index + 1 == len(dummy_data) else "\r"
            self.ptdebug(f"[RCPT] SLOW DOWN TEST [{index+1}/{len(dummy_data)}]", Out.INFO, end=endl)
            start_time = time.time()
            status, reply = smtp.docmd("RCPT TO:", f"<{user}>")
            end_time = time.time() - start_time

            last_request_time = end_time
            if index == 0:
                initial_time += end_time
            # if index+1 == len(dummy_data):
            if index < half:
                first_half_time += end_time
            else:
                second_half_time += end_time

            if end_time >= 3:
                is_unstable_response = True
            if end_time >= 3 and is_unstable_response:
                # print("unstable response, break")
                is_slow_down = True
                break

        if (second_half_time - first_half_time) > initial_time * 10:
            is_slow_down = True
        if is_slow_down:
            self.ptdebug(f"[RCPT] Method have slow-down protection implemented", Out.NOTVULN)

        self.ptdebug(f"First request response time: {str(initial_time)[:8]}", Out.INFO)
        self.ptdebug(f"Last request response time:  {str(last_request_time)[:8]}", Out.INFO)

        return {"rcpt": is_slow_down}

    def expn_vrfy_enumeration(self, method, smtp) -> list[str]:
        self.ptdebug(f"Enumerating users:", Out.INFO)
        enumerated_users: list[str] = []
        total_aliases = 0 if method == "EXPN" else None
        for user in self.wordlist:
            start_time = time.time()
            # print(user)
            status, reply = smtp.docmd(method, user)
            # print(status, "\n", time.time() - start_time)
            if status != 550:
                user_email = re.findall(r"<(.*?)>", self.bytes_to_str(reply))
                enumerated_users.append(user_email)
                self.ptdebug(
                    user_email[0],
                )
                if method == "EXPN" and len(user_email) > 1:
                    for alias in user_email[1:]:
                        total_aliases += len(user_email[1:])
                        self.ptdebug(f"   {alias}", Out.ADDITIONS)

        additional_message = (
            f"(total {len(enumerated_users) + total_aliases} with aliases)"
            if method == "EXPN"
            else ""
        )
        self.ptdebug(f" ")
        self.ptdebug(f"-- Enumerated {len(enumerated_users)} emails {additional_message} --")
        self.ptdebug(f" ")

        self.already_enumerated = True
        return enumerated_users

    def expn_vrfy_test(self, method, smtp) -> bool:
        status, reply = smtp.docmd(method, "foofoofoo")
        self.ptdebug(f"Testing {method} method: [{status}] {self.bytes_to_str(reply)}", Out.INFO)
        if status in [250, 550] and not "AUTH" in self.bytes_to_str(reply).upper():
            is_vulnerable = True
            self.ptdebug(f"Server is vulnerable to {method} enumeration", Out.VULN)
        else:
            is_vulnerable = False
            self.ptdebug(f"Server is not vulnerable to {method} enumeration", Out.INFO)
        return is_vulnerable

    def newline_to_reply(self, reply):
        reply = self.bytes_to_str(reply)
        if not reply.endswith("\n"):
            reply += "\n"
        return reply

    def rcpt_test(self, smtp) -> bool:
        """RCPT enum vulnerability"""
        self.ptdebug(f"Testing RCPT method:", Out.INFO, end=" ")

        status, reply = smtp.docmd("MAIL FROM:", "<mail@from.me>")
        status, reply = smtp.docmd("RCPT TO:", "<foofoofoo>")
        reply = self.bytes_to_str(reply)
        self.ptdebug(f"[{status}] " + reply)
        if (
            status in [250, 550]
            and not "AUTH" in reply.upper()
            and ("UNKNOWN" in reply.upper() or "OK" in reply.upper())
        ):
            is_vulnerable = True
            self.ptdebug(f"Server is vulnerable to RCPT enumeration", Out.VULN)
        else:
            is_vulnerable = False
            self.ptdebug(f"Server is not vulnerable to RCPT enumeration", Out.NOTVULN)
        return is_vulnerable

    def rcpt_enumeration(self, smtp) -> list[str]:
        self.ptdebug(f"Enumerating users:", Out.INFO)
        enumerated_users: list[str] = []
        for user in self.wordlist:
            user = user.split("@")[0]
            status, reply = smtp.docmd("RCPT TO:", f"<{user}>")
            if status != 550 and not "UNKNOWN" in self.bytes_to_str(reply).upper():
                enumerated_users.append(user)
                self.ptdebug(user)

        self.ptdebug(f" ")
        self.ptdebug(f"-- Enumerated {len(enumerated_users)} users --")
        self.ptdebug(f" ")

        self.already_enumerated = True
        return enumerated_users

    def bytes_to_str(self, text):
        return text.decode("utf-8")

    def test_blacklist(self, target: str) -> BlacklistResult:
        self.ptdebug("Testing target against blacklists:", title=True)
        blacklist_parser = BlacklistParser(self.ptdebug, self.args.json)

        try:
            error_msg = blacklist_parser.lookup(target)
        except Exception as e:
            self.ptjsonlib.end_error(f"Exception during Blacklist lookup: {e}", self.args.json)

        if error_msg:
            self.ptdebug(error_msg, Out.VULN)

        listed = [
            BlacklistEntry(r[1], r[2], r[3])
            for r in blacklist_parser.result["table_result"]
            if r[0] == "LISTED"
        ]

        if len(listed) > 0:
            return BlacklistResult(True, listed)
        else:
            return BlacklistResult(False, None)

        # parser_result_json = blacklist_parser.result

    def _resolver_query(self, resolver, domain, ns, record_type):
        data = resolver.resolve(domain, record_type)
        return [self._rdata_to_str(rdata) for rdata in data]

    def _get_spf_records(self, resolver, domain, ns):
        # self.ptprint(f"SPF Records for {ns}:", "INFO", self.use_json))
        spf_result = {ns: []}
        try:
            for record in ["SPF", "TXT"]:
                spf_result[ns].append(self._rdata_to_str(rdata))
        except dns.resolver.NoAnswer as e:
            pass
        except dns.resolver.Timeout as e:
            pass

    def _rdata_to_str(self, rdata):
        str_rdata = str(rdata)
        if str_rdata.startswith('"') and str_rdata.endswith('"'):
            str_rdata = str_rdata[1:-1]
        return str_rdata

    def _get_nameservers(self, domain) -> dict[str, list[str]]:
        self.ptdebug(f"Retrieving SPF records for: {self.target}", title=True)

        resolver = dns.resolver.Resolver()
        resolver.timeout = 10
        resolver.lifetime = 10
        self.ptdebug(f"Retrieving nameservers for domain: {domain}", title=True)
        try:
            ns_query = resolver.resolve(domain, "NS", tcp=True)
            nameserver_list = [str(rdata)[:-1] for rdata in ns_query]
            self.ptdebug("    " + "\n    ".join(nameserver_list))
        except Exception as e:
            self.ptjsonlib.end_error(f"Error retrieving nameservers - {e}", self.use_json)

        spf_result = {}
        for ns in nameserver_list:
            try:
                ns_ip = socket.gethostbyname(ns)
            except Exception as e:
                self.ptdebug(f"Exception - {e}", Out.ERROR)
                continue
            resolver.nameservers = [ns_ip]
            spf_result.update({ns: []})
            self.ptdebug(f"{ns}:", Out.INFO)
            spf_result[ns].extend(self._get_spf_for_ns(domain, resolver))

        is_spf_difference = self._check_difference_between_ns_response(spf_result)

        results = {ns: val for ns, val in spf_result.items() if len(val) > 0}
        return results

    def _check_difference_between_ns_response(self, result):
        is_difference = False
        for index, value in enumerate(result.values()):
            for index_2, value_2 in enumerate(result.values()):
                if index == index_2:
                    continue
                if value != value_2:
                    is_difference = True
        if is_difference:
            self.ptdebug(f"Different response between nameservers", Out.VULN)
            return True
        else:
            return False

    def _get_spf_for_ns(self, domain, resolver):
        try:
            result = []
            for dns_type in ["TXT", "SPF"]:
                answer = resolver.resolve(domain, dns_type)
                for rdata in answer:
                    rdata = self._rdata_to_str(rdata)
                    if dns_type == "TXT" and not re.search("v=spf1", rdata):
                        continue
                    result.append(rdata)
                    self.ptdebug(rdata)
        except dns.resolver.NoAnswer as e:
            pass
        except dns.resolver.Timeout as e:
            raise Exception("Timeout error")
        return result

    def auth_ntlm(self, smtp: smtplib.SMTP) -> NTLMResult:
        """
        Performs NTLM authentication to extract internal server
        information from server's challenge response.

        Returns:
            NTLMInfo | None: disclosed information, or None in case of failure
        """
        ntlm = None
        try:
            code, resp = smtp.docmd("AUTH NTLM")
            if code == 334:
                smtp.send(b64encode(get_NegotiateMessage_data()) + smtplib.bCRLF)
                code, resp = smtp.getreply()

                ntlm = decode_ChallengeMessage_blob(b64decode(resp))
        except:
            ntlm = None

        if ntlm is None:
            self.ptdebug(
                f"Server is not vulnerable to information disclosure via NTLM authentication",
                Out.NOTVULN,
            )
            return NTLMResult(False, None)
        else:
            self.ptdebug(
                f"Server is vulnerable to information disclosure via NTLM authentication", Out.VULN
            )
            self.ptdebug(f"  Target name: {ntlm.target_name}")
            self.ptdebug(f"  NetBios domain name: {ntlm.netbios_domain}")
            self.ptdebug(f"  NetBios computer name: {ntlm.netbios_computer}")
            self.ptdebug(f"  DNS domain name: {ntlm.dns_domain}")
            self.ptdebug(f"  DNS computer name: {ntlm.dns_computer}")
            self.ptdebug(f"  DNS tree: {ntlm.dns_tree}")
            self.ptdebug(f"  OS version: {ntlm.os_version}")

            return NTLMResult(True, ntlm)

    def test_enumeration(self, smtp: smtplib.SMTP, enumeration_vulns: dict[str, bool | None]):
        if self.args.enumerate is None:
            return None

        if self.args.enumerate == "ALL":
            self.args.enumerate = ["VRFY", "EXPN", "RCPT"]

        try:
            if "EXPN" in self.args.enumerate:
                enumeration_vulns.update({"expn": self.expn_vrfy_test("EXPN", smtp)})
            if "VRFY" in self.args.enumerate:
                enumeration_vulns.update({"vrfy": self.expn_vrfy_test("VRFY", smtp)})
            if "RCPT" in self.args.enumerate:
                enumeration_vulns.update({"rcpt": self.rcpt_test(smtp)})
        except Exception as e:
            self.ptjsonlib.end_error(
                f"Connection terminated with server "
                + f"{self.args.target.ip}:{self.args.target.port} ({get_mode(self.args)}): {e}",
                self.use_json,
            )
            raise SystemExit

    def test_slowdown_enumeration(
        self, smtp: smtplib.SMTP, enumeration_vulns: dict[str, bool | None]
    ):
        if self.args.enumerate is None:
            return None

        # self.prefered_enum_method = None
        self.slow_down_results = {"expn": False, "vrfy": False, "rcpt": False}
        if "EXPN" in self.args.enumerate and enumeration_vulns["expn"]:
            self.slow_down_results.update(self.expn_vrfy_slow_down_test("EXPN", smtp))
        if (
            "VRFY" in self.args.enumerate and enumeration_vulns["vrfy"]
        ):  # and not self.is_slow_down:
            self.slow_down_results.update(self.expn_vrfy_slow_down_test("VRFY", smtp))
        if (
            "RCPT" in self.args.enumerate and enumeration_vulns["rcpt"]
        ):  # and not self.is_slow_down:
            self.slow_down_results.update(self.rcpt_slow_down_test(smtp))

        self.ptdebug("Slow-Down results:", Out.INFO)
        for key, value in self.slow_down_results.items():
            self.ptdebug(f"{key}:{bool(value)}")

    def do_enumeration(
        self, smtp: smtplib.SMTP, enumeration_vulns: dict[str, bool]
    ) -> dict[str, list[str] | None]:
        enumeration_results: dict[str, list[str] | None] = {
            "expn": None,
            "vrfy": None,
            "rcpt": None,
        }
        if enumeration_vulns["expn"]:
            enumeration_results["expn"] = self.expn_vrfy_enumeration("EXPN", smtp)
        elif enumeration_vulns["vrfy"]:
            enumeration_results["vrfy"] = self.expn_vrfy_enumeration("VRFY", smtp)
        elif enumeration_vulns["rcpt"]:
            enumeration_results["rcpt"] = self.rcpt_enumeration(smtp)

        return enumeration_results

    def enumeration(self, smtp: smtplib.SMTP) -> list[EnumResult]:
        enumeration_vulns: dict[str, bool | None] = {
            "expn": None,
            "vrfy": None,
            "rcpt": None,
        }
        enumeration_results = None

        self.test_enumeration(smtp, enumeration_vulns)

        if self.args.slow_down:
            self.test_slowdown_enumeration(smtp, enumeration_vulns)

        if self.wordlist is not None:
            enumeration_results = self.do_enumeration(smtp, enumeration_vulns)

        enum_results: list[EnumResult] = []

        for method in enumeration_vulns.keys():
            if (vulnerable := enumeration_vulns[method]) is not None:
                if self.args.slow_down:
                    slow_down = self.slow_down_results[method]
                else:
                    slow_down = None

                if self.wordlist is not None:
                    wordlist_result = enumeration_results[method]
                else:
                    wordlist_result = None

                enum_results.append(EnumResult(method, vulnerable, slow_down, wordlist_result))

        return enum_results

    def initial_info(self) -> tuple[smtplib.SMTP, InfoResult]:
        self.ptdebug("Initial server information", title=True)

        smtp, _, banner = self.connect()
        banner = banner.decode()
        self.ptdebug("Banner: " + banner, Out.INFO)

        try:
            _, ehlo = smtp.ehlo(self.fqdn)
            ehlo = ehlo.decode()
            self.ptdebug("EHLO response: " + ehlo, Out.INFO)

        except Exception as e:
            self.ptjsonlib.end_error(
                f"Could not negotiate initial EHLO with "
                + f"{self.args.target.ip}:{self.args.target.port} ({get_mode(self.args)}): {e}",
                self.use_json,
            )
            raise SystemExit

        return smtp, InfoResult(banner, ehlo)

    def _try_login(self, creds: Creds) -> Creds | None:
        smtp, *_ = self.connect()

        try:
            smtp.login(creds.user, creds.passw)
            result = creds
        except:
            result = None
        finally:
            smtp.close()
            return result

    # endregion

    # region output
    def output(self) -> None:
        properties: dict[str, None | str | int | list[str]] = self.ptjsonlib.json_object["results"][
            "properties"
        ]

        # Blacklist information
        if blacklist := self.results.blacklist:
            if not blacklist.listed:
                self.ptprint("Blacklist information: clean", title=True)
            else:
                self.ptprint("Blacklist information: listed", title=True)

                if (results := blacklist.results) is not None:
                    self.ptprint("Listed on the following blacklists:", Out.INFO)

                    json_lines: list[str] = []
                    for r in results:
                        r_str = f'{r.blacklist.strip()}: "{r.reason}" (TTL={r.ttl})'
                        self.ptprint(r_str)
                        json_lines.append(r_str)

                    if len(json_lines) > 0:
                        self.ptjsonlib.add_vulnerability(
                            VULNS.Blacklist.value,
                            f"blacklists containing target {self.target}",
                            "\n".join(json_lines),
                        )

        # SPF records
        if (spf_records := self.results.spf_records) is not None:
            self.ptprint(f"SPF records: found {len(spf_records)} records", title=True)

            json_lines = []
            for ns, records in spf_records.items():
                self.ptprint("Nameserver " + ns, Out.INFO)
                for r in records:
                    self.ptprint(r)
                    json_lines.append(f"[{ns}] {r}")

            if len(json_lines) > 0:
                properties["spfRecords"] = "\n".join(json_lines)

        # Server information
        if info := self.results.info:
            self.ptprint("Server information", title=True)

            self.ptprint(f"Banner:", Out.INFO)
            self.ptprint(info.banner)
            properties["banner"] = info.banner

            self.ptprint(f"EHLO:", Out.INFO)
            self.ptprint(info.ehlo)
            properties["ehloCommand"] = info.ehlo

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

        # Open relay
        if (open_relay := self.results.open_relay) is not None:
            self.ptprint(f"Open relay: {open_relay}", title=True)

            if open_relay:
                self.ptjsonlib.add_vulnerability(VULNS.OpenRelay.value, "Open relay")

        # User enumeration
        if (enum_results := self.results.enum_results) is not None:
            self.ptprint("User enumeration methods", title=True)

            json_lines = []
            for e in enum_results:
                if e.slowdown is not None:
                    slowdown = " (rate limited)" if e.slowdown else " (not rate limited)"
                else:
                    slowdown = ""

                vuln = "vulnerable" if e.vulnerable else "not vulnerable"

                out_str = f'Method "{e.method}" {vuln}{slowdown}'
                self.ptprint(out_str, Out.INFO)

                if not e.vulnerable:
                    continue

                json_lines.append(out_str)

                if (results := e.results) is not None:
                    out_str = f"Enumerated {len(results)} users"
                    self.ptprint(out_str, Out.INFO)
                    json_lines.append(out_str)

                    for r in results:
                        self.ptprint(r)
                        json_lines.append(r)

            if len(json_lines) > 0:
                self.args.enumerate
                req = f"enumeration methods: {self.args.enumerate}"
                if self.args.wordlist is not None:
                    req += f"\nwordlist used: {self.args.wordlist}"

                self.ptjsonlib.add_vulnerability(VULNS.UserEnum.value, req, "\n".join(json_lines))

        # Maximum connections
        if max_con := self.results.max_connections:
            if max_con.max is None:
                self.ptprint("Maximum connections: no limit found", title=True)
                properties["maxConnections"] = None
            else:
                self.ptprint("Maximum connections", title=True)
                self.ptprint(f"Maximum simultaneous connections: {max_con.max}")
                properties["maxConnections"] = max_con.max

                if max_con.ban_minutes is None:
                    self.ptprint(f"No timeout (ban) detected")
                    properties["banDuration"] = None
                else:
                    self.ptprint(f"Timeout (ban) duration: {max_con.ban_minutes} minutes")
                    properties["banDuration"] = max_con.ban_minutes

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
