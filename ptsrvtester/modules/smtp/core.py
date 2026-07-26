import argparse, socket, sys, threading
from base64 import b64encode

from ptlibs.ptjsonlib import PtJsonLib

try:
    from ntlm_auth.ntlm import NtlmContext
except ImportError:
    NtlmContext = None

from .._base import BaseModule, BaseArgs, Out
from ..utils.helpers import check_if_brute, simple_bruteforce, text_or_file

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False

from .helpers import *
from .results import *
from .registry import *
from .cli import *

from .tests.recon import ReconMixin
from .tests.protocol import ProtocolMixin
from .tests.auth import AuthMixin
from .tests.enumeration import EnumMixin
from .tests.relay import RelayMixin
from .tests.delivery import DeliveryMixin
from .tests.content import ContentMixin
from .tests.stress import StressMixin
from .tests.indirect import IndirectMixin
from .reporting import ReportingMixin
from .connection import ConnectionMixin
from .shared import SharedMixin


class SMTP(ReconMixin, ProtocolMixin, AuthMixin, EnumMixin, RelayMixin, DeliveryMixin, ContentMixin, StressMixin, IndirectMixin, ReportingMixin, ConnectionMixin, SharedMixin, BaseModule):
    @staticmethod
    def module_args():
        return SMTPArgs()

    def __init__(self, args: BaseArgs, ptjsonlib: PtJsonLib):
        if not isinstance(args, SMTPArgs):
            raise argparse.ArgumentError(
                None, f'module "{args.module}" received wrong arguments namespace'
            )

        # Translate -ts/--tests codes into the internal per-test dest flags before validation.
        _apply_smtp_tests(args)

        if args.slow_down and args.enumerate == None:
            raise argparse.ArgumentError(None, "--slow-down requires also --enumerate")

        bomb_requested = getattr(args, "bomb", False)
        antivirus_requested = getattr(args, "antivirus", False)
        if bomb_requested and (not args.rcpt_to or not str(args.rcpt_to).strip()):
            raise argparse.ArgumentError(None, "-bomb requires -r/--rcpt-to (recipient)")
        if antivirus_requested and (not args.rcpt_to or not str(args.rcpt_to).strip()):
            raise argparse.ArgumentError(None, "-antivirus requires -r/--rcpt-to (recipient)")
        ssrf_requested = getattr(args, "ssrf", False)
        if ssrf_requested:
            if not args.rcpt_to or not str(args.rcpt_to).strip():
                raise argparse.ArgumentError(None, "-ssrf requires -r/--rcpt-to (recipient)")
            canary = getattr(args, "ssrf_canary_url", None) or ""
            if not canary or not str(canary).strip():
                raise argparse.ArgumentError(None, "-ssrf requires --ssrf-canary-url (canary/callback URL)")
        zipxxe_requested = getattr(args, "zipxxe", False)
        if zipxxe_requested:
            if not args.rcpt_to or not str(args.rcpt_to).strip():
                raise argparse.ArgumentError(None, "-zipxxe requires -r/--rcpt-to (recipient)")
        spoof_headers_requested = getattr(args, "spoof_headers", False)
        if spoof_headers_requested and (not args.rcpt_to or not str(args.rcpt_to).strip()):
            raise argparse.ArgumentError(None, "-sh/--spoof-headers requires -r/--rcpt-to (recipient)")
        bcc_test_requested = getattr(args, "bcc_test", None)
        if bcc_test_requested:
            if not args.rcpt_to or not str(args.rcpt_to).strip():
                raise argparse.ArgumentError(None, "-ts BCC requires -r/--rcpt-to (To recipient)")
            cc_val = getattr(args, "cc", None) or ""
            if not cc_val.strip():
                raise argparse.ArgumentError(None, "-ts BCC requires -cc/--cc (Cc recipient)")
            if not str(bcc_test_requested).strip():
                raise argparse.ArgumentError(None, "-ts BCC requires -bcc/--bcc <emails> (Bcc addresses)")
        alias_test_requested = getattr(args, "alias_test", False)
        if alias_test_requested and (not args.rcpt_to or not str(args.rcpt_to).strip()):
            raise argparse.ArgumentError(None, "-al/--alias-test requires -r/--rcpt-to (base recipient)")
        bounce_replay_requested = getattr(args, "bounce_replay", False)
        if bounce_replay_requested:
            if not args.mail_from or not str(args.mail_from).strip():
                raise argparse.ArgumentError(
                    None, "-br/--bounce-replay requires -m/--mail-from (controlled bounce / MAIL FROM address)"
                )
            if not args.rcpt_to or not str(args.rcpt_to).strip():
                raise argparse.ArgumentError(None, "-br/--bounce-replay requires -r/--rcpt-to (recipient)")
        rl_n = getattr(args, "rcpt_limit", None)
        if rl_n is not None and getattr(args, "send", False):
            if not args.mail_from or not str(args.mail_from).strip() or "@" not in str(args.mail_from):
                raise argparse.ArgumentError(
                    None,
                    "RCPTLIM with --send requires -m/--mail-from (envelope MAIL FROM for delivery)",
                )
        rdd_n = getattr(args, "rcpt_duplicate", None)
        if rdd_n is not None:
            if not args.rcpt_to or not str(args.rcpt_to).strip():
                raise argparse.ArgumentError(
                    None, "-rdd/--rcpt-duplicate requires -r/--rcpt-to (same address is probed)"
                )
            if rdd_n < 2:
                raise argparse.ArgumentError(None, "-rdd/--rcpt-duplicate N must be at least 2")
            if rdd_n > RCPT_DUP_MAX:
                raise argparse.ArgumentError(
                    None, f"-rdd/--rcpt-duplicate N must not exceed {RCPT_DUP_MAX}"
                )
        # Canary required only for XXE variants; billion_laughs and zip_bomb work without it
        if zipxxe_requested:
            variants_arg = getattr(args, "zipxxe_variants", None)
            zipxxe_variants = [v.strip().lower() for v in (variants_arg or "billion_laughs_attach,billion_laughs_body,xxe_zip,xxe_docx").split(",") if v.strip()]
            xxe_variants = {"xxe_zip", "xxe_docx", "xxe_body"}
            needs_canary = any(v in xxe_variants for v in zipxxe_variants)
            if needs_canary:
                canary = getattr(args, "zipxxe_canary_url", None) or ""
                if not canary or not str(canary).strip():
                    raise argparse.ArgumentError(None, "-zipxxe with xxe_zip/xxe_docx/xxe_body requires --zipxxe-canary-url (canary/callback URL)")
        # Known tests: BOMB,ANTIVIRUS,SSRF,FLOOD,ZIPXXE=implemented

        if args.interactive and args.json:
            raise argparse.ArgumentError(None, "--interactive cannot be used together with --json")

        self.use_json = args.json
        self.ptjsonlib = ptjsonlib
        self.already_enumerated = None
        self._enum_progress_print_lock = threading.Lock()
        self._enum_clock_thread: threading.Thread | None = None
        self._enum_clock_stop = threading.Event()
        self._enum_clock_state: dict[str, int | str] | None = None
        # Line-buffer / write-through stdout so enum progress is not held until block ends
        if not self.use_json and hasattr(sys.stdout, "reconfigure"):
            try:
                sys.stdout.reconfigure(line_buffering=True, write_through=True)
            except (OSError, ValueError, AttributeError):
                pass

        self.rate_limit_is_error = None
        self.is_slow_down = None
        self.fqdn = "example.com" if not args.fqdn else args.fqdn

        # Enumeration / -rl / -ae recipient or candidate names: -U file and/or -u list.
        raw: list[str] = []
        if _smtp_users_file_supplies_name_list(args):
            raw = list(filter(lambda x: x != "", text_or_file(None, args.users)))
        if args.user is not None and (
            args.enumerate is not None
            or getattr(args, "auth_enum", False)
            or _rcpt_limit_active(args)
        ):
            raw.extend(x for x in text_or_file(args.user, None) if x != "")
        if raw:
            self.wordlist = [u for u in raw if self._is_valid_local_part(u.split("@")[0].strip())]
            self._wordlist_skipped = len(raw) - len(self.wordlist)
        else:
            self.wordlist = None
            self._wordlist_skipped = 0

        # Default port number: 465 for implicit TLS (--tls), 587 for STARTTLS, 25 otherwise
        if args.target.port == 0:
            if args.tls:
                args.target.port = 465
            elif getattr(args, "starttls", False):
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
        else:
            try:
                self.target_ip = socket.gethostbyname(self.target)
            except socket.gaierror:
                raise argparse.ArgumentError(
                    None, f"Cannot resolve domain name '{self.target}' to IP address"
                )

        self.args = args
        self._brute_stream_lock = threading.Lock()
        self.results: SMTPResults

    def _is_run_all_mode(self) -> bool:
        """True when only target is given (no test switches). Run all tests in sequence.

        Derived directly from the test registry (SMTP_TEST_DESTS for boolean tests,
        SMTP_VALUE_DESTS for value-carrying tests) so it never drifts from the set of
        available tests. Selection happens exclusively via -ts / the value modifiers.
        """
        if self.do_brute:
            return False
        if any(getattr(self.args, dest, False) for dest in SMTP_TEST_DESTS):
            return False
        if any(getattr(self.args, dest, None) is not None for dest in SMTP_VALUE_DESTS):
            return False
        return True

    def _fail(self, msg: str) -> None:
        """In run-all mode: raise TestFailedError. Otherwise: end_error + SystemExit."""
        if self.run_all_mode:
            raise TestFailedError(msg)
        self.ptjsonlib.end_error(msg, self.use_json)
        raise SystemExit

    def run(self):
        self.results = SMTPResults()
        smtp = None
        if getattr(self.args, "rl_no_precheck", False) and not _rcpt_limit_active(self.args):
            self.args.rcpt_limit = RCPT_LIMIT_DEFAULT_ATTEMPTS
        self.run_all_mode = self._is_run_all_mode()

        if self.run_all_mode:
            self._run_all_tests()
            return

        # Indirect scanning (blacklist: domain + public IP; private IP skipped with message)
        if self.args.blacklist_test:
            self.ptprint("Blacklist information", Out.INFO)
            bl_result, skipped_private = self.test_blacklist(self.target)
            if skipped_private:
                self.results.blacklist_private_ip_skipped = True
            elif bl_result is not None:
                self.results.blacklist = bl_result
            self._stream_blacklist_result()

        if self.args.spf_test:
            self.ptprint("SPF records", Out.INFO)
            if self.target_is_ip:
                self.results.spf_requires_domain = True
            else:
                try:
                    self.results.spf_records = self._get_nameservers(self.target)
                except SystemExit:
                    raise
                except Exception as e:
                    self.ptjsonlib.end_error(f"Error during SPF test: {e}", self.use_json)
                    raise SystemExit
            self._stream_spf_result()

        # Direct scanning
        # Only -iv (invalid-commands): no banner needed, test connects itself
        only_invalid_commands = (
            getattr(self.args, "invalid_commands", False)
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role_identify", False)
            and self.args.enumerate is None
            and not self.args.rate_limit
            and not getattr(self.args, "noop_flood1", False)
            and not getattr(self.args, "noop_flood2", None)
            and not _rcpt_limit_active(self.args)
            and getattr(self.args, "rcpt_duplicate", None) is None
            and not getattr(self.args, "probe_accepted_domain", False)
            and not self.do_brute
        )
        if only_invalid_commands:
            self.ptprint("Command Robustness Test", Out.INFO)
            try:
                self.results.inv_comm = self.test_invalid_commands()
                self._stream_inv_comm_result()
            except Exception as e:
                self.results.inv_comm_error = str(e)
                self._stream_inv_comm_result()
            return

        # Only -ho (helo-only): test if server supports EHLO extensions
        only_helo_only = (
            getattr(self.args, "helo_only", False)
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role_identify", False)
            and self.args.enumerate is None
            and not self.args.rate_limit
            and not getattr(self.args, "noop_flood1", False)
            and not getattr(self.args, "noop_flood2", None)
            and not _rcpt_limit_active(self.args)
            and getattr(self.args, "rcpt_duplicate", None) is None
            and not getattr(self.args, "probe_accepted_domain", False)
            and not self.do_brute
            and not getattr(self.args, "invalid_commands", False)
        )
        if only_helo_only:
            self.ptprint("HELO-only Test", Out.INFO)
            try:
                self.results.helo_only = self.test_helo_only()
                self._stream_helo_only_result()
            except Exception as e:
                self.results.helo_only_error = str(e)
                self._stream_helo_only_result()
            return

        # Only -hb (helo-bypass): test HELO/EHLO value for restriction bypass
        only_helo_bypass = (
            getattr(self.args, "helo_bypass", False)
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role_identify", False)
            and self.args.enumerate is None
            and not self.args.rate_limit
            and not getattr(self.args, "noop_flood1", False)
            and not getattr(self.args, "noop_flood2", None)
            and not _rcpt_limit_active(self.args)
            and getattr(self.args, "rcpt_duplicate", None) is None
            and not getattr(self.args, "probe_accepted_domain", False)
            and not self.do_brute
            and not getattr(self.args, "invalid_commands", False)
            and not getattr(self.args, "helo_only", False)
        )
        if only_helo_bypass:
            self.ptprint("HELO/EHLO Bypass Test", Out.INFO)
            try:
                self.results.helo_bypass = self.test_helo_bypass()
                self._stream_helo_bypass_result()
            except Exception as e:
                self.results.helo_bypass_error = str(e)
                self._stream_helo_bypass_result()
            return

        # Only -id / --id-aggressive: SMTP server software identification (--id-aggressive implies -id)
        only_identify = (
            (getattr(self.args, "identify", False) or getattr(self.args, "id_aggressive", False))
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role_identify", False)
            and self.args.enumerate is None
            and not self.args.rate_limit
            and not getattr(self.args, "noop_flood1", False)
            and not getattr(self.args, "noop_flood2", None)
            and not _rcpt_limit_active(self.args)
            and getattr(self.args, "rcpt_duplicate", None) is None
            and not getattr(self.args, "probe_accepted_domain", False)
            and not self.do_brute
            and not getattr(self.args, "invalid_commands", False)
            and not getattr(self.args, "helo_only", False)
            and not getattr(self.args, "helo_bypass", False)
            and not getattr(self.args, "auth_format", False)
        )
        if only_identify:
            self.ptprint("Service Fingerprinting", Out.INFO)
            try:
                self.results.identify = self.test_server_identify()
                self._stream_identify_result()
            except Exception as e:
                self.results.identify_error = str(e)
                self._stream_identify_result()
            return

        # Only -br (bounce-replay): test if server sends bounces to MAIL FROM without validation
        only_bounce_replay = (
            _bounce_replay_active(self.args)
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role_identify", False)
            and self.args.enumerate is None
            and not self.args.rate_limit
            and not getattr(self.args, "noop_flood1", False)
            and not getattr(self.args, "noop_flood2", None)
            and not _rcpt_limit_active(self.args)
            and getattr(self.args, "rcpt_duplicate", None) is None
            and not getattr(self.args, "probe_accepted_domain", False)
            and not getattr(self.args, "invalid_commands", False)
            and not getattr(self.args, "helo_only", False)
            and not getattr(self.args, "helo_bypass", False)
        )
        if only_bounce_replay:
            self.ptprint("Bounce Replay Test", Out.INFO)
            try:
                self.results.bounce_replay = self.test_bounce_replay()
                self._stream_bounce_replay_result()
            except Exception as e:
                self.results.bounce_replay_error = str(e)
                self._stream_bounce_replay_result()
            return

        # -bomb / -av / -ssrf / -flood / -zipxxe (any combination; fixed order BOMB → … → ZIPXXE)
        ts_ordered_tests: list[str] = []
        if getattr(self.args, "bomb", False):
            ts_ordered_tests.append("BOMB")
        if getattr(self.args, "antivirus", False):
            ts_ordered_tests.append("ANTIVIRUS")
        if getattr(self.args, "ssrf", False):
            ts_ordered_tests.append("SSRF")
        if getattr(self.args, "flood", False):
            ts_ordered_tests.append("FLOOD")
        if getattr(self.args, "zipxxe", False):
            ts_ordered_tests.append("ZIPXXE")
        only_standalone_ts_tests = (
            len(ts_ordered_tests) > 0
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role_identify", False)
            and self.args.enumerate is None
            and not self.args.rate_limit
            and not getattr(self.args, "noop_flood1", False)
            and not getattr(self.args, "noop_flood2", None)
            and not _rcpt_limit_active(self.args)
            and getattr(self.args, "rcpt_duplicate", None) is None
            and not getattr(self.args, "probe_accepted_domain", False)
            and not self.do_brute
            and not getattr(self.args, "invalid_commands", False)
            and not getattr(self.args, "helo_only", False)
            and not getattr(self.args, "helo_bypass", False)
            and not _bounce_replay_active(self.args)
        )
        if only_standalone_ts_tests:
            for test_name in ts_ordered_tests:
                if test_name == "BOMB":
                    self.ptprint("Mail Bomb / Rate Limiting Test", Out.INFO)
                    try:
                        self.results.mail_bomb = self.test_bomb()
                        self._stream_mail_bomb_result()
                    except Exception as e:
                        self.results.mail_bomb_error = str(e)
                        self._stream_mail_bomb_result()
                elif test_name == "ANTIVIRUS":
                    self.ptprint("Antivirus / Antispam Test", Out.INFO)
                    try:
                        self.results.antivirus = self.test_antivirus()
                        self._stream_antivirus_result()
                    except Exception as e:
                        self.results.antivirus_error = str(e)
                        self._stream_antivirus_result()
                elif test_name == "SSRF":
                    self.ptprint("SSRF Test – server fetches links in messages", Out.INFO)
                    try:
                        self.results.ssrf = self.test_ssrf()
                        self._stream_ssrf_result()
                    except Exception as e:
                        self.results.ssrf_error = str(e)
                        self._stream_ssrf_result()
                elif test_name == "FLOOD":
                    self.ptprint("Queue Flood Test", Out.INFO)
                    try:
                        self.results.flood = self.test_flood()
                        self._stream_flood_result()
                    except Exception as e:
                        self.results.flood_error = str(e)
                        self._stream_flood_result()
                elif test_name == "ZIPXXE":
                    self.ptprint("ZIPXXE Test – Zip Bomb, Billion Laughs, XXE", Out.INFO)
                    try:
                        self.results.zipxxe = self.test_zipxxe()
                        self._stream_zipxxe_result()
                    except Exception as e:
                        self.results.zipxxe_error = str(e)
                        self._stream_zipxxe_result()
            return

        # Standalone -sh: Header spoofing test
        only_spoof_headers = (
            getattr(self.args, "spoof_headers", False)
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role_identify", False)
            and self.args.enumerate is None
            and not self.args.rate_limit
            and not getattr(self.args, "noop_flood1", False)
            and not getattr(self.args, "noop_flood2", None)
            and not _rcpt_limit_active(self.args)
            and getattr(self.args, "rcpt_duplicate", None) is None
            and not getattr(self.args, "probe_accepted_domain", False)
            and not self.do_brute
            and not getattr(self.args, "invalid_commands", False)
            and not getattr(self.args, "helo_only", False)
            and not getattr(self.args, "helo_bypass", False)
            and not _bounce_replay_active(self.args)
            and not getattr(self.args, "bomb", False)
            and not getattr(self.args, "antivirus", False)
            and not getattr(self.args, "ssrf", False)
            and not getattr(self.args, "flood", False)
            and not getattr(self.args, "zipxxe", False)
            and not getattr(self.args, "bcc_test", False)
        )
        if only_spoof_headers:
            self.ptprint("Header Spoofing Test (From, Reply-To, Return-Path)", Out.INFO)
            try:
                self.results.spoof_header = self.test_spoof_headers()
                self._stream_spoof_header_result()
            except Exception as e:
                self.results.spoof_header_error = str(e)
                self._stream_spoof_header_result()
            return

        # Standalone -bcc: BCC disclosure test
        only_bcc_test = (
            getattr(self.args, "bcc_test", False)
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role_identify", False)
            and self.args.enumerate is None
            and not self.args.rate_limit
            and not getattr(self.args, "noop_flood1", False)
            and not getattr(self.args, "noop_flood2", None)
            and not _rcpt_limit_active(self.args)
            and getattr(self.args, "rcpt_duplicate", None) is None
            and not getattr(self.args, "probe_accepted_domain", False)
            and not self.do_brute
            and not getattr(self.args, "invalid_commands", False)
            and not getattr(self.args, "helo_only", False)
            and not getattr(self.args, "helo_bypass", False)
            and not _bounce_replay_active(self.args)
            and not getattr(self.args, "bomb", False)
            and not getattr(self.args, "antivirus", False)
            and not getattr(self.args, "ssrf", False)
            and not getattr(self.args, "flood", False)
            and not getattr(self.args, "zipxxe", False)
            and not getattr(self.args, "spoof_headers", False)
            and not getattr(self.args, "alias_test", False)
        )
        if only_bcc_test:
            self.ptprint("BCC Disclosure Test", Out.INFO)
            try:
                self.results.bcc_test = self.test_bcc()
                self._stream_bcc_result()
            except Exception as e:
                self.results.bcc_test_error = str(e)
                self._stream_bcc_result()
            return

        # Standalone -al: Alias & Addressing bypass test
        only_alias_test = (
            getattr(self.args, "alias_test", False)
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role_identify", False)
            and self.args.enumerate is None
            and not self.args.rate_limit
            and not getattr(self.args, "noop_flood1", False)
            and not getattr(self.args, "noop_flood2", None)
            and not _rcpt_limit_active(self.args)
            and getattr(self.args, "rcpt_duplicate", None) is None
            and not getattr(self.args, "probe_accepted_domain", False)
            and not self.do_brute
            and not getattr(self.args, "invalid_commands", False)
            and not getattr(self.args, "helo_only", False)
            and not getattr(self.args, "helo_bypass", False)
            and not _bounce_replay_active(self.args)
            and not getattr(self.args, "bomb", False)
            and not getattr(self.args, "antivirus", False)
            and not getattr(self.args, "ssrf", False)
            and not getattr(self.args, "flood", False)
            and not getattr(self.args, "zipxxe", False)
            and not getattr(self.args, "spoof_headers", False)
            and not getattr(self.args, "bcc_test", False)
        )
        if only_alias_test:
            self.ptprint("Alias & Addressing Bypass Test", Out.INFO)
            try:
                self.results.alias_test = self.test_alias()
                self._stream_alias_result()
            except Exception as e:
                self.results.alias_test_error = str(e)
                self._stream_alias_result()
            return

        # Only -ie: no need to connect; test_encryption() opens its own connections
        if (
            self.args.isencrypt
            and not self.args.interactive
            and not self.args.ntlm
            and not self.args.open_relay
            and self.args.enumerate is None
            and not self.args.rate_limit
            and not self.do_brute
            and getattr(self.args, "rcpt_duplicate", None) is None
        ):
            if not self.use_json:
                self.ptprint("Encryption", Out.INFO)
            self.results.encryption = self.test_encryption()
            self._stream_encryption_result()
            return

        # Standalone role only: no banner, just connect, EHLO and identify role
        only_role = (
            getattr(self.args, "role_identify", False)
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and self.args.enumerate is None
            and not self.args.rate_limit
            and not getattr(self.args, "noop_flood1", False)
            and not getattr(self.args, "noop_flood2", None)
            and not _rcpt_limit_active(self.args)
            and getattr(self.args, "rcpt_duplicate", None) is None
            and not getattr(self.args, "probe_accepted_domain", False)
            and not self.do_brute
        )
        if only_role:
            self.ptprint("Identified Role", Out.INFO)
            try:
                smtp, info = self.initial_info(get_commands=True)
                self.results.info = InfoResult(
                    info.banner,
                    info.ehlo,
                    getattr(info, "ehlo_starttls", None),
                )
                self.results.resolved_domain = self._get_domain_from_banner_or_ptr(self.results.info)
                self.results.banner_requested = False
                self.results.commands_requested = False
                self.results.role = self.test_role(smtp, info)
                self._stream_role_result()
            except TestFailedError as e:
                self.results.role_error = str(e)
                self._stream_role_result()
            except Exception as e:
                self.results.info_error = str(e)
            return

        # Standalone enumeration only: no banner, no initial_info, just this test
        only_enumerate = (
            self.args.enumerate is not None
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role_identify", False)
            and not self.args.rate_limit
            and not getattr(self.args, "noop_flood1", False)
            and not getattr(self.args, "noop_flood2", None)
            and not _rcpt_limit_active(self.args)
            and getattr(self.args, "rcpt_duplicate", None) is None
            and not getattr(self.args, "probe_accepted_domain", False)
            and not self.do_brute
        )
        if only_enumerate:
            self.ptprint("User Enumeration & Catch All mailbox", Out.INFO)
            try:
                smtp_enum, status, reply = self.connect(timeout=15.0)
                if status != 220:
                    raise Exception(self.bytes_to_str(reply) if reply else "Connect failed")
                banner = reply.decode()
                ehlo = None
                try:
                    _, ehlo_bytes = smtp_enum.ehlo(self.fqdn)
                    ehlo = ehlo_bytes.decode() if ehlo_bytes else None
                except Exception:
                    pass
                self.results.info = InfoResult(banner, ehlo, None)
                self.results.resolved_domain = self._get_domain_from_banner_or_ptr(self.results.info)
                self.results.banner_requested = False
                try:
                    self.results.catch_all = self.test_catchall(smtp_enum)
                except Exception:
                    self.results.catch_all = "indeterminate"
                self.results.enum_results = self.enumeration(smtp_enum)
                self._stream_enumeration_result()
            except Exception as e:
                self.results.info_error = str(e)
            return

        # Standalone commands or authentications (EHLO): -A and -c are aliases, same test
        only_commands_or_auth = (
            (self.args.commands or getattr(self.args, "authentications", False))
            and not self.args.banner
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role_identify", False)
            and self.args.enumerate is None
            and not self.args.rate_limit
            and not getattr(self.args, "noop_flood1", False)
            and not getattr(self.args, "noop_flood2", None)
            and not _rcpt_limit_active(self.args)
            and getattr(self.args, "rcpt_duplicate", None) is None
            and not getattr(self.args, "probe_accepted_domain", False)
            and not self.do_brute
        )
        if only_commands_or_auth:
            try:
                smtp, info = self.initial_info(get_commands=True)
                self.results.info = InfoResult(
                    None,
                    info.ehlo,
                    getattr(info, "ehlo_starttls", None),
                )
                self.results.banner_requested = False
                self.results.commands_requested = True
                self.results.authentications_requested = getattr(self.args, "authentications", False)
                self._stream_ehlo_result()
            except Exception as e:
                self.results.info_error = str(e)
            return

        # Standalone RCPT TO limit only: no banner, no other tests, just this test
        only_rcpt_limit = (
            _rcpt_limit_active(self.args)
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role_identify", False)
            and self.args.enumerate is None
            and not self.args.rate_limit
            and not getattr(self.args, "noop_flood1", False)
            and not getattr(self.args, "noop_flood2", None)
            and not getattr(self.args, "probe_accepted_domain", False)
            and not self.do_brute
            and getattr(self.args, "rcpt_duplicate", None) is None
        )
        if only_rcpt_limit:
            self.ptprint(self._rcpt_limit_section_title(), Out.INFO)
            try:
                self.results.rcpt_limit = self.test_rcpt_limit()
                self._stream_rcpt_limit_result()
            except TestFailedError as e:
                self.results.rcpt_limit_error = str(e)
                self._stream_rcpt_limit_result()
            except Exception as e:
                self.results.info_error = str(e)
            return

        # Standalone duplicate RCPT TO (-rdd): same envelope recipient N times in one MAIL
        only_rcpt_duplicate = (
            getattr(self.args, "rcpt_duplicate", None) is not None
            and not _rcpt_limit_active(self.args)
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role_identify", False)
            and self.args.enumerate is None
            and not self.args.rate_limit
            and not getattr(self.args, "noop_flood1", False)
            and not getattr(self.args, "noop_flood2", None)
            and not getattr(self.args, "probe_accepted_domain", False)
            and not self.do_brute
        )
        if only_rcpt_duplicate:
            self.ptprint("Duplicate RCPT TO (same recipient)", Out.INFO)
            try:
                self.results.rcpt_duplicate = self.test_rcpt_duplicate()
                self._stream_rcpt_duplicate_result()
            except TestFailedError as e:
                self.results.rcpt_duplicate_error = str(e)
                self._stream_rcpt_duplicate_result()
            except Exception as e:
                self.results.rcpt_duplicate_error = str(e)
                self._stream_rcpt_duplicate_result()
            return

        # Standalone accepted-domain probe only (informational; no PTv code)
        only_probe_accepted_domain = (
            getattr(self.args, "probe_accepted_domain", False)
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role_identify", False)
            and self.args.enumerate is None
            and not self.args.rate_limit
            and not getattr(self.args, "noop_flood1", False)
            and not getattr(self.args, "noop_flood2", None)
            and not _rcpt_limit_active(self.args)
            and not self.do_brute
        )
        if only_probe_accepted_domain:
            self.ptprint("Accepted recipient domain (probe)", Out.INFO)
            try:
                self.results.accepted_domain_probe = self.test_probe_accepted_domain()
                self._stream_accepted_domain_probe_result()
            except Exception as e:
                self.results.accepted_domain_probe_error = str(e)
                self._stream_accepted_domain_probe_result()
            return

        # Standalone interactive only: no banner output, just connect and start CLI
        only_interactive = (
            self.args.interactive
            and not self.args.banner
            and not self.args.commands
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role_identify", False)
            and self.args.enumerate is None
            and not self.args.rate_limit
            and not getattr(self.args, "noop_flood1", False)
            and not getattr(self.args, "noop_flood2", None)
            and not _rcpt_limit_active(self.args)
            and getattr(self.args, "rcpt_duplicate", None) is None
            and not getattr(self.args, "probe_accepted_domain", False)
            and not self.do_brute
        )
        if only_interactive and not self.use_json:
            try:
                smtp, _ = self.initial_info(get_commands=False)
                self.start_interactive_mode(smtp)
            except Exception as e:
                self.results.info_error = str(e)
            return

        # Standalone NTLM only: no banner output, just this test
        only_ntlm = (
            self.args.ntlm
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.open_relay
            and not getattr(self.args, "role_identify", False)
            and self.args.enumerate is None
            and not self.args.rate_limit
            and not getattr(self.args, "noop_flood1", False)
            and not getattr(self.args, "noop_flood2", None)
            and not _rcpt_limit_active(self.args)
            and getattr(self.args, "rcpt_duplicate", None) is None
            and not getattr(self.args, "probe_accepted_domain", False)
            and not self.do_brute
        )
        if only_ntlm:
            self.ptprint("NTLM information", Out.INFO)
            try:
                smtp, _ = self.initial_info(get_commands=False)
                self.results.ntlm = self.auth_ntlm(smtp)
                self._stream_ntlm_result()
            except Exception as e:
                self.results.info_error = str(e)
            return

        # Standalone open relay only: no banner output, just this test
        only_open_relay = (
            self.args.open_relay
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not getattr(self.args, "role_identify", False)
            and self.args.enumerate is None
            and not self.args.rate_limit
            and not getattr(self.args, "noop_flood1", False)
            and not getattr(self.args, "noop_flood2", None)
            and not _rcpt_limit_active(self.args)
            and getattr(self.args, "rcpt_duplicate", None) is None
            and not getattr(self.args, "probe_accepted_domain", False)
            and not self.do_brute
        )
        if only_open_relay:
            self.ptprint("Open relay", Out.INFO)
            try:
                smtp, _ = self.initial_info(get_commands=False)
                mail_from = self.args.mail_from or f"relaytest@{self.fqdn}"
                rcpt_to = self.args.rcpt_to or "relaytest@external.relaytest.local"
                self.results.open_relay = self.open_relay_test(smtp, mail_from, rcpt_to)
                self._stream_open_relay_result()
            except Exception as e:
                self.results.info_error = str(e)
            return

        # Standalone rate limit only: no banner, no initial_info, just this test
        only_rate_limit = (
            self.args.rate_limit
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role_identify", False)
            and self.args.enumerate is None
            and not getattr(self.args, "noop_flood1", False)
            and not getattr(self.args, "noop_flood2", None)
            and not _rcpt_limit_active(self.args)
            and getattr(self.args, "rcpt_duplicate", None) is None
            and not getattr(self.args, "probe_accepted_domain", False)
            and not self.do_brute
        )
        if only_rate_limit:
            self.ptprint("Rate limiting", Out.INFO)
            try:
                self.results.rate_limit = self.rate_limit_test()
                self._stream_rate_limit_result()
            except Exception as e:
                self.results.rate_limit_error = str(e)
                self._stream_rate_limit_result()
            return

        # Standalone NOOP flood, single connection (-ts NOOP1): single-connection NOOP spam.
        only_noop_flood1 = (
            getattr(self.args, "noop_flood1", False)
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role_identify", False)
            and self.args.enumerate is None
            and not self.args.rate_limit
            and not getattr(self.args, "noop_flood2", None)
            and not _rcpt_limit_active(self.args)
            and getattr(self.args, "rcpt_duplicate", None) is None
            and not getattr(self.args, "probe_accepted_domain", False)
            and not self.do_brute
        )
        if only_noop_flood1:
            self.ptprint(
                f"NOOP Flooding test ({NOOP_FLOOD1_MAX_COMMANDS} NOOPs in 1 connection)",
                Out.INFO,
            )
            try:
                self.results.noop_flood1 = self.noop_flood_test_single()
                self._stream_noop_flood1_result()
            except Exception as e:
                self.results.noop_flood1_error = str(e)
                self._stream_noop_flood1_result()
            return

        # Standalone NOOP flood 2 (-nf2): parallel-connection NOOP DoS.
        only_noop_flood2 = (
            getattr(self.args, "noop_flood2", None) is not None
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role_identify", False)
            and self.args.enumerate is None
            and not self.args.rate_limit
            and not getattr(self.args, "noop_flood1", False)
            and not _rcpt_limit_active(self.args)
            and getattr(self.args, "rcpt_duplicate", None) is None
            and not getattr(self.args, "probe_accepted_domain", False)
            and not self.do_brute
        )
        if only_noop_flood2:
            requested = self.args.noop_flood2 or NOOP_FLOOD2_DEFAULT_CONNECTIONS
            self.ptprint(
                f"NOOP Flooding DoS test ({requested} connections within "
                f"{int(NOOP_FLOOD2_RUN_SECONDS)} seconds)",
                Out.INFO,
            )
            try:
                self.results.noop_flood2 = self.noop_flood_test_parallel()
                self._stream_noop_flood2_result()
            except Exception as e:
                self.results.noop_flood2_error = str(e)
                self._stream_noop_flood2_result()
            return

        # Standalone AUTH LOGIN format probe only (PTL-SVC-SMTP-AUTH-FORMAT)
        only_auth_format = (
            getattr(self.args, "auth_format", False)
            and not getattr(self.args, "auth_enum", False)
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role_identify", False)
            and self.args.enumerate is None
            and not self.args.rate_limit
            and not getattr(self.args, "noop_flood1", False)
            and not getattr(self.args, "noop_flood2", None)
            and not _rcpt_limit_active(self.args)
            and getattr(self.args, "rcpt_duplicate", None) is None
            and not getattr(self.args, "probe_accepted_domain", False)
            and not self.do_brute
        )
        if only_auth_format:
            self.ptprint("AUTH LOGIN format detection", Out.INFO)
            try:
                self.results.auth_format = self.test_auth_format_probe()
                self._stream_auth_format_result()
            except Exception as e:
                self.results.auth_format_error = str(e)
                self._stream_auth_format_result()
            return

        # Standalone AUTH user enumeration only
        only_auth_enum = (
            getattr(self.args, "auth_enum", False)
            and not getattr(self.args, "auth_format", False)
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role_identify", False)
            and self.args.enumerate is None
            and not self.args.rate_limit
            and not getattr(self.args, "noop_flood1", False)
            and not getattr(self.args, "noop_flood2", None)
            and not _rcpt_limit_active(self.args)
            and getattr(self.args, "rcpt_duplicate", None) is None
            and not getattr(self.args, "probe_accepted_domain", False)
            and not self.do_brute
        )
        if only_auth_enum:
            self.ptprint("AUTH user enumeration", Out.INFO)
            try:
                self.results.auth_enum = self.test_auth_enum()
                self._stream_auth_enum_result()
            except Exception as e:
                self.results.auth_enum_error = str(e)
                self._stream_auth_enum_result()
            return

        # Standalone HELO/EHLO hostname validation only
        only_helo_validation = (
            getattr(self.args, "helo_validation", False)
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role_identify", False)
            and self.args.enumerate is None
            and not self.args.rate_limit
            and not getattr(self.args, "noop_flood1", False)
            and not getattr(self.args, "noop_flood2", None)
            and not _rcpt_limit_active(self.args)
            and getattr(self.args, "rcpt_duplicate", None) is None
            and not getattr(self.args, "probe_accepted_domain", False)
            and not self.do_brute
        )
        if only_helo_validation:
            self.ptprint("HELO/EHLO hostname validation", Out.INFO)
            try:
                self.results.helo_validation = self.test_helo_validation()
                self._stream_helo_validation_result()
            except Exception as e:
                self.results.helo_validation_error = str(e)
                self._stream_helo_validation_result()
            return

        # Standalone AUTH downgrade only
        only_auth_downgrade = (
            getattr(self.args, "auth_downgrade", False)
            and not self.args.banner
            and not self.args.commands
            and not self.args.interactive
            and not self.args.isencrypt
            and not self.args.ntlm
            and not self.args.open_relay
            and not getattr(self.args, "role_identify", False)
            and self.args.enumerate is None
            and not self.args.rate_limit
            and not getattr(self.args, "noop_flood1", False)
            and not getattr(self.args, "noop_flood2", None)
            and not _rcpt_limit_active(self.args)
            and getattr(self.args, "rcpt_duplicate", None) is None
            and not getattr(self.args, "probe_accepted_domain", False)
            and not self.do_brute
        )
        if only_auth_downgrade:
            self.ptprint("Authentication Downgrade Test", Out.INFO)
            try:
                self.results.auth_downgrade = self.test_auth_downgrade()
                self._stream_auth_downgrade_result()
            except Exception as e:
                self.results.auth_downgrade_error = str(e)
                self._stream_auth_downgrade_result()
            return

        # enter only if any of these arguments were explicitly specified
        need_info = (
            self.args.banner
            or self.args.commands
            or getattr(self.args, "authentications", False)
            or getattr(self.args, "auth_enum", False)
            or getattr(self.args, "auth_format", False)
            or getattr(self.args, "helo_validation", False)
            or getattr(self.args, "auth_downgrade", False)
            or getattr(self.args, "invalid_commands", False)
            or self.args.interactive
            or self.args.isencrypt
            or self.args.ntlm
            or self.args.open_relay
            or getattr(self.args, "role_identify", False)
            or self.args.enumerate is not None
            or self.args.rate_limit
            or _rcpt_limit_active(self.args)
            or getattr(self.args, "rcpt_duplicate", None) is not None
            or self.do_brute
        )
        if need_info:
            do_banner = self.args.banner
            do_role = getattr(self.args, "role_identify", False)
            do_commands = (
                self.args.commands
                or getattr(self.args, "authentications", False)
                or do_role
                or (self.args.enumerate is not None)
                or getattr(self.args, "helo_validation", False)
                or getattr(self.args, "auth_downgrade", False)
                or getattr(self.args, "invalid_commands", False)
                or (_rcpt_limit_active(self.args) and not getattr(self.args, "domain", None))
            )
            self.results.banner_requested = do_banner
            self.results.commands_requested = self.args.commands or getattr(self.args, "authentications", False)
            self.results.authentications_requested = getattr(self.args, "authentications", False)

            self.ptprint("Banner", Out.INFO)
            try:
                smtp, info = self.initial_info(get_commands=do_commands)
            except Exception as e:
                self.results.info_error = str(e)
                return
            self.results.info = InfoResult(
                info.banner if (do_banner or do_role) else None,
                info.ehlo if do_commands else None,
                getattr(info, "ehlo_starttls", None),
            )
            self.results.resolved_domain = self._get_domain_from_banner_or_ptr(self.results.info)
            self._stream_banner_result()
            if do_commands:
                self._stream_ehlo_result()

            if do_role:
                self.ptprint("Identified Role", Out.INFO)
                try:
                    self.results.role = self.test_role(smtp, info)
                except TestFailedError as e:
                    self.results.role_error = str(e)
                except Exception as e:
                    self.results.role_error = str(e)
                self._stream_role_result()

            if self.args.isencrypt:
                self.ptprint("Encryption", Out.INFO)
                self.results.encryption = self.test_encryption()
                self._stream_encryption_result()

            if self.args.interactive and not self.use_json:
                self.start_interactive_mode(smtp)

            if self.args.ntlm:
                self.ptprint("NTLM information", Out.INFO)
                self.results.ntlm = self.auth_ntlm(smtp)
                self._stream_ntlm_result()

            if getattr(self.args, "auth_format", False):
                self.ptprint("AUTH LOGIN format detection", Out.INFO)
                try:
                    self.results.auth_format = self.test_auth_format_probe()
                    self._stream_auth_format_result()
                except Exception as e:
                    self.results.auth_format_error = str(e)
                    self._stream_auth_format_result()

            if getattr(self.args, "auth_enum", False):
                self.ptprint("AUTH user enumeration", Out.INFO)
                try:
                    self.results.auth_enum = self.test_auth_enum()
                    self._stream_auth_enum_result()
                except Exception as e:
                    self.results.auth_enum_error = str(e)
                    self._stream_auth_enum_result()

            if getattr(self.args, "helo_validation", False):
                self.ptprint("HELO/EHLO hostname validation", Out.INFO)
                try:
                    self.results.helo_validation = self.test_helo_validation()
                    self._stream_helo_validation_result()
                except Exception as e:
                    self.results.helo_validation_error = str(e)
                    self._stream_helo_validation_result()

            if getattr(self.args, "auth_downgrade", False):
                self.ptprint("Authentication Downgrade Test", Out.INFO)
                try:
                    self.results.auth_downgrade = self.test_auth_downgrade()
                    self._stream_auth_downgrade_result()
                except Exception as e:
                    self.results.auth_downgrade_error = str(e)
                    self._stream_auth_downgrade_result()

            if getattr(self.args, "invalid_commands", False):
                self.ptprint("Command Robustness Test", Out.INFO)
                try:
                    self.results.inv_comm = self.test_invalid_commands()
                    self._stream_inv_comm_result()
                except Exception as e:
                    self.results.inv_comm_error = str(e)
                    self._stream_inv_comm_result()

            if getattr(self.args, "helo_bypass", False):
                self.ptprint("HELO/EHLO Bypass Test", Out.INFO)
                try:
                    self.results.helo_bypass = self.test_helo_bypass()
                    self._stream_helo_bypass_result()
                except Exception as e:
                    self.results.helo_bypass_error = str(e)
                    self._stream_helo_bypass_result()

            if self.args.open_relay:
                self.ptprint("Open relay", Out.INFO)
                self.results.open_relay = self.open_relay_test(
                    smtp, self.args.mail_from, self.args.rcpt_to
                )
                self._stream_open_relay_result()

            if self.args.enumerate is not None:
                self.ptprint("User Enumeration & Catch All mailbox", Out.INFO)
                smtp_enum = self.get_smtp_handler(timeout=15.0)
                smtp_enum.docmd("EHLO", self.fqdn)
                try:
                    self.results.catch_all = self.test_catchall(smtp_enum)
                except Exception:
                    self.results.catch_all = "indeterminate"
                self.results.enum_results = self.enumeration(smtp_enum)
                self._stream_enumeration_result()

            if self.args.rate_limit:
                self.ptprint("Rate limiting", Out.INFO)
                self.results.rate_limit = self.rate_limit_test()
                self._stream_rate_limit_result()

            if _rcpt_limit_active(self.args):
                self.ptprint(self._rcpt_limit_section_title(), Out.INFO)
                try:
                    self.results.rcpt_limit = self.test_rcpt_limit()
                except TestFailedError as e:
                    self.results.rcpt_limit_error = str(e)
                except Exception as e:
                    self.results.rcpt_limit_error = str(e)
                self._stream_rcpt_limit_result()

            if getattr(self.args, "rcpt_duplicate", None) is not None:
                self.ptprint("Duplicate RCPT TO (same recipient)", Out.INFO)
                try:
                    self.results.rcpt_duplicate = self.test_rcpt_duplicate()
                except TestFailedError as e:
                    self.results.rcpt_duplicate_error = str(e)
                except Exception as e:
                    self.results.rcpt_duplicate_error = str(e)
                self._stream_rcpt_duplicate_result()

            if self.do_brute:
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

    def _run_all_tests(self) -> None:
        """Run all tests in sequence. On failure: print error, continue with next.

        Excluded from run-all (use flags explicitly):
        - rate_limit (-rt): opens many connections simultaneously, triggers rate limits (421).
        - rcpt_limit (-rl): many RCPT TO probes per session; use -rl explicitly if needed.
        - rcpt_duplicate (-rdd): repeated RCPT TO for the same address; use -rdd explicitly if needed.
        - invalid_commands (-iv): high server load (fuzzing, long inputs, many connections).
          Use -iv flag explicitly if needed.
        """
        # 1. Banner + commands (plaintext connection, EHLO)
        self.results.banner_requested = True
        self.results.commands_requested = True
        self.ptprint("Banner", Out.INFO)
        try:
            smtp, info = self.initial_info(get_commands=True)
            self.results.info = info
        except TestFailedError as e:
            self.results.info_error = str(e)
            return
        except Exception as e:
            self.results.info_error = str(e)
            return
        self.results.resolved_domain = self._get_domain_from_banner_or_ptr(self.results.info)
        self._stream_banner_result()

        # Role identification (uses banner/EHLO data already collected)
        self.ptprint("Identified Role", Out.INFO)
        try:
            self.results.role = self.test_role(smtp, info)
        except TestFailedError as e:
            self.results.role_error = str(e)
        except Exception as e:
            self.results.role_error = str(e)
        self._stream_role_result()

        self._stream_ptr_domain()
        self._stream_ehlo_result()
        # 2. Encryption: on port 465 we connected via TLS, so set tls_ok=True.
        #    With --starttls we already upgraded, so starttls_ok=True (EHLO may omit STARTTLS after upgrade).
        #    On other ports: STARTTLS from EHLO if present.
        #    Full test_encryption() (all three modes) only with -ie flag.
        if self.args.target.port == 465:
            self.results.encryption = EncryptionResult(
                plaintext_ok=False, starttls_ok=False, tls_ok=True
            )
        elif self.args.starttls or (info.ehlo and "STARTTLS" in info.ehlo.upper()):
            self.results.encryption = EncryptionResult(
                plaintext_ok=True, starttls_ok=True, tls_ok=False
            )
        else:
            self.results.encryption = EncryptionResult(
                plaintext_ok=True, starttls_ok=False, tls_ok=False
            )
        self.ptprint("Encryption", Out.INFO)
        self._stream_encryption_result()

        # 3. Open relay (always in run-all; use defaults if mail_from/rcpt_to not set)
        self.ptprint("Open relay", Out.INFO)
        try:
            mail_from = self.args.mail_from or f"relaytest@{self.fqdn}"
            rcpt_to = self.args.rcpt_to or "relaytest@external.relaytest.local"
            self.results.open_relay = self.open_relay_test(smtp, mail_from, rcpt_to)
        except TestFailedError as e:
            self.results.open_relay_error = str(e)
        except Exception as e:
            self.results.open_relay_error = str(e)
        self._stream_open_relay_result()

        # 3b. HELO/EHLO hostname validation
        self.ptprint("HELO/EHLO hostname validation", Out.INFO)
        try:
            self.results.helo_validation = self.test_helo_validation()
        except TestFailedError as e:
            self.results.helo_validation_error = str(e)
        except Exception as e:
            self.results.helo_validation_error = str(e)
        self._stream_helo_validation_result()

        # 3c. AUTH downgrade
        self.ptprint("Authentication Downgrade", Out.INFO)
        try:
            self.results.auth_downgrade = self.test_auth_downgrade()
        except TestFailedError as e:
            self.results.auth_downgrade_error = str(e)
        except Exception as e:
            self.results.auth_downgrade_error = str(e)
        self._stream_auth_downgrade_result()

        # 4. Blacklist (domain + public IP; private IP skipped)
        self.ptprint("Blacklist information", Out.INFO)
        try:
            bl_result, skipped_private = self.test_blacklist(self.target)
            if skipped_private:
                self.results.blacklist_private_ip_skipped = True
            elif bl_result is not None:
                self.results.blacklist = bl_result
        except TestFailedError as e:
            self.results.blacklist_error = str(e)
        except Exception as e:
            self.results.blacklist_error = str(e)
        self._stream_blacklist_result()

        # 5. SPF (only if domain)
        self.ptprint("SPF records", Out.INFO)
        if self.target_is_ip:
            self.results.spf_requires_domain = True
        else:
            try:
                self.results.spf_records = self._get_nameservers(self.target)
            except TestFailedError as e:
                self.results.spf_error = str(e)
            except Exception as e:
                self.results.spf_error = str(e)
        self._stream_spf_result()

        # 6. User Enumeration & Catch All mailbox
        self.ptprint("User Enumeration & Catch All mailbox", Out.INFO)
        save_enum = self.args.enumerate
        try:
            self.args.enumerate = "ALL"
            smtp_enum = self.get_smtp_handler(timeout=15.0)
            smtp_enum.docmd("EHLO", self.fqdn)
            try:
                self.results.catch_all = self.test_catchall(smtp_enum)
            except Exception:
                self.results.catch_all = "indeterminate"
            self.results.enum_results = self.enumeration(smtp_enum)
        except TestFailedError as e:
            self.results.enum_error = str(e)
        except Exception as e:
            self.results.enum_error = str(e)
        finally:
            self.args.enumerate = save_enum
        self._stream_enumeration_result()

        # 7. NTLM
        self.ptprint("NTLM information", Out.INFO)
        try:
            self.results.ntlm = self.auth_ntlm(smtp)
        except TestFailedError as e:
            self.results.ntlm_error = str(e)
        except Exception as e:
            self.results.ntlm_error = str(e)
        self._stream_ntlm_result()

    _MAIL_RCPT_TRANSACTION_OK = (250, 251, 252)

    # RFC 5322 atext (atom text) + dot; RFC 6531 allows Unicode letters/digits in local part
    _ATEXT_ASCII = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+-/=?^_`{|}~.")

    AUTH_ENUM_PASSWORD = "PtSrv_Test_!@#_2026"
    AUTH_ENUM_METHOD_PROBE_ORDER = ("LOGIN", "PLAIN", "NTLM")

    # XOAUTH2 bogus token: syntactically correct Base64, semantically nonsense (user=admin\0auth=Bearer 1234567890\0\0)
    _AUTH_DOWNGRADE_BOGUS_XOAUTH2 = b64encode(b"user=admin\x00auth=Bearer 1234567890\x00\x00").decode()
