import ipaddress, random, secrets, smtplib, ssl, threading, time
from base64 import b64decode, b64encode

from ....ptntlmauth.ptntlmauth import get_NegotiateMessage_data, decode_ChallengeMessage_blob

try:
    from ntlm_auth.ntlm import NtlmContext
except ImportError:
    NtlmContext = None

from ..._base import Out
from ...utils import ptprinthelper
from ...utils.helpers import AUTH_ENUM_SYNTHETIC_INVALID_COUNT, auth_enum_candidate_names, auth_enum_ntlm_identity_note
from ...utils.progress import ThreadedProgress

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False

from ..helpers import *
from ..results import *
from ..registry import *


class AuthMixin:

    def _auth_enum_connect_aborted(self) -> str | None:
        return getattr(self, "_auth_enum_conn_abort", None)

    def _auth_enum_note_connect_abort(self, msg: str) -> None:
        lock = getattr(self, "_auth_enum_abort_lock", None)
        if lock is None:
            lock = threading.Lock()
            self._auth_enum_abort_lock = lock
        with lock:
            if self._auth_enum_conn_abort is None:
                self._auth_enum_conn_abort = msg

    def _get_smtp_for_auth_enum(self) -> tuple[smtplib.SMTP, str]:
        """
        Get SMTP connection; EHLO parsed for AUTH extensions (LOGIN / PLAIN / NTLM).
        On port 25/587: if plain EHLO lacks LOGIN, NTLM, and PLAIN but has STARTTLS, upgrade and re-EHLO.

        Uses non-fatal connect so threaded AUTH-ENUM workers never call ``end_error`` on
        transient failures (avoids duplicate error lines and premature ``os._exit``).
        """
        if abort := self._auth_enum_connect_aborted():
            raise ConnectionError(abort)
        try:
            smtp, status, reply = self.connect(timeout=15.0, fatal=False)
        except ConnectionError as e:
            self._auth_enum_note_connect_abort(str(e))
            raise
        if status != 220:
            msg = f"SMTP Info - [{status}] {self.bytes_to_str(reply)}"
            self._auth_enum_note_connect_abort(msg)
            raise ConnectionError(msg)
        _, ehlo_bytes = smtp.ehlo(self.fqdn)
        ehlo = ehlo_bytes.decode() if ehlo_bytes else ""

        auth_methods = _get_auth_methods_from_ehlo(ehlo)
        needs_starttls = (
            "LOGIN" not in auth_methods
            and "NTLM" not in auth_methods
            and "PLAIN" not in auth_methods
            and "STARTTLS" in ehlo.upper()
            and self.args.target.port != 465
            and not self.args.tls
            and not self.args.starttls
        )
        if needs_starttls:
            status, _ = smtp.docmd("STARTTLS")
            if status == 220:
                ctx = ssl._create_unverified_context()
                try:
                    _is_ip = ipaddress.ip_address(self.args.target.ip)
                    server_hostname = None
                except ValueError:
                    server_hostname = self.args.target.ip
                sock_ssl = ctx.wrap_socket(smtp.sock, server_hostname=server_hostname)
                smtp.sock = sock_ssl
                smtp.file = None
                smtp.helo_resp = None
                smtp.ehlo_resp = None
                smtp.esmtp_features = {}
                smtp.does_esmtp = False
                _, ehlo_bytes = smtp.ehlo(self.fqdn)
                ehlo = ehlo_bytes.decode() if ehlo_bytes else ""
                if self.args.debug and not getattr(self, "_auth_enum_dbg_logged_starttls", False):
                    self.ptdebug(
                        "AUTH-ENUM: STARTTLS applied (LOGIN/PLAIN/NTLM was not advertised on plain EHLO); "
                        "subsequent AUTH probes use TLS",
                    )
                    self._auth_enum_dbg_logged_starttls = True

        return smtp, ehlo

    def _auth_enum_reply_snip(self, resp: bytes | str | None, limit: int = 96) -> str:
        """Short one-line SMTP reply for -vv AUTH-ENUM tracing (avoids dumping huge blobs)."""
        if resp is None:
            return ""
        raw = resp if isinstance(resp, str) else self.bytes_to_str(resp)
        s = raw.replace("\r\n", " ").replace("\r", " ").replace("\n", " ").strip()
        if len(s) > limit:
            return s[: limit - 3] + "..."
        return s

    def _auth_enum_show_live_progress(self) -> bool:
        """Same TTY live line as ``-e`` enumeration: disabled for JSON and for ``--threads`` > 1."""
        return not self.use_json and int(getattr(self.args, "enum_threads", 1) or 1) <= 1

    @staticmethod
    def _auth_enum_progress_label(user: str) -> str:
        u = (user or "").strip()
        if len(u) > 48:
            return u[:45] + "..."
        return u or "…"

    def _auth_enum_progress_session_begin(self) -> None:
        if not self._auth_enum_show_live_progress():
            return
        self._enum_progress_line_dirty = False
        self._enum_progress_start = time.time()

    def _auth_enum_progress_session_end(self) -> None:
        if not self._auth_enum_show_live_progress():
            return
        self._enum_progress_newline()
        self._enum_clock_shutdown()

    def _auth_enum_progress_step(self, step: int, total: int, label: str) -> None:
        if not self._auth_enum_show_live_progress() or total <= 0:
            return
        self._enum_wait_begin(step, total, label)

    def _auth_enum_progress_step_done(self) -> None:
        if not self._auth_enum_show_live_progress():
            return
        self._enum_wait_end()

    def _auth_enum_probe_login_user(self, user: str) -> str | None:
        """One connection: AUTH LOGIN → user → wrong password; return stage signature or None."""
        conn = None
        try:
            conn, _ = self._get_smtp_for_auth_enum()
            code, resp = conn.docmd("AUTH", "LOGIN")
            self.ptdebug(
                f"AUTH-ENUM probe {user!r}: AUTH LOGIN → {code} {self._auth_enum_reply_snip(resp)!r}",
            )
            if code != 334:
                return None
            code, resp = conn.docmd(b64encode(user.encode()).decode())
            self.ptdebug(
                f"AUTH-ENUM probe {user!r}: after username (b64) → {code} {self._auth_enum_reply_snip(resp)!r}",
            )
            if code >= 500:
                return _auth_enum_login_stage_signature("u", code, resp, self.bytes_to_str)
            if code == 334:
                code, resp = conn.docmd(b64encode(self.AUTH_ENUM_PASSWORD.encode()).decode())
                self.ptdebug(
                    f"AUTH-ENUM probe {user!r}: after password (fixed wrong) → {code} "
                    f"{self._auth_enum_reply_snip(resp)!r}",
                )
                if code >= 500:
                    return _auth_enum_login_stage_signature("p", code, resp, self.bytes_to_str)
            return None
        except Exception:
            return None
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def _auth_enum_probe_ntlm_user(self, user: str) -> str | None:
        """One connection: AUTH NTLM negotiate → user + wrong password; return 'code line' or None."""
        if NtlmContext is None:
            return None
        conn = None
        try:
            conn, _ = self._get_smtp_for_auth_enum()
            code, resp = conn.docmd("AUTH", "NTLM")
            self.ptdebug(f"AUTH-ENUM NTLM probe {user!r}: AUTH NTLM → {code} {self._auth_enum_reply_snip(resp)!r}")
            if code != 334:
                return None
            conn.send(b64encode(get_NegotiateMessage_data()) + smtplib.bCRLF)
            code, resp = conn.getreply()
            self.ptdebug(
                f"AUTH-ENUM NTLM probe {user!r}: after negotiate blob → {code} {self._auth_enum_reply_snip(resp)!r}",
            )
            if code != 334:
                return None
            ctx = NtlmContext(user, self.AUTH_ENUM_PASSWORD)
            type3 = ctx.step(b64decode(resp))
            conn.send(b64encode(type3) + smtplib.bCRLF)
            code, resp = conn.getreply()
            self.ptdebug(
                f"AUTH-ENUM NTLM probe {user!r}: after Type 3 (wrong password) → {code} "
                f"{self._auth_enum_reply_snip(resp)!r}",
            )
            if code >= 500:
                txt = self.bytes_to_str(resp).strip()
                return f"{code} {txt}" if txt else str(code)
            return None
        except Exception:
            return None
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def _auth_enum_plain_exchange(self, conn: smtplib.SMTP, user: str, password: str) -> tuple[int, bytes]:
        """
        RFC 4616 PLAIN + RFC 4954 SMTP AUTH: send initial-response ``AUTH PLAIN <base64>``;
        on 334 continuation, send the same base64 line (some servers omit initial-response path).
        """
        init = _auth_enum_plain_initial_b64(user, password)
        code, resp = conn.docmd("AUTH", f"PLAIN {init}")
        if code == 334:
            code, resp = conn.docmd(init)
        return code, resp

    def _auth_enum_probe_plain_user(self, user: str) -> str | None:
        """One connection: AUTH PLAIN with wrong password; compare final SMTP line vs invalid baseline (RFC 4616)."""
        conn = None
        try:
            conn, _ = self._get_smtp_for_auth_enum()
            code, resp = self._auth_enum_plain_exchange(conn, user, self.AUTH_ENUM_PASSWORD)
            self.ptdebug(
                f"AUTH-ENUM PLAIN probe {user!r}: after PLAIN exchange → {code} "
                f"{self._auth_enum_reply_snip(resp)!r}",
            )
            if code >= 500:
                txt = self.bytes_to_str(resp).strip()
                return f"{code} {txt}" if txt else str(code)
            return None
        except Exception:
            return None
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    @staticmethod
    def _auth_enum_synthetic_invalid_names() -> list[str]:
        return [
            f"enumtest_invalid_{random.getrandbits(32):08x}"
            for _ in range(AUTH_ENUM_SYNTHETIC_INVALID_COUNT)
        ]

    def _auth_enum_methods_to_test(self, auth_methods: set[str]) -> list[str]:
        return [m for m in self.AUTH_ENUM_METHOD_PROBE_ORDER if m in auth_methods]

    @staticmethod
    def _auth_enum_login_postprocess(
        invalid_responses: list[str],
        candidate_sigs: list[str | None],
        candidates: list[str],
    ) -> tuple[bool, list[str]]:
        """Compute LOGIN enumeration result from collected signatures.

        Returns ``(effective_protocol_flow_vuln, enumerated_list)``:

        * baseline (invalid) users rejected with 5xx at the username stage
          (``LOGIN:u:``) is only a real oracle if at least one candidate is NOT
          rejected there (i.e. passes to the password stage → likely valid).
        * a candidate is enumerated when its signature differs from the invalid
          baseline OR it passed the username gate while invalid users did not.
        """
        inv_set = set(invalid_responses)
        baseline_gate_reject = any(s and s.startswith("LOGIN:u:") for s in invalid_responses)
        enumerated: list[str] = []
        gate_passed_count = 0
        for cand, sig in zip(candidates, candidate_sigs):
            differs = bool(sig and inv_set and sig not in inv_set)
            passed_gate = bool(baseline_gate_reject and sig and not sig.startswith("LOGIN:u:"))
            if passed_gate:
                gate_passed_count += 1
            if differs or passed_gate:
                enumerated.append(cand)
        effective_proto = baseline_gate_reject and gate_passed_count > 0
        return effective_proto, enumerated

    def _auth_enum_finalize_method_result(
        self,
        method: str,
        *,
        invalid_responses: list[str],
        protocol_flow_vuln: bool,
        enumerated_list: list[str],
        candidates: list[str],
        any_candidate_sig: bool,
        valid_response: str | None,
    ) -> AuthEnumResult:
        response_differs = len(enumerated_list) > 0
        vulnerable = protocol_flow_vuln or response_differs
        detail: str | None = None
        if protocol_flow_vuln:
            detail = "Server responds 5xx after username (before password challenge)"
        elif response_differs:
            detail = (
                f"Different responses vs synthetic invalid baseline; "
                f"examples: {invalid_responses[:1]} vs {valid_response}"
            )

        if not invalid_responses and not protocol_flow_vuln:
            return AuthEnumResult(
                vulnerable=False,
                indeterminate=True,
                method_tested=method,
                protocol_flow_vuln=False,
                invalid_user_responses=[],
                valid_user_response=None,
                enumerated_users=(),
                detail="Could not obtain AUTH baseline from two synthetic invalid users",
            )
        if not vulnerable and candidates and not any_candidate_sig:
            return AuthEnumResult(
                vulnerable=False,
                indeterminate=True,
                method_tested=method,
                protocol_flow_vuln=False,
                invalid_user_responses=invalid_responses,
                valid_user_response=valid_response,
                enumerated_users=(),
                detail="No comparable AUTH responses for candidate names",
            )

        self.ptdebug(
            f"AUTH-ENUM {method}: summary vulnerable={vulnerable} "
            f"protocol_flow_vuln={protocol_flow_vuln} response_differs={response_differs} "
            f"enumerated={list(enumerated_list)!r} first_candidate_signature={valid_response!r}",
        )
        return AuthEnumResult(
            vulnerable=vulnerable,
            indeterminate=False,
            method_tested=method,
            protocol_flow_vuln=protocol_flow_vuln,
            invalid_user_responses=invalid_responses,
            valid_user_response=valid_response,
            enumerated_users=tuple(enumerated_list),
            detail=detail,
        )

    def _auth_enum_aggregate_results(self, method_results: list[AuthEnumResult]) -> AuthEnumResult:
        if not method_results:
            return AuthEnumResult(
                vulnerable=False,
                indeterminate=True,
                method_tested="",
                protocol_flow_vuln=False,
                invalid_user_responses=[],
                valid_user_response=None,
                enumerated_users=(),
                detail="No AUTH enumeration probes were run",
            )
        if len(method_results) == 1:
            return method_results[0]

        methods_tested = ",".join(r.method_tested for r in method_results if r.method_tested)
        enumerated: list[str] = []
        seen_enum: set[str] = set()
        for r in method_results:
            for u in r.enumerated_users:
                if u not in seen_enum:
                    seen_enum.add(u)
                    enumerated.append(u)

        if any(r.vulnerable for r in method_results):
            detail_parts = [
                f"{r.method_tested}: {r.detail}"
                for r in method_results
                if r.vulnerable and r.detail
            ]
            return AuthEnumResult(
                vulnerable=True,
                indeterminate=False,
                method_tested=methods_tested,
                protocol_flow_vuln=any(r.protocol_flow_vuln for r in method_results),
                invalid_user_responses=[],
                valid_user_response=None,
                enumerated_users=tuple(enumerated),
                detail="; ".join(detail_parts) if detail_parts else "User enumeration via one or more AUTH mechanisms",
            )

        if all(r.indeterminate for r in method_results):
            detail_parts = [r.detail for r in method_results if r.detail]
            return AuthEnumResult(
                vulnerable=False,
                indeterminate=True,
                method_tested=methods_tested,
                protocol_flow_vuln=False,
                invalid_user_responses=[],
                valid_user_response=None,
                enumerated_users=(),
                detail="; ".join(detail_parts) if detail_parts else "Indeterminate",
            )

        return AuthEnumResult(
            vulnerable=False,
            indeterminate=False,
            method_tested=methods_tested,
            protocol_flow_vuln=False,
            invalid_user_responses=[],
            valid_user_response=None,
            enumerated_users=(),
            detail=None,
        )

    def _auth_enum_progress_run_step(self, total: int, label: str) -> None:
        counter = getattr(self, "_auth_enum_progress_counter", 0) + 1
        self._auth_enum_progress_counter = counter
        self._auth_enum_progress_step(counter, total, label)

    def _auth_enum_test_login_method(
        self,
        candidates: list[str],
        invalid_users: list[str],
        *,
        progress_total: int,
    ) -> AuthEnumResult:
        invalid_responses: list[str] = []
        protocol_flow_vuln = False
        enumerated_list: list[str] = []
        valid_response: str | None = None
        any_candidate_sig = False

        self.ptdebug(f"AUTH-ENUM: LOGIN — synthetic baseline: {invalid_users!r}")
        for inv_user in invalid_users:
            self._auth_enum_progress_run_step(progress_total, self._auth_enum_progress_label(inv_user))
            try:
                r = self._auth_enum_probe_login_user(inv_user)
                self.ptdebug(f"AUTH-ENUM baseline {inv_user!r}: signature={r!r}")
                if r:
                    invalid_responses.append(r)
            finally:
                self._auth_enum_progress_step_done()

        inv_normalized = set(invalid_responses) if invalid_responses else set()
        self.ptdebug(
            f"AUTH-ENUM: baseline comparison set ({len(inv_normalized)}): {sorted(inv_normalized)!r}",
        )
        candidate_sigs: list[str | None] = []
        for i, cand in enumerate(candidates):
            self._auth_enum_progress_run_step(progress_total, self._auth_enum_progress_label(cand))
            try:
                r = self._auth_enum_probe_login_user(cand)
                candidate_sigs.append(r)
                self.ptdebug(f"AUTH-ENUM candidate[{i}] {cand!r}: signature={r!r}")
                if i == 0:
                    valid_response = r
                if r is not None:
                    any_candidate_sig = True
            finally:
                self._auth_enum_progress_step_done()

        protocol_flow_vuln, enumerated_list = self._auth_enum_login_postprocess(
            invalid_responses, candidate_sigs, candidates,
        )
        self.ptdebug(
            f"AUTH-ENUM: LOGIN effective protocol_flow_vuln={protocol_flow_vuln}; "
            f"enumerated={enumerated_list!r}",
        )

        return self._auth_enum_finalize_method_result(
            "LOGIN",
            invalid_responses=invalid_responses,
            protocol_flow_vuln=protocol_flow_vuln,
            enumerated_list=enumerated_list,
            candidates=candidates,
            any_candidate_sig=any_candidate_sig,
            valid_response=valid_response,
        )

    def _auth_enum_test_plain_method(
        self,
        candidates: list[str],
        invalid_users: list[str],
        *,
        progress_total: int,
    ) -> AuthEnumResult:
        invalid_responses: list[str] = []
        enumerated_list: list[str] = []
        valid_response: str | None = None
        any_candidate_sig = False

        self.ptdebug(f"AUTH-ENUM: PLAIN (RFC 4616) — synthetic baseline: {invalid_users!r}")
        for inv_user in invalid_users:
            self._auth_enum_progress_run_step(progress_total, self._auth_enum_progress_label(inv_user))
            try:
                r = self._auth_enum_probe_plain_user(inv_user)
                self.ptdebug(f"AUTH-ENUM PLAIN baseline {inv_user!r}: line={r!r}")
                if r:
                    invalid_responses.append(r)
            finally:
                self._auth_enum_progress_step_done()

        inv_normalized = (
            {_normalize_auth_response_for_comparison(r) for r in invalid_responses}
            if invalid_responses
            else set()
        )
        self.ptdebug(
            f"AUTH-ENUM: PLAIN baseline normalized set ({len(inv_normalized)}): {sorted(inv_normalized)!r}",
        )
        for i, cand in enumerate(candidates):
            self._auth_enum_progress_run_step(progress_total, self._auth_enum_progress_label(cand))
            try:
                r = self._auth_enum_probe_plain_user(cand)
                differs = bool(
                    r
                    and inv_normalized
                    and _normalize_auth_response_for_comparison(r) not in inv_normalized
                )
                self.ptdebug(
                    f"AUTH-ENUM PLAIN candidate[{i}] {cand!r}: line={r!r}; differs_from_baseline={differs}",
                )
                if i == 0:
                    valid_response = r
                if r is not None:
                    any_candidate_sig = True
                if r and inv_normalized and _normalize_auth_response_for_comparison(r) not in inv_normalized:
                    enumerated_list.append(cand)
            finally:
                self._auth_enum_progress_step_done()

        return self._auth_enum_finalize_method_result(
            "PLAIN",
            invalid_responses=invalid_responses,
            protocol_flow_vuln=False,
            enumerated_list=enumerated_list,
            candidates=candidates,
            any_candidate_sig=any_candidate_sig,
            valid_response=valid_response,
        )

    def _auth_enum_test_ntlm_method(
        self,
        candidates: list[str],
        invalid_users: list[str],
        *,
        progress_total: int,
    ) -> AuthEnumResult:
        if NtlmContext is None:
            return AuthEnumResult(
                vulnerable=False,
                indeterminate=True,
                method_tested="NTLM",
                protocol_flow_vuln=False,
                invalid_user_responses=[],
                valid_user_response=None,
                enumerated_users=(),
                detail="NTLM test requires ntlm-auth package",
            )

        def _norm_line(code: int, resp: bytes) -> str:
            txt = self.bytes_to_str(resp).strip()
            return f"{code} {txt}" if txt else str(code)

        invalid_responses: list[str] = []
        enumerated_list: list[str] = []
        valid_response: str | None = None
        any_candidate_sig = False

        self.ptdebug(f"AUTH-ENUM: NTLM — invalid baseline identities: {invalid_users!r}")
        for inv_user in invalid_users:
            self._auth_enum_progress_run_step(progress_total, self._auth_enum_progress_label(inv_user))
            try:
                try:
                    conn, _ = self._get_smtp_for_auth_enum()
                    code, resp = conn.docmd("AUTH", "NTLM")
                    if code != 334:
                        self.ptdebug(
                            f"AUTH-ENUM NTLM baseline {inv_user!r}: AUTH NTLM → {code} "
                            f"{self._auth_enum_reply_snip(resp)!r} (skip)",
                        )
                        try:
                            conn.close()
                        except Exception:
                            pass
                        continue
                    conn.send(b64encode(get_NegotiateMessage_data()) + smtplib.bCRLF)
                    code, resp = conn.getreply()
                    if code != 334:
                        self.ptdebug(
                            f"AUTH-ENUM NTLM baseline {inv_user!r}: after negotiate → {code} "
                            f"{self._auth_enum_reply_snip(resp)!r} (skip)",
                        )
                        try:
                            conn.close()
                        except Exception:
                            pass
                        continue
                    ctx = NtlmContext(inv_user, self.AUTH_ENUM_PASSWORD)
                    type3 = ctx.step(b64decode(resp))
                    conn.send(b64encode(type3) + smtplib.bCRLF)
                    code, resp = conn.getreply()
                    if code >= 500:
                        invalid_responses.append(_norm_line(code, resp))
                        self.ptdebug(
                            f"AUTH-ENUM NTLM baseline {inv_user!r}: after Type 3 → {code} "
                            f"{self._auth_enum_reply_snip(resp)!r}",
                        )
                    try:
                        conn.close()
                    except Exception:
                        pass
                except Exception as ex:
                    self.ptdebug(f"AUTH-ENUM NTLM baseline {inv_user!r}: exception {type(ex).__name__}: {ex}")
            finally:
                self._auth_enum_progress_step_done()

        inv_normalized = (
            {_normalize_auth_response_for_comparison(r) for r in invalid_responses}
            if invalid_responses
            else set()
        )
        self.ptdebug(
            f"AUTH-ENUM: NTLM baseline normalized set ({len(inv_normalized)}): {sorted(inv_normalized)!r}",
        )
        for i, cand in enumerate(candidates):
            self._auth_enum_progress_run_step(progress_total, self._auth_enum_progress_label(cand))
            try:
                r = self._auth_enum_probe_ntlm_user(cand)
                differs = bool(
                    r
                    and inv_normalized
                    and _normalize_auth_response_for_comparison(r) not in inv_normalized
                )
                self.ptdebug(
                    f"AUTH-ENUM NTLM candidate[{i}] {cand!r}: line={r!r}; differs_from_baseline={differs}",
                )
                if i == 0:
                    valid_response = r
                if r is not None:
                    any_candidate_sig = True
                if r and inv_normalized and _normalize_auth_response_for_comparison(r) not in inv_normalized:
                    enumerated_list.append(cand)
            finally:
                self._auth_enum_progress_step_done()

        return self._auth_enum_finalize_method_result(
            "NTLM",
            invalid_responses=invalid_responses,
            protocol_flow_vuln=False,
            enumerated_list=enumerated_list,
            candidates=candidates,
            any_candidate_sig=any_candidate_sig,
            valid_response=valid_response,
        )

    def _auth_enum_method_threaded(
        self,
        method: str,
        probe_fn,
        normalize,
        candidates: list[str],
        invalid_users: list[str],
        progress: ThreadedProgress,
        enum_threads: int,
    ) -> AuthEnumResult:
        """Probe one AUTH mechanism with -t worker threads (one fresh connection per probe).

        Baseline + candidate probes run in parallel (each opens its own connection, so there
        is no connection-reuse benefit to serialising them); the verdict is computed after all
        probes finish, identically to the sequential path.
        """
        is_login = method == "LOGIN"
        invalid_responses: list[str] = []
        cand_sigs: list[str | None] = [None] * len(candidates)
        lock = threading.Lock()

        items = [("b", -1, u) for u in invalid_users]
        items += [("c", i, u) for i, u in enumerate(candidates)]

        def work(item, _out) -> str:
            kind, idx, user = item
            if self._auth_enum_connect_aborted():
                return user
            try:
                sig = probe_fn(user)
            except Exception:
                sig = None
            with lock:
                if kind == "b":
                    if sig:
                        invalid_responses.append(sig)
                else:
                    cand_sigs[idx] = sig
            return user

        progress.run(items, work, enum_threads, finalize=False)

        valid_response = cand_sigs[0] if cand_sigs else None
        any_candidate_sig = any(s is not None for s in cand_sigs)

        if is_login:
            protocol_flow_vuln, enumerated_list = self._auth_enum_login_postprocess(
                invalid_responses, cand_sigs, candidates,
            )
        else:
            protocol_flow_vuln = False
            inv_normalized = (
                {normalize(r) for r in invalid_responses} if invalid_responses else set()
            )
            enumerated_list = []
            for i, cand in enumerate(candidates):
                r = cand_sigs[i]
                differs = bool(r and inv_normalized and normalize(r) not in inv_normalized)
                if differs:
                    enumerated_list.append(cand)
        self.ptdebug(
            f"AUTH-ENUM: {method} (threaded) protocol_flow_vuln={protocol_flow_vuln}; "
            f"enumerated={enumerated_list!r}",
        )

        return self._auth_enum_finalize_method_result(
            method,
            invalid_responses=invalid_responses,
            protocol_flow_vuln=protocol_flow_vuln,
            enumerated_list=enumerated_list,
            candidates=candidates,
            any_candidate_sig=any_candidate_sig,
            valid_response=valid_response,
        )

    def _auth_enum_run_methods_threaded(
        self,
        methods_to_test: list[str],
        candidates: list[str],
        invalid_users: list[str],
        per_method_steps: int,
        enum_threads: int,
    ) -> list[AuthEnumResult]:
        """Threaded (-t) variant of the AUTH-ENUM mechanism loop with one shared progress bar."""
        # Methods that actually issue probes (NTLM without ntlm-auth issues none).
        probe_methods = [
            m for m in methods_to_test if not (m == "NTLM" and NtlmContext is None)
        ]
        progress_total = per_method_steps * len(probe_methods)
        progress = ThreadedProgress(progress_total, enabled=not self.use_json)
        method_results: list[AuthEnumResult] = []
        try:
            for method in methods_to_test:
                self.ptdebug(f"AUTH-ENUM: starting mechanism {method} ({enum_threads} threads)")
                if method == "LOGIN":
                    method_results.append(
                        self._auth_enum_method_threaded(
                            "LOGIN", self._auth_enum_probe_login_user, lambda x: x,
                            candidates, invalid_users, progress, enum_threads,
                        ),
                    )
                elif method == "PLAIN":
                    method_results.append(
                        self._auth_enum_method_threaded(
                            "PLAIN", self._auth_enum_probe_plain_user,
                            _normalize_auth_response_for_comparison,
                            candidates, invalid_users, progress, enum_threads,
                        ),
                    )
                elif method == "NTLM":
                    if NtlmContext is None:
                        method_results.append(
                            AuthEnumResult(
                                vulnerable=False,
                                indeterminate=True,
                                method_tested="NTLM",
                                protocol_flow_vuln=False,
                                invalid_user_responses=[],
                                valid_user_response=None,
                                enumerated_users=(),
                                detail="NTLM test requires ntlm-auth package",
                            ),
                        )
                    else:
                        method_results.append(
                            self._auth_enum_method_threaded(
                                "NTLM", self._auth_enum_probe_ntlm_user,
                                _normalize_auth_response_for_comparison,
                                candidates, invalid_users, progress, enum_threads,
                            ),
                        )
        finally:
            progress.finalize()
        return method_results

    def test_auth_enum(self) -> AuthEnumResult:
        """
        AUTH user enumeration: for each advertised mechanism (LOGIN, PLAIN, NTLM), probe two
        synthetic invalid identities plus candidates from -u/-U or ``default_logins``.
        """
        self._auth_enum_dbg_logged_starttls = False
        self._auth_enum_conn_abort = None
        candidates, used_default_logins = auth_enum_candidate_names(
            self.args,
            wordlist=getattr(self, "wordlist", None),
        )
        invalid_users = self._auth_enum_synthetic_invalid_names()
        cand_src = "default_logins" if used_default_logins else "-u/-U"
        self.ptdebug(
            f"AUTH-ENUM: {len(candidates)} candidate(s) ({cand_src}); "
            f"synthetic baseline: {invalid_users!r}; "
            f"candidates={candidates if len(candidates) <= 12 else candidates[:12] + ['…']}",
        )

        def _store_and_return(
            method_results: list[AuthEnumResult],
            aggregate: AuthEnumResult,
        ) -> AuthEnumResult:
            self.results.auth_enum_methods = tuple(method_results)
            if any(r.method_tested == "NTLM" for r in method_results):
                self.results.auth_enum_ntlm_note = auth_enum_ntlm_identity_note(
                    used_default_logins,
                    candidates,
                )
            else:
                self.results.auth_enum_ntlm_note = None
            return aggregate

        try:
            _, ehlo = self._get_smtp_for_auth_enum()
        except Exception as e:
            self.ptdebug(f"AUTH-ENUM: aborted — initial connect/EHLO failed: {e!r}")
            err = AuthEnumResult(
                vulnerable=False,
                indeterminate=True,
                method_tested="",
                protocol_flow_vuln=False,
                invalid_user_responses=[],
                valid_user_response=None,
                enumerated_users=(),
                detail=str(e),
            )
            return _store_and_return([], err)

        auth_methods = _get_auth_methods_from_ehlo(ehlo)
        methods_to_test = self._auth_enum_methods_to_test(auth_methods)
        self.ptdebug(
            f"AUTH-ENUM: target {self.args.target.ip}:{self.args.target.port} fqdn={self.fqdn!r}; "
            f"AUTH from EHLO → {sorted(auth_methods)!r}; probe order → {methods_to_test!r}",
        )
        if not methods_to_test:
            self.ptdebug(
                "AUTH-ENUM: aborted — EHLO has no AUTH mechanism LOGIN, PLAIN or NTLM "
                "(after any STARTTLS upgrade inside probe)",
            )
            no_auth = AuthEnumResult(
                vulnerable=False,
                indeterminate=True,
                method_tested="",
                protocol_flow_vuln=False,
                invalid_user_responses=[],
                valid_user_response=None,
                enumerated_users=(),
                detail="Server does not advertise AUTH LOGIN, PLAIN or NTLM",
            )
            return _store_and_return([], no_auth)

        enum_threads = max(1, int(getattr(self.args, "enum_threads", 1) or 1))
        per_method_steps = len(invalid_users) + len(candidates)
        method_results: list[AuthEnumResult] = []

        if enum_threads > 1:
            method_results = self._auth_enum_run_methods_threaded(
                methods_to_test, candidates, invalid_users, per_method_steps, enum_threads,
            )
        else:
            progress_total = per_method_steps * len(methods_to_test)
            self._auth_enum_progress_counter = 0
            self._auth_enum_progress_session_begin()
            try:
                for method in methods_to_test:
                    self.ptdebug(f"AUTH-ENUM: starting mechanism {method}")
                    if method == "LOGIN":
                        method_results.append(
                            self._auth_enum_test_login_method(
                                candidates,
                                invalid_users,
                                progress_total=progress_total,
                            ),
                        )
                    elif method == "PLAIN":
                        method_results.append(
                            self._auth_enum_test_plain_method(
                                candidates,
                                invalid_users,
                                progress_total=progress_total,
                            ),
                        )
                    elif method == "NTLM":
                        method_results.append(
                            self._auth_enum_test_ntlm_method(
                                candidates,
                                invalid_users,
                                progress_total=progress_total,
                            ),
                        )
            finally:
                self._auth_enum_progress_session_end()

        if abort_msg := self._auth_enum_connect_aborted():
            self.results.auth_enum_error = abort_msg
            err = AuthEnumResult(
                vulnerable=False,
                indeterminate=True,
                method_tested="",
                protocol_flow_vuln=False,
                invalid_user_responses=[],
                valid_user_response=None,
                enumerated_users=(),
                detail=abort_msg,
            )
            return _store_and_return(method_results, err)

        aggregate = self._auth_enum_aggregate_results(method_results)
        self.ptdebug(
            f"AUTH-ENUM: aggregate vulnerable={aggregate.vulnerable} indeterminate={aggregate.indeterminate} "
            f"methods_tested={aggregate.method_tested!r} enumerated={list(aggregate.enumerated_users)!r}",
        )
        return _store_and_return(method_results, aggregate)

    @staticmethod
    def _auth_format_last_two_labels(fqdn: str) -> str | None:
        """Last two DNS labels (no PSL — UK/JP etc. often wrong for 'organizational' domain)."""
        parts = fqdn.strip().lower().rstrip(".").split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return None

    def _auth_format_resolve_target_domain(self, ehlo_text: str) -> AuthFormatTargetDomainDerivation:
        """
        Domain for probe B: from scan hostname or, if target is IP, from first EHLO hostname line.
        Documented limitation: not PSL-aware (mail.company.co.uk → co.uk).
        """
        raw = (self.args.target.ip or "").strip()
        host_l = raw.lower().rstrip(".")
        try:
            ipaddress.ip_address(host_l)
            is_ip = True
        except ValueError:
            is_ip = False

        if not is_ip:
            dom = self._auth_format_last_two_labels(host_l)
            if dom:
                note = (
                    f"Derived '{dom}' as last 2 labels from scan target {host_l!r} "
                    f"(not PSL-aware — e.g. mail.company.co.uk → co.uk; compare probe B vs C if unsure)."
                )
                return AuthFormatTargetDomainDerivation(dom, "scan_last2", note, None, host_l)
            return AuthFormatTargetDomainDerivation(
                None,
                "none",
                "Scan target is not a multi-label hostname; probe B skipped.",
                None,
                host_l or None,
            )

        eh = _get_hostname_from_ehlo_raw(ehlo_text)
        if not eh:
            return AuthFormatTargetDomainDerivation(
                None,
                "none",
                "Scan target is an IP and no suitable hostname on first EHLO line; probe B skipped.",
                None,
                None,
            )
        dom = self._auth_format_last_two_labels(eh)
        if not dom:
            return AuthFormatTargetDomainDerivation(
                None,
                "none",
                f"Scan target is an IP; EHLO hostname {eh!r} is not suitable for last-2 derivation; probe B skipped.",
                eh,
                None,
            )
        note = (
            f"Scan target is an IP; derived '{dom}' from EHLO hostname {eh!r} "
            f"(last 2 labels, not PSL-aware — EHLO may differ from connection target)."
        )
        return AuthFormatTargetDomainDerivation(dom, "ehlo_last2", note, eh, None)

    def _ntlm_netbios_domain_probe(self) -> str | None:
        """One-shot NTLM negotiate to read NetBIOS/DNS name from challenge (optional 4th probe)."""
        smtp = None
        try:
            smtp, ehlo = self._get_smtp_for_auth_enum()
            if "NTLM" not in _get_auth_methods_from_ehlo(ehlo):
                return None
            code, resp = smtp.docmd("AUTH", "NTLM")
            if code != 334:
                return None
            smtp.send(b64encode(get_NegotiateMessage_data()) + smtplib.bCRLF)
            code2, resp2 = smtp.getreply()
            if code2 != 334:
                return None
            info = decode_ChallengeMessage_blob(b64decode(resp2))
            return (info.netbios_domain or info.dns_domain or info.target_name or "").strip() or None
        except Exception:
            return None
        finally:
            if smtp:
                try:
                    smtp.close()
                except Exception:
                    pass

    def _probe_auth_login_identity(
        self, identity: str
    ) -> tuple[int | None, bool, int | None, str | None, bool, str | None]:
        """
        Fresh connection: AUTH LOGIN → optional challenge decode → base64 identity.
        Returns:
            code_after_identity, password_phase, code_after_password, reply_after_identity,
            rate_limited, challenge_decoded (from first 334 after AUTH LOGIN).
        """
        smtp = None
        ch_dec: str | None = None
        try:
            smtp, _ = self._get_smtp_for_auth_enum()
            code, resp = smtp.docmd("AUTH", "LOGIN")
            ch_dec = _auth_format_decode_login_challenge(resp)
            if code in (421, 450, 452):
                return None, False, None, self.bytes_to_str(resp), True, ch_dec
            if code != 334:
                return code, False, None, self.bytes_to_str(resp), False, ch_dec
            id_b64 = b64encode(identity.encode("utf-8")).decode("ascii")
            code_u, resp_u = smtp.docmd(id_b64)
            if code_u in (421, 450, 452):
                return None, False, None, self.bytes_to_str(resp_u), True, ch_dec
            if code_u == 334:
                pw_b64 = b64encode(secrets.token_bytes(16)).decode("ascii")
                code_p, resp_p = smtp.docmd(pw_b64)
                return code_u, True, code_p, self.bytes_to_str(resp_u), False, ch_dec
            return code_u, False, None, self.bytes_to_str(resp_u), code_u in (421, 450, 452), ch_dec
        finally:
            if smtp:
                try:
                    smtp.close()
                except Exception:
                    pass

    def test_auth_format_probe(self) -> AuthFormatProbeResult:
        """
        PTL-SVC-SMTP-AUTH-FORMAT: infer expected AUTH LOGIN identity shape using a few non-destructive probes.
        Each probe uses a fresh connection; ~1.5s delay between probes to reduce rate-limit risk.
        """
        probe_user = f"ptauthfmt_{secrets.token_hex(4)}"
        try:
            sm0, ehlo0 = self._get_smtp_for_auth_enum()
            try:
                sm0.close()
            except Exception:
                pass
        except Exception as e:
            return AuthFormatProbeResult(
                "",
                (),
                None,
                None,
                f"Connection failed: {e}",
                "error",
                None,
                None,
                False,
                True,
                str(e),
                "none",
                None,
                None,
                None,
            )

        auth_methods = _get_auth_methods_from_ehlo(ehlo0)
        if "LOGIN" not in auth_methods:
            return AuthFormatProbeResult(
                "",
                (),
                None,
                None,
                "Server does not advertise AUTH LOGIN",
                "no_login",
                None,
                None,
                False,
                True,
                None,
                "none",
                None,
                None,
                None,
            )

        td_info = self._auth_format_resolve_target_domain(ehlo0)
        target_domain = td_info.domain
        netbios_domain = self._ntlm_netbios_domain_probe()

        plan: list[tuple[str, str, str | None, str | None]] = [
            ("single_label", "Single label", probe_user, None),
            (
                "target_domain",
                "Target domain e-mail",
                f"{probe_user}@{target_domain}" if target_domain else None,
                None if target_domain else "Target domain unknown (use hostname target or N/A)",
            ),
            (
                "external_domain",
                f"External domain ({AUTH_FORMAT_EXTERNAL_SUFFIX})",
                f"{probe_user}@{AUTH_FORMAT_EXTERNAL_SUFFIX}",
                None,
            ),
            (
                "netbios",
                "NetBIOS (DOMAIN\\user)",
                f"{netbios_domain}\\{probe_user}" if netbios_domain else None,
                None if netbios_domain else "NTLM not advertised or domain not decoded",
            ),
        ]

        rows_out: list[AuthFormatProbeRow] = []
        challenge_decoded: str | None = None
        challenge_hint: str | None = None
        rate_glob = False
        first_probe = True

        for pid, label, ident, skip_reason in plan:
            if not first_probe:
                time.sleep(AUTH_FORMAT_PROBE_DELAY_SEC)
            first_probe = False
            if rate_glob:
                rows_out.append(
                    AuthFormatProbeRow(
                        probe_id=pid,
                        label=label,
                        identity=ident or "",
                        skipped=True,
                        skip_reason="Skipped (previous probe rate-limited)",
                        code_after_identity=None,
                        password_phase=False,
                        code_after_password=None,
                        reply_after_identity=None,
                        rate_limited=False,
                    )
                )
                continue
            if ident is None:
                rows_out.append(
                    AuthFormatProbeRow(
                        probe_id=pid,
                        label=label,
                        identity="",
                        skipped=True,
                        skip_reason=skip_reason or "Skipped",
                        code_after_identity=None,
                        password_phase=False,
                        code_after_password=None,
                        reply_after_identity=None,
                        rate_limited=False,
                    )
                )
                continue
            try:
                c_id, pwd_ph, c_pw, reply_id, rl, ch1 = self._probe_auth_login_identity(ident)
            except Exception as ex:
                rows_out.append(
                    AuthFormatProbeRow(
                        probe_id=pid,
                        label=label,
                        identity=ident,
                        skipped=False,
                        skip_reason=None,
                        code_after_identity=None,
                        password_phase=False,
                        code_after_password=None,
                        reply_after_identity=str(ex),
                        rate_limited=False,
                    )
                )
                continue
            if challenge_decoded is None and ch1:
                challenge_decoded = ch1
                challenge_hint = _auth_format_hint_from_challenge_text(ch1)
            if rl:
                rate_glob = True
            if c_pw is not None and c_pw in (421, 450, 452):
                rate_glob = True
            rows_out.append(
                AuthFormatProbeRow(
                    probe_id=pid,
                    label=label,
                    identity=ident,
                    skipped=False,
                    skip_reason=None,
                    code_after_identity=c_id,
                    password_phase=pwd_ph,
                    code_after_password=c_pw,
                    reply_after_identity=reply_id,
                    rate_limited=rl,
                )
            )

        sym_map = {r.probe_id: _auth_format_row_symbol(r) for r in rows_out}
        sym_a = sym_map.get("single_label", "?")
        sym_b = sym_map.get("target_domain", "skip")
        sym_c = sym_map.get("external_domain", "?")
        sym_d = sym_map.get("netbios", "skip")
        b_ran = any(r.probe_id == "target_domain" and not r.skipped for r in rows_out)
        d_ran = any(r.probe_id == "netbios" and not r.skipped for r in rows_out)

        if rate_glob:
            cid, msg = (
                "rate_limited",
                "Probe stopped early: server returned temporary failure (421/450/452) — possible rate limiting",
            )
        elif sym_a == "rate" or sym_b == "rate" or sym_c == "rate" or sym_d == "rate":
            cid, msg = (
                "rate_limited",
                "Temporary failure during probe (421/450/452) — possible rate limiting",
            )
            rate_glob = True
        else:
            cid, msg = _auth_format_conclude(
                sym_a, sym_b, sym_c, sym_d, b_ran, d_ran, challenge_hint
            )
            if challenge_hint and cid == "mixed_responses":
                msg = f"{msg} (LOGIN challenge hint: {challenge_hint})"

        indet = cid in ("error", "no_login", "rate_limited", "indeterminate_no_target_domain", "challenge_hint_only")
        return AuthFormatProbeResult(
            method_tested="LOGIN",
            rows=tuple(rows_out),
            challenge_decoded=challenge_decoded,
            challenge_hint=challenge_hint,
            conclusion=msg,
            conclusion_id=cid,
            target_domain_used=target_domain,
            netbios_domain_used=netbios_domain,
            rate_limited=rate_glob or sym_a == "rate" or sym_b == "rate" or sym_c == "rate" or sym_d == "rate",
            indeterminate=indet,
            detail=None,
            target_domain_source=td_info.source,
            target_domain_analyst_note=td_info.analyst_note,
            target_domain_ehlo_hostname=td_info.ehlo_hostname,
            target_domain_scan_hostname=td_info.scan_hostname,
        )

    def _get_smtp_for_auth_downgrade(self) -> tuple[smtplib.SMTP, str]:
        """
        Get SMTP connection with AUTH over TLS (STARTTLS or implicit).
        For port 25/587: upgrade via STARTTLS if not already encrypted.
        """
        smtp = self.get_smtp_handler()
        _, ehlo_bytes = smtp.ehlo(self.fqdn)
        ehlo = ehlo_bytes.decode() if ehlo_bytes else ""

        auth_methods = _get_auth_methods_from_ehlo(ehlo)
        needs_starttls = (
            "STARTTLS" in ehlo.upper()
            and self.args.target.port != 465
            and not self.args.tls
            and not self.args.starttls
        )
        if needs_starttls:
            status, _ = smtp.docmd("STARTTLS")
            if status == 220:
                ctx = ssl._create_unverified_context()
                try:
                    _is_ip = ipaddress.ip_address(self.args.target.ip)
                    server_hostname = None
                except ValueError:
                    server_hostname = self.args.target.ip
                sock_ssl = ctx.wrap_socket(smtp.sock, server_hostname=server_hostname)
                smtp.sock = sock_ssl
                smtp.file = None
                smtp.helo_resp = None
                smtp.ehlo_resp = None
                smtp.esmtp_features = {}
                smtp.does_esmtp = False
                _, ehlo_bytes = smtp.ehlo(self.fqdn)
                ehlo = ehlo_bytes.decode() if ehlo_bytes else ""

        return smtp, ehlo

    def test_auth_downgrade(self) -> AuthDowngradeResult:
        """
        Test AUTH downgrade: server changes AUTH offer after failed authentication.
        RFC 4954: session state undefined after failed AUTH; RSET before second EHLO.
        """
        WEAK_METHODS = {"PLAIN", "LOGIN"}
        AUTH_TRIGGER_PREFERENCE = ["XOAUTH2", "OAUTHBEARER", "SCRAM-SHA-256", "SCRAM-SHA-1", "PLAIN"]

        try:
            smtp, ehlo_before = self._get_smtp_for_auth_downgrade()
        except Exception as e:
            return AuthDowngradeResult(
                vulnerable=False,
                weakness=False,
                indeterminate=True,
                info_defensive=False,
                methods_before=[],
                methods_after=[],
                auth_method_used="",
                server_response=None,
                detail=f"Connection failed: {e}",
                rset_ok=None,
            )

        methods_before = sorted(_get_auth_methods_from_ehlo(ehlo_before))
        if not methods_before:
            return AuthDowngradeResult(
                vulnerable=False,
                weakness=False,
                indeterminate=True,
                info_defensive=False,
                methods_before=[],
                methods_after=[],
                auth_method_used="",
                server_response=None,
                detail="Server does not advertise AUTH",
                rset_ok=None,
            )

        auth_method_used = None
        for method in AUTH_TRIGGER_PREFERENCE:
            if method in {m.upper() for m in methods_before}:
                auth_method_used = method
                break
        if not auth_method_used:
            auth_method_used = methods_before[0] if methods_before else "PLAIN"

        bogus_token = self._AUTH_DOWNGRADE_BOGUS_XOAUTH2
        if auth_method_used == "PLAIN":
            bogus_token = b64encode(b"\x00test\x00test").decode()
        elif auth_method_used in ("OAUTHBEARER", "XOAUTH2"):
            bogus_token = self._AUTH_DOWNGRADE_BOGUS_XOAUTH2

        server_response: str | None = None
        try:
            try:
                code, resp = smtp.docmd("AUTH", f"{auth_method_used} {bogus_token}")
            except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError) as e:
                return AuthDowngradeResult(
                    vulnerable=False,
                    weakness=False,
                    indeterminate=True,
                    info_defensive=False,
                    methods_before=methods_before,
                    methods_after=[],
                    auth_method_used=auth_method_used,
                    server_response=str(e),
                    detail="Connection closed after failed auth (defensive reaction)",
                    rset_ok=None,
                )
            server_response = f"[{code}] {self.bytes_to_str(resp)}".strip() if resp else str(code)

            if code == 421:
                return AuthDowngradeResult(
                    vulnerable=False,
                    weakness=False,
                    indeterminate=True,
                    info_defensive=False,
                    methods_before=methods_before,
                    methods_after=[],
                    auth_method_used=auth_method_used,
                    server_response=server_response,
                    detail="Server closed session (421) after failed auth",
                    rset_ok=None,
                )

            try:
                smtp.docmd("RSET")
            except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError) as e:
                return AuthDowngradeResult(
                    vulnerable=False,
                    weakness=False,
                    indeterminate=True,
                    info_defensive=False,
                    methods_before=methods_before,
                    methods_after=[],
                    auth_method_used=auth_method_used,
                    server_response=server_response,
                    detail="Connection closed after RSET (server may have terminated session on RSET)",
                    rset_ok=False,
                )

            try:
                _, ehlo_after_bytes = smtp.ehlo(self.fqdn)
            except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError) as e:
                return AuthDowngradeResult(
                    vulnerable=False,
                    weakness=False,
                    indeterminate=True,
                    info_defensive=False,
                    methods_before=methods_before,
                    methods_after=[],
                    auth_method_used=auth_method_used,
                    server_response=server_response,
                    detail="Connection closed during second EHLO",
                    rset_ok=True,
                )
            ehlo_after = ehlo_after_bytes.decode() if ehlo_after_bytes else ""
            methods_after = sorted(_get_auth_methods_from_ehlo(ehlo_after))

        except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError) as e:
            return AuthDowngradeResult(
                vulnerable=False,
                weakness=False,
                indeterminate=True,
                info_defensive=False,
                methods_before=methods_before,
                methods_after=[],
                auth_method_used=auth_method_used or "?",
                server_response=server_response or str(e),
                detail="Connection closed during test",
                rset_ok=None,
            )

        set_before = set(m.upper() for m in methods_before)
        set_after = set(m.upper() for m in methods_after)

        new_methods = set_after - set_before
        removed_methods = set_before - set_after

        if not methods_after:
            return AuthDowngradeResult(
                vulnerable=False,
                weakness=False,
                indeterminate=False,
                info_defensive=True,
                methods_before=methods_before,
                methods_after=[],
                auth_method_used=auth_method_used,
                server_response=server_response,
                detail="AUTH disappeared after failure (defensive reaction)",
                rset_ok=True,
            )

        if new_methods:
            weak_new = new_methods & WEAK_METHODS
            detail = f"New methods after failure: {sorted(new_methods)}"
            if weak_new:
                detail += "; risk: credential sniffing"
            return AuthDowngradeResult(
                vulnerable=True,
                weakness=False,
                indeterminate=False,
                info_defensive=False,
                methods_before=methods_before,
                methods_after=methods_after,
                auth_method_used=auth_method_used,
                server_response=server_response,
                detail=detail,
                rset_ok=True,
            )

        if removed_methods and (set_after & WEAK_METHODS):
            return AuthDowngradeResult(
                vulnerable=True,
                weakness=True,
                indeterminate=False,
                info_defensive=False,
                methods_before=methods_before,
                methods_after=methods_after,
                auth_method_used=auth_method_used,
                server_response=server_response,
                detail=f"Strong methods removed, PLAIN/LOGIN remained: {sorted(removed_methods)}",
                rset_ok=True,
            )

        return AuthDowngradeResult(
            vulnerable=False,
            weakness=False,
            indeterminate=False,
            info_defensive=False,
            methods_before=methods_before,
            methods_after=methods_after,
            auth_method_used=auth_method_used,
            server_response=server_response,
            detail="No authentication downgrade detected",
            rset_ok=True,
        )

    def _stream_auth_enum_method_verdict(self, mr: AuthEnumResult) -> None:
        pp = ptprinthelper.ptprint
        show = not self.use_json
        if mr.indeterminate:
            pp(f"Could not determine: {mr.detail or 'insufficient AUTH responses'}",
               bullet_type="TITLE", condition=show, indent=8)
            return
        if mr.vulnerable:
            if mr.protocol_flow_vuln:
                msg = (
                    "User enumeration is possible because the server responds with 5xx "
                    "after the username (before the password challenge)"
                )
            else:
                msg = (
                    "User enumeration is possible because error messages are different "
                    "for valid and invalid logins"
                )
            pp(msg, bullet_type="VULN", condition=show, indent=8)
            if mr.enumerated_users:
                for u in mr.enumerated_users:
                    pp(u, bullet_type="TEXT", condition=show, indent=12)
            elif mr.detail and not mr.protocol_flow_vuln:
                # No per-user list: show the technical detail (skip when it just
                # repeats the protocol-flow verdict sentence above).
                pp(mr.detail, bullet_type="TEXT", condition=show, indent=12)
            return
        pp(
            "User enumeration is not possible because error messages are the same "
            "for valid and invalid logins (or no valid login was delivered)",
            bullet_type="NOTVULN", condition=show, indent=8,
        )
        if mr.detail:
            pp(mr.detail, bullet_type="TEXT", condition=show, indent=12)

    def _stream_auth_enum_result(self) -> None:
        pp = ptprinthelper.ptprint
        show = not self.use_json
        if (auth_enum_error := self.results.auth_enum_error) is not None:
            pp(f"AUTH enumeration test failed: {auth_enum_error}", bullet_type="VULN", condition=show, indent=4)
            return
        ae = self.results.auth_enum
        if ae is None:
            return
        method_results = self.results.auth_enum_methods
        if not method_results:
            if ae.indeterminate:
                if ae.detail == "Server does not advertise AUTH LOGIN, PLAIN or NTLM":
                    pp(f"Not vulnerable: {ae.detail}", bullet_type="NOTVULN", condition=show, indent=4)
                else:
                    pp(f"Indeterminate: {ae.detail or 'Could not determine'}", bullet_type="TITLE", condition=show, indent=4)
            return
        ntlm_note = self.results.auth_enum_ntlm_note
        for mr in method_results:
            pp(f"AUTH {mr.method_tested} test enumeration", bullet_type="TITLE", condition=show, indent=4)
            if mr.method_tested == "NTLM" and ntlm_note:
                pp(ntlm_note, bullet_type="TITLE", condition=show, indent=8)
            self._stream_auth_enum_method_verdict(mr)
        if ae.vulnerable and ae.enumerated_users and len(method_results) > 1:
            pp("Enumerated users (all mechanisms)", bullet_type="TITLE", condition=show, indent=4)
            for u in ae.enumerated_users:
                pp(u, bullet_type="TEXT", condition=show, indent=8)

    def _stream_auth_format_result(self) -> None:
        """PTL-SVC-SMTP-AUTH-FORMAT: text output for AUTH LOGIN identity-shape probes."""
        pp = ptprinthelper.ptprint
        show = not self.use_json
        if (err := self.results.auth_format_error) is not None:
            pp(f"AUTH format probe failed: {err}", bullet_type="TITLE", condition=show, indent=4)
            return
        af = self.results.auth_format
        if af is None:
            return
        pp(f"AUTH Analysis ({af.method_tested})", bullet_type="INFO", condition=show, indent=4)
        if af.challenge_decoded is not None:
            pp(f"AUTH LOGIN challenge (decoded): {af.challenge_decoded!r}", bullet_type="TITLE", condition=show, indent=4)
        if af.challenge_hint:
            pp(f"Challenge heuristic: {af.challenge_hint}", bullet_type="TITLE", condition=show, indent=4)
        pp("Auth Format Probe:", bullet_type="TITLE", condition=show, indent=4)
        if af.target_domain_used:
            pp(f"Target domain used: {af.target_domain_used}", bullet_type="TITLE", condition=show, indent=8)
        else:
            pp("Target domain used: (none — probe B skipped)", bullet_type="TITLE", condition=show, indent=8)
        if af.target_domain_analyst_note:
            pp(af.target_domain_analyst_note, bullet_type="TITLE", condition=show, indent=8)
        if af.target_domain_source == "ehlo_last2" and af.target_domain_ehlo_hostname and af.target_domain_used:
            self.ptdebug(
                f"AUTH-FORMAT: scan target is IP; EHLO hostname {af.target_domain_ehlo_hostname!r} "
                f"→ derived domain {af.target_domain_used!r} (last 2 labels, no PSL)",
                Out.INFO,
            )
        elif af.target_domain_source == "scan_last2" and af.target_domain_scan_hostname and af.target_domain_used:
            self.ptdebug(
                f"AUTH-FORMAT: target domain from scan target {af.target_domain_scan_hostname!r} "
                f"→ {af.target_domain_used!r} (last 2 labels, no PSL)",
                Out.INFO,
            )
        elif af.target_domain_source == "none":
            self.ptdebug(
                "AUTH-FORMAT: no derived domain for probe B (see analyst note above)",
                Out.INFO,
            )
        for r in af.rows:
            if r.skipped:
                pp(f"{r.label}: skipped ({r.skip_reason or 'n/a'})", bullet_type="TITLE", condition=show, indent=8)
            elif r.password_phase:
                tail = f"final reply {r.code_after_password}" if r.code_after_password is not None else "password phase"
                pp(f"{r.label}: accepted → password phase ({tail})", bullet_type="TITLE", condition=show, indent=8)
            else:
                rep = (r.reply_after_identity or "").replace("\r\n", " ").strip()
                if len(rep) > 140:
                    rep = rep[:137] + "..."
                pp(f"{r.label}: rejected at username ({r.code_after_identity}) {rep}".rstrip(),
                   bullet_type="TITLE", condition=show, indent=8)
        pp(f"Auth Identity Format: {af.conclusion}", bullet_type="TITLE", condition=show, indent=4)
        if af.conclusion_id == "flexible_all_formats":
            ch_tail = ""
            hint_note = af.challenge_hint
            if hint_note and "ambiguous" in hint_note.lower():
                hint_note = "format ambiguous"
            if af.challenge_decoded is not None and hint_note:
                ch_tail = f" Challenge hint: {af.challenge_decoded!r} — {hint_note}."
            elif af.challenge_decoded is not None:
                ch_tail = f" Challenge hint: {af.challenge_decoded!r}."
            elif hint_note:
                ch_tail = f" Challenge hint: {hint_note}."
            pp(
                f"Note: All probes that ran reached password phase — server may be masking "
                f"expected format (catch-all behavior).{ch_tail}",
                bullet_type="TITLE", condition=show, indent=4,
            )
        if af.netbios_domain_used:
            pp(f"NTLM-derived DOMAIN for NetBIOS probe: {af.netbios_domain_used}", bullet_type="TITLE", condition=show, indent=4)

    def _stream_auth_downgrade_result(self) -> None:
        pp = ptprinthelper.ptprint
        show = not self.use_json
        if (err := self.results.auth_downgrade_error) is not None:
            pp(f"AUTH downgrade test failed: {err}", bullet_type="VULN", condition=show, indent=4)
            return
        ad = self.results.auth_downgrade
        if ad is None:
            return
        pp(f"Initial methods: {ad.methods_before}", bullet_type="TITLE", condition=show, indent=4)
        pp(f"Attempting failed AUTH ({ad.auth_method_used})...", bullet_type="TITLE", condition=show, indent=4)
        if ad.server_response:
            pp(f"Server response: {ad.server_response}", bullet_type="TITLE", condition=show, indent=4)
        if ad.rset_ok is not None:
            pp("Resetting session state (RSET)...", bullet_type="TITLE", condition=show, indent=4)
            if ad.rset_ok:
                pp("RSET OK", bullet_type="NOTVULN", condition=show, indent=4)
                pp(f"Post-failure methods: {ad.methods_after}", bullet_type="TITLE", condition=show, indent=4)
            else:
                pp("Connection closed after RSET", bullet_type="WARNING", condition=show, indent=4)
        elif ad.methods_after:
            pp(f"Post-failure methods: {ad.methods_after}", bullet_type="TITLE", condition=show, indent=4)
        if ad.indeterminate:
            pp(f"Indeterminate: {ad.detail or 'Could not determine'}", bullet_type="TITLE", condition=show, indent=4)
            return
        if ad.info_defensive:
            pp(ad.detail, bullet_type="TITLE", condition=show, indent=4)
            return
        if ad.vulnerable:
            pp(f"VULNERABLE: {ad.detail}", bullet_type="VULN", condition=show, indent=4)
            pp(f"Before: {ad.methods_before}", bullet_type="TEXT", condition=show, indent=8)
            pp(f"After:  {ad.methods_after}", bullet_type="TEXT", condition=show, indent=8)
            pp("Risk: Server may be susceptible to forced credential sniffing.", bullet_type="TITLE", condition=show, indent=4)
        else:
            pp(ad.detail, bullet_type="NOTVULN", condition=show, indent=4)
