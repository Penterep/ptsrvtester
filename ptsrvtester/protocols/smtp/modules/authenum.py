"""AUTHENUM — user enumeration via AUTH LOGIN / PLAIN / NTLM."""
import ipaddress, random, secrets, smtplib, ssl, threading, time
from base64 import b64decode, b64encode

from ..utils.ptntlmauth.ptntlmauth import get_NegotiateMessage_data, decode_ChallengeMessage_blob

try:
    from ntlm_auth.ntlm import NtlmContext
except ImportError:
    NtlmContext = None

from ..._base import Out
from ..utils.helpers import AUTH_ENUM_SYNTHETIC_INVALID_COUNT, auth_enum_candidate_names, auth_enum_ntlm_identity_note
from ..utils.progress import ThreadedProgress

from ..utils.helpers import *
from ..utils.results import *
from ..utils.registry import *

from ._auth import (
    _auth_enum_connect_aborted,
    _auth_enum_note_connect_abort,
    _get_smtp_for_auth_enum,
)
from ._common import eng


__MODULELABEL__ = "AUTH user enumeration"
__MODULECODE__ = "AUTHENUM"
__ORDER__ = 58


def _auth_enum_reply_snip(e, resp: bytes | str | None, limit: int=96) -> str:
    """Short one-line SMTP reply for -vv AUTH-ENUM tracing (avoids dumping huge blobs)."""
    if resp is None:
        return ''
    raw = resp if isinstance(resp, str) else e.bytes_to_str(resp)
    s = raw.replace('\r\n', ' ').replace('\r', ' ').replace('\n', ' ').strip()
    if len(s) > limit:
        return s[:limit - 3] + '...'
    return s


def _auth_enum_show_live_progress(e) -> bool:
    """Same TTY live line as ``-e`` enumeration: disabled for JSON and for ``--threads`` > 1."""
    return not e.use_json and int(getattr(e.args, 'enum_threads', 1) or 1) <= 1


def _auth_enum_progress_label(user: str) -> str:
    u = (user or '').strip()
    if len(u) > 48:
        return u[:45] + '...'
    return u or '…'


def _auth_enum_progress_session_begin(e) -> None:
    if not _auth_enum_show_live_progress(e):
        return
    e._enum_progress_line_dirty = False
    e._enum_progress_start = time.time()


def _auth_enum_progress_session_end(e) -> None:
    if not _auth_enum_show_live_progress(e):
        return
    e._enum_progress_newline()
    e._enum_clock_shutdown()


def _auth_enum_progress_step(e, step: int, total: int, label: str) -> None:
    if not _auth_enum_show_live_progress(e) or total <= 0:
        return
    e._enum_wait_begin(step, total, label)


def _auth_enum_progress_step_done(e) -> None:
    if not _auth_enum_show_live_progress(e):
        return
    e._enum_wait_end()


def _auth_enum_probe_login_user(e, user: str) -> str | None:
    """One connection: AUTH LOGIN → user → wrong password; return stage signature or None."""
    conn = None
    try:
        conn, _ = _get_smtp_for_auth_enum(e)
        code, resp = conn.docmd('AUTH', 'LOGIN')
        e._smtp_vv_io('AUTH LOGIN', f'{code} {_auth_enum_reply_snip(e, resp)}')
        if code != 334:
            return None
        code, resp = conn.docmd(b64encode(user.encode()).decode())
        e._smtp_vv_io(f'AUTH LOGIN user {user}', f'{code} {_auth_enum_reply_snip(e, resp)}')
        if code >= 500:
            return _auth_enum_login_stage_signature('u', code, resp, e.bytes_to_str)
        if code == 334:
            code, resp = conn.docmd(b64encode(e.AUTH_ENUM_PASSWORD.encode()).decode())
            e._smtp_vv_io('AUTH LOGIN password', f'{code} {_auth_enum_reply_snip(e, resp)}')
            if code >= 500:
                return _auth_enum_login_stage_signature('p', code, resp, e.bytes_to_str)
        return None
    except Exception as ex:
        if e._smtp_exc_is_timeout(ex):
            return AUTH_ENUM_TIMEOUT_SIG
        return None
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def _auth_enum_probe_ntlm_user(e, user: str) -> str | None:
    """One connection: AUTH NTLM negotiate → user + wrong password; return 'code line' or None."""
    if NtlmContext is None:
        return None
    conn = None
    try:
        conn, _ = _get_smtp_for_auth_enum(e)
        code, resp = conn.docmd('AUTH', 'NTLM')
        e._smtp_vv_io('AUTH NTLM', f'{code} {_auth_enum_reply_snip(e, resp)}')
        if code != 334:
            return None
        conn.send(b64encode(get_NegotiateMessage_data()) + smtplib.bCRLF)
        code, resp = conn.getreply()
        e._smtp_vv_io('AUTH NTLM negotiate', f'{code} {_auth_enum_reply_snip(e, resp)}')
        if code != 334:
            return None
        ctx = NtlmContext(user, e.AUTH_ENUM_PASSWORD)
        type3 = ctx.step(b64decode(resp))
        conn.send(b64encode(type3) + smtplib.bCRLF)
        code, resp = conn.getreply()
        e._smtp_vv_io(f'AUTH NTLM user {user}', f'{code} {_auth_enum_reply_snip(e, resp)}')
        if code >= 500:
            txt = e.bytes_to_str(resp).strip()
            return f'{code} {txt}' if txt else str(code)
        return None
    except Exception as ex:
        if e._smtp_exc_is_timeout(ex):
            return AUTH_ENUM_TIMEOUT_SIG
        return None
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def _auth_enum_plain_exchange(e, conn: smtplib.SMTP, user: str, password: str) -> tuple[int, bytes]:
    """
        RFC 4616 PLAIN + RFC 4954 SMTP AUTH: send initial-response ``AUTH PLAIN <base64>``;
        on 334 continuation, send the same base64 line (some servers omit initial-response path).
        """
    init = _auth_enum_plain_initial_b64(user, password)
    code, resp = conn.docmd('AUTH', f'PLAIN {init}')
    if code == 334:
        code, resp = conn.docmd(init)
    return (code, resp)


def _auth_enum_probe_plain_user(e, user: str) -> str | None:
    """One connection: AUTH PLAIN with wrong password; compare final SMTP line vs invalid baseline (RFC 4616)."""
    conn = None
    try:
        conn, _ = _get_smtp_for_auth_enum(e)
        code, resp = _auth_enum_plain_exchange(e, conn, user, e.AUTH_ENUM_PASSWORD)
        e._smtp_vv_io(f'AUTH PLAIN {user}', f'{code} {_auth_enum_reply_snip(e, resp)}')
        if code >= 500:
            txt = e.bytes_to_str(resp).strip()
            return f'{code} {txt}' if txt else str(code)
        return None
    except Exception as ex:
        if e._smtp_exc_is_timeout(ex):
            return AUTH_ENUM_TIMEOUT_SIG
        return None
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def _auth_enum_synthetic_invalid_names() -> list[str]:
    return [f'enumtest_invalid_{random.getrandbits(32):08x}' for _ in range(AUTH_ENUM_SYNTHETIC_INVALID_COUNT)]


def _auth_enum_methods_to_test(e, auth_methods: set[str]) -> list[str]:
    return [m for m in e.AUTH_ENUM_METHOD_PROBE_ORDER if m in auth_methods]


def _auth_enum_login_postprocess(invalid_responses: list[str], candidate_sigs: list[str | None], candidates: list[str]) -> tuple[bool, list[str]]:
    """Compute LOGIN enumeration result from collected signatures.

        Returns ``(effective_protocol_flow_vuln, enumerated_list)``:

        * baseline (invalid) users rejected with 5xx at the username stage
          (``LOGIN:u:``) is only a real oracle if at least one candidate is NOT
          rejected there (i.e. passes to the password stage → likely valid).
        * a candidate is enumerated when its signature differs from the invalid
          baseline OR it passed the username gate while invalid users did not.
        """
    inv_set = set(invalid_responses)
    baseline_gate_reject = any((s and s.startswith('LOGIN:u:') for s in invalid_responses))
    enumerated: list[str] = []
    gate_passed_count = 0
    for cand, sig in zip(candidates, candidate_sigs):
        if sig == AUTH_ENUM_TIMEOUT_SIG:
            continue
        differs = bool(sig and inv_set and (sig not in inv_set))
        passed_gate = bool(baseline_gate_reject and sig and (not sig.startswith('LOGIN:u:')))
        if passed_gate:
            gate_passed_count += 1
        if differs or passed_gate:
            enumerated.append(cand)
    effective_proto = baseline_gate_reject and gate_passed_count > 0
    return (effective_proto, enumerated)


def _auth_enum_finalize_method_result(e, method: str, *, invalid_responses: list[str], protocol_flow_vuln: bool, enumerated_list: list[str], candidates: list[str], any_candidate_sig: bool, valid_response: str | None, timeout_n: int=0, probe_n: int=0) -> AuthEnumResult:
    response_differs = len(enumerated_list) > 0
    vulnerable = protocol_flow_vuln or response_differs
    detail: str | None = None
    if protocol_flow_vuln:
        detail = 'Server responds 5xx after username (before password challenge)'
    elif response_differs:
        detail = f'Different responses vs synthetic invalid baseline; examples: {invalid_responses[:1]} vs {valid_response}'
    if timeout_n and (not vulnerable):
        majority = bool(probe_n and timeout_n * 2 >= probe_n)
        if majority or not invalid_responses or (candidates and (not any_candidate_sig)):
            return AuthEnumResult(vulnerable=False, indeterminate=True, method_tested=method, protocol_flow_vuln=False, invalid_user_responses=invalid_responses, valid_user_response=valid_response, enumerated_users=(), detail=f'{timeout_n} of {probe_n} probes timed out. Could not tell whether usernames exist.')
    if not invalid_responses and (not protocol_flow_vuln):
        return AuthEnumResult(vulnerable=False, indeterminate=True, method_tested=method, protocol_flow_vuln=False, invalid_user_responses=[], valid_user_response=None, enumerated_users=(), detail='Could not obtain AUTH baseline from two synthetic invalid users')
    if not vulnerable and candidates and (not any_candidate_sig):
        return AuthEnumResult(vulnerable=False, indeterminate=True, method_tested=method, protocol_flow_vuln=False, invalid_user_responses=invalid_responses, valid_user_response=valid_response, enumerated_users=(), detail='No comparable AUTH responses for candidate names')
    return AuthEnumResult(vulnerable=vulnerable, indeterminate=False, method_tested=method, protocol_flow_vuln=protocol_flow_vuln, invalid_user_responses=invalid_responses, valid_user_response=valid_response, enumerated_users=tuple(enumerated_list), detail=detail)


def _auth_enum_aggregate_results(e, method_results: list[AuthEnumResult]) -> AuthEnumResult:
    if not method_results:
        return AuthEnumResult(vulnerable=False, indeterminate=True, method_tested='', protocol_flow_vuln=False, invalid_user_responses=[], valid_user_response=None, enumerated_users=(), detail='No AUTH enumeration probes were run')
    if len(method_results) == 1:
        return method_results[0]
    methods_tested = ','.join((r.method_tested for r in method_results if r.method_tested))
    enumerated: list[str] = []
    seen_enum: set[str] = set()
    for r in method_results:
        for u in r.enumerated_users:
            if u not in seen_enum:
                seen_enum.add(u)
                enumerated.append(u)
    if any((r.vulnerable for r in method_results)):
        detail_parts = [f'{r.method_tested}: {r.detail}' for r in method_results if r.vulnerable and r.detail]
        return AuthEnumResult(vulnerable=True, indeterminate=False, method_tested=methods_tested, protocol_flow_vuln=any((r.protocol_flow_vuln for r in method_results)), invalid_user_responses=[], valid_user_response=None, enumerated_users=tuple(enumerated), detail='; '.join(detail_parts) if detail_parts else 'User enumeration via one or more AUTH mechanisms')
    if all((r.indeterminate for r in method_results)):
        detail_parts = [r.detail for r in method_results if r.detail]
        return AuthEnumResult(vulnerable=False, indeterminate=True, method_tested=methods_tested, protocol_flow_vuln=False, invalid_user_responses=[], valid_user_response=None, enumerated_users=(), detail='; '.join(detail_parts) if detail_parts else 'Indeterminate')
    return AuthEnumResult(vulnerable=False, indeterminate=False, method_tested=methods_tested, protocol_flow_vuln=False, invalid_user_responses=[], valid_user_response=None, enumerated_users=(), detail=None)


def _auth_enum_progress_run_step(e, total: int, label: str) -> None:
    counter = getattr(e, '_auth_enum_progress_counter', 0) + 1
    e._auth_enum_progress_counter = counter
    _auth_enum_progress_step(e, counter, total, label)


def _auth_enum_test_login_method(e, candidates: list[str], invalid_users: list[str], *, progress_total: int) -> AuthEnumResult:
    invalid_responses: list[str] = []
    protocol_flow_vuln = False
    enumerated_list: list[str] = []
    valid_response: str | None = None
    any_candidate_sig = False
    timeout_n = 0
    for inv_user in invalid_users:
        _auth_enum_progress_run_step(e, progress_total, _auth_enum_progress_label(inv_user))
        try:
            r = _auth_enum_probe_login_user(e, inv_user)
            if r == AUTH_ENUM_TIMEOUT_SIG:
                timeout_n += 1
            elif r:
                invalid_responses.append(r)
        finally:
            _auth_enum_progress_step_done(e)
    inv_normalized = set(invalid_responses) if invalid_responses else set()
    candidate_sigs: list[str | None] = []
    for i, cand in enumerate(candidates):
        _auth_enum_progress_run_step(e, progress_total, _auth_enum_progress_label(cand))
        try:
            r = _auth_enum_probe_login_user(e, cand)
            candidate_sigs.append(r)
            if r == AUTH_ENUM_TIMEOUT_SIG:
                timeout_n += 1
            if i == 0:
                valid_response = r if r != AUTH_ENUM_TIMEOUT_SIG else None
            if r is not None and r != AUTH_ENUM_TIMEOUT_SIG:
                any_candidate_sig = True
        finally:
            _auth_enum_progress_step_done(e)
    protocol_flow_vuln, enumerated_list = _auth_enum_login_postprocess(invalid_responses, candidate_sigs, candidates)
    return _auth_enum_finalize_method_result(e, 'LOGIN', invalid_responses=invalid_responses, protocol_flow_vuln=protocol_flow_vuln, enumerated_list=enumerated_list, candidates=candidates, any_candidate_sig=any_candidate_sig, valid_response=valid_response, timeout_n=timeout_n, probe_n=len(invalid_users) + len(candidates))


def _auth_enum_test_plain_method(e, candidates: list[str], invalid_users: list[str], *, progress_total: int) -> AuthEnumResult:
    invalid_responses: list[str] = []
    enumerated_list: list[str] = []
    valid_response: str | None = None
    any_candidate_sig = False
    timeout_n = 0
    for inv_user in invalid_users:
        _auth_enum_progress_run_step(e, progress_total, _auth_enum_progress_label(inv_user))
        try:
            r = _auth_enum_probe_plain_user(e, inv_user)
            if r == AUTH_ENUM_TIMEOUT_SIG:
                timeout_n += 1
            elif r:
                invalid_responses.append(r)
        finally:
            _auth_enum_progress_step_done(e)
    inv_normalized = {_normalize_auth_response_for_comparison(r) for r in invalid_responses} if invalid_responses else set()
    for i, cand in enumerate(candidates):
        _auth_enum_progress_run_step(e, progress_total, _auth_enum_progress_label(cand))
        try:
            r = _auth_enum_probe_plain_user(e, cand)
            if r == AUTH_ENUM_TIMEOUT_SIG:
                timeout_n += 1
                differs = False
            else:
                differs = bool(r and inv_normalized and (_normalize_auth_response_for_comparison(r) not in inv_normalized))
            if i == 0:
                valid_response = r if r != AUTH_ENUM_TIMEOUT_SIG else None
            if r is not None and r != AUTH_ENUM_TIMEOUT_SIG:
                any_candidate_sig = True
            if differs:
                enumerated_list.append(cand)
        finally:
            _auth_enum_progress_step_done(e)
    return _auth_enum_finalize_method_result(e, 'PLAIN', invalid_responses=invalid_responses, protocol_flow_vuln=False, enumerated_list=enumerated_list, candidates=candidates, any_candidate_sig=any_candidate_sig, valid_response=valid_response, timeout_n=timeout_n, probe_n=len(invalid_users) + len(candidates))


def _auth_enum_test_ntlm_method(e, candidates: list[str], invalid_users: list[str], *, progress_total: int) -> AuthEnumResult:
    if NtlmContext is None:
        return AuthEnumResult(vulnerable=False, indeterminate=True, method_tested='NTLM', protocol_flow_vuln=False, invalid_user_responses=[], valid_user_response=None, enumerated_users=(), detail='NTLM test requires ntlm-auth package')

    invalid_responses: list[str] = []
    enumerated_list: list[str] = []
    valid_response: str | None = None
    any_candidate_sig = False
    timeout_n = 0
    for inv_user in invalid_users:
        _auth_enum_progress_run_step(e, progress_total, _auth_enum_progress_label(inv_user))
        try:
            r = _auth_enum_probe_ntlm_user(e, inv_user)
            if r == AUTH_ENUM_TIMEOUT_SIG:
                timeout_n += 1
            elif r:
                invalid_responses.append(r)
        finally:
            _auth_enum_progress_step_done(e)
    inv_normalized = {_normalize_auth_response_for_comparison(r) for r in invalid_responses} if invalid_responses else set()
    for i, cand in enumerate(candidates):
        _auth_enum_progress_run_step(e, progress_total, _auth_enum_progress_label(cand))
        try:
            r = _auth_enum_probe_ntlm_user(e, cand)
            if r == AUTH_ENUM_TIMEOUT_SIG:
                timeout_n += 1
                differs = False
            else:
                differs = bool(r and inv_normalized and (_normalize_auth_response_for_comparison(r) not in inv_normalized))
            if i == 0:
                valid_response = r if r != AUTH_ENUM_TIMEOUT_SIG else None
            if r is not None and r != AUTH_ENUM_TIMEOUT_SIG:
                any_candidate_sig = True
            if differs:
                enumerated_list.append(cand)
        finally:
            _auth_enum_progress_step_done(e)
    return _auth_enum_finalize_method_result(e, 'NTLM', invalid_responses=invalid_responses, protocol_flow_vuln=False, enumerated_list=enumerated_list, candidates=candidates, any_candidate_sig=any_candidate_sig, valid_response=valid_response, timeout_n=timeout_n, probe_n=len(invalid_users) + len(candidates))


def _auth_enum_method_threaded(e, method: str, probe_fn, normalize, candidates: list[str], invalid_users: list[str], progress: ThreadedProgress, enum_threads: int) -> AuthEnumResult:
    """Probe one AUTH mechanism with -t worker threads (one fresh connection per probe).

        Baseline + candidate probes run in parallel (each opens its own connection, so there
        is no connection-reuse benefit to serialising them); the verdict is computed after all
        probes finish, identically to the sequential path.
        """
    is_login = method == 'LOGIN'
    invalid_responses: list[str] = []
    cand_sigs: list[str | None] = [None] * len(candidates)
    lock = threading.Lock()
    timeout_n = 0
    items = [('b', -1, u) for u in invalid_users]
    items += [('c', i, u) for i, u in enumerate(candidates)]

    def work(item, _out) -> str:
        nonlocal timeout_n
        kind, idx, user = item
        if _auth_enum_connect_aborted(e):
            return user
        try:
            sig = probe_fn(user)
        except Exception as ex:
            sig = AUTH_ENUM_TIMEOUT_SIG if e._smtp_exc_is_timeout(ex) else None
        with lock:
            if sig == AUTH_ENUM_TIMEOUT_SIG:
                timeout_n += 1
            if kind == 'b':
                if sig and sig != AUTH_ENUM_TIMEOUT_SIG:
                    invalid_responses.append(sig)
            else:
                cand_sigs[idx] = sig
        return user
    progress.run(items, work, enum_threads, finalize=False)
    valid_response = None
    if cand_sigs and cand_sigs[0] != AUTH_ENUM_TIMEOUT_SIG:
        valid_response = cand_sigs[0]
    any_candidate_sig = any((s is not None and s != AUTH_ENUM_TIMEOUT_SIG for s in cand_sigs))
    if is_login:
        protocol_flow_vuln, enumerated_list = _auth_enum_login_postprocess(invalid_responses, cand_sigs, candidates)
    else:
        protocol_flow_vuln = False
        inv_normalized = {normalize(r) for r in invalid_responses} if invalid_responses else set()
        enumerated_list = []
        for i, cand in enumerate(candidates):
            r = cand_sigs[i]
            if r == AUTH_ENUM_TIMEOUT_SIG:
                continue
            differs = bool(r and inv_normalized and (normalize(r) not in inv_normalized))
            if differs:
                enumerated_list.append(cand)
    return _auth_enum_finalize_method_result(e, method, invalid_responses=invalid_responses, protocol_flow_vuln=protocol_flow_vuln, enumerated_list=enumerated_list, candidates=candidates, any_candidate_sig=any_candidate_sig, valid_response=valid_response, timeout_n=timeout_n, probe_n=len(invalid_users) + len(candidates))


def _auth_enum_run_methods_threaded(e, methods_to_test: list[str], candidates: list[str], invalid_users: list[str], per_method_steps: int, enum_threads: int) -> list[AuthEnumResult]:
    """Threaded (-t) variant of the AUTH-ENUM mechanism loop with one shared progress bar."""
    probe_methods = [m for m in methods_to_test if not (m == 'NTLM' and NtlmContext is None)]
    progress_total = per_method_steps * len(probe_methods)
    progress = ThreadedProgress(progress_total, enabled=not e.use_json)
    method_results: list[AuthEnumResult] = []
    try:
        for method in methods_to_test:
            if method == 'LOGIN':
                method_results.append(_auth_enum_method_threaded(e, 'LOGIN', lambda user: _auth_enum_probe_login_user(e, user), lambda x: x, candidates, invalid_users, progress, enum_threads))
            elif method == 'PLAIN':
                method_results.append(_auth_enum_method_threaded(e, 'PLAIN', lambda user: _auth_enum_probe_plain_user(e, user), _normalize_auth_response_for_comparison, candidates, invalid_users, progress, enum_threads))
            elif method == 'NTLM':
                if NtlmContext is None:
                    method_results.append(AuthEnumResult(vulnerable=False, indeterminate=True, method_tested='NTLM', protocol_flow_vuln=False, invalid_user_responses=[], valid_user_response=None, enumerated_users=(), detail='NTLM test requires ntlm-auth package'))
                else:
                    method_results.append(_auth_enum_method_threaded(e, 'NTLM', lambda user: _auth_enum_probe_ntlm_user(e, user), _normalize_auth_response_for_comparison, candidates, invalid_users, progress, enum_threads))
    finally:
        progress.finalize()
    return method_results


def test_auth_enum(e) -> AuthEnumResult:
    """
        AUTH user enumeration: for each advertised mechanism (LOGIN, PLAIN, NTLM), probe two
        synthetic invalid identities plus candidates from -u/-U or ``default_logins``.
        """
    e._auth_enum_dbg_logged_starttls = False
    e._auth_enum_conn_abort = None
    candidates, used_default_logins = auth_enum_candidate_names(e.args, wordlist=getattr(e, 'wordlist', None))
    invalid_users = _auth_enum_synthetic_invalid_names()
    cand_src = 'default_logins' if used_default_logins else '-u/-U'

    def _store_and_return(method_results: list[AuthEnumResult], aggregate: AuthEnumResult) -> AuthEnumResult:
        e.results.auth_enum_methods = tuple(method_results)
        if any((r.method_tested == 'NTLM' for r in method_results)):
            e.results.auth_enum_ntlm_note = auth_enum_ntlm_identity_note(used_default_logins, candidates)
        else:
            e.results.auth_enum_ntlm_note = None
        return aggregate
    try:
        _, ehlo = _get_smtp_for_auth_enum(e)
    except Exception as ex:
        err = AuthEnumResult(vulnerable=False, indeterminate=True, method_tested='', protocol_flow_vuln=False, invalid_user_responses=[], valid_user_response=None, enumerated_users=(), detail=str(ex))
        return _store_and_return([], err)
    auth_methods = _get_auth_methods_from_ehlo(ehlo)
    methods_to_test = _auth_enum_methods_to_test(e, auth_methods)
    if not methods_to_test:
        no_auth = AuthEnumResult(vulnerable=False, indeterminate=True, method_tested='', protocol_flow_vuln=False, invalid_user_responses=[], valid_user_response=None, enumerated_users=(), detail='Server does not advertise AUTH LOGIN, PLAIN or NTLM')
        return _store_and_return([], no_auth)
    enum_threads = max(1, int(getattr(e.args, 'enum_threads', 1) or 1))
    per_method_steps = len(invalid_users) + len(candidates)
    method_results: list[AuthEnumResult] = []
    if enum_threads > 1:
        method_results = _auth_enum_run_methods_threaded(e, methods_to_test, candidates, invalid_users, per_method_steps, enum_threads)
    else:
        progress_total = per_method_steps * len(methods_to_test)
        e._auth_enum_progress_counter = 0
        _auth_enum_progress_session_begin(e)
        try:
            for method in methods_to_test:
                if method == 'LOGIN':
                    method_results.append(_auth_enum_test_login_method(e, candidates, invalid_users, progress_total=progress_total))
                elif method == 'PLAIN':
                    method_results.append(_auth_enum_test_plain_method(e, candidates, invalid_users, progress_total=progress_total))
                elif method == 'NTLM':
                    method_results.append(_auth_enum_test_ntlm_method(e, candidates, invalid_users, progress_total=progress_total))
        finally:
            _auth_enum_progress_session_end(e)
    if (abort_msg := _auth_enum_connect_aborted(e)):
        e.results.auth_enum_error = abort_msg
        err = AuthEnumResult(vulnerable=False, indeterminate=True, method_tested='', protocol_flow_vuln=False, invalid_user_responses=[], valid_user_response=None, enumerated_users=(), detail=abort_msg)
        return _store_and_return(method_results, err)
    aggregate = _auth_enum_aggregate_results(e, method_results)
    return _store_and_return(method_results, aggregate)


def _stream_auth_enum_method_verdict(e, mr: AuthEnumResult) -> None:
    pp = e._ptprint_raw
    show = not e.use_json
    if mr.indeterminate:
        pp(f"Could not determine: {mr.detail or 'insufficient AUTH responses'}", bullet_type='WARNING', condition=show, indent=8)
        return
    if mr.vulnerable:
        if mr.protocol_flow_vuln:
            msg = 'User enumeration is possible because the server responds with 5xx after the username (before the password challenge)'
        else:
            msg = 'User enumeration is possible because error messages are different for valid and invalid logins'
        pp(msg, bullet_type='VULN', condition=show, indent=8)
        if mr.enumerated_users:
            for u in mr.enumerated_users:
                pp(u, bullet_type='TEXT', condition=show, indent=12)
        elif mr.detail and (not mr.protocol_flow_vuln):
            pp(mr.detail, bullet_type='TEXT', condition=show, indent=12)
        return
    pp('User enumeration is not possible because error messages are the same for valid and invalid logins (or no valid login was delivered)', bullet_type='NOTVULN', condition=show, indent=8)
    if mr.detail:
        pp(mr.detail, bullet_type='TEXT', condition=show, indent=12)


def _stream_auth_enum_result(e) -> None:
    pp = e._ptprint_raw
    show = not e.use_json
    if (auth_enum_error := e.results.auth_enum_error) is not None:
        pp(f'AUTH enumeration test failed: {auth_enum_error}', bullet_type='VULN', condition=show, indent=4)
        return
    ae = e.results.auth_enum
    if ae is None:
        return
    method_results = e.results.auth_enum_methods
    if not method_results:
        if ae.indeterminate:
            if ae.detail == 'Server does not advertise AUTH LOGIN, PLAIN or NTLM':
                pp('AUTH LOGIN/PLAIN/NTLM not advertised', bullet_type='WARNING', condition=show, indent=4)
            else:
                pp(f"Indeterminate: {ae.detail or 'Could not determine'}", bullet_type='WARNING', condition=show, indent=4)
        return
    ntlm_note = e.results.auth_enum_ntlm_note
    for mr in method_results:
        pp(f'AUTH {mr.method_tested} test enumeration', bullet_type='TITLE', condition=show, indent=4)
        if mr.method_tested == 'NTLM' and ntlm_note:
            pp(ntlm_note, bullet_type='TITLE', condition=show, indent=8)
        _stream_auth_enum_method_verdict(e, mr)
    if ae.vulnerable and ae.enumerated_users and (len(method_results) > 1):
        pp('Enumerated users (all mechanisms)', bullet_type='TITLE', condition=show, indent=4)
        for u in ae.enumerated_users:
            pp(u, bullet_type='TEXT', condition=show, indent=8)


def run(ctx):
    e = eng(ctx)
    e.args.auth_enum = True
    e._load_wordlist()
    try:
        e.results.auth_enum = test_auth_enum(e)
    except Exception as ex:
        e.results.auth_enum_error = str(ex)
        ctx.out(f"AUTHENUM failed: {ex}", "ERROR", indent=4)
        return
    _stream_auth_enum_result(e)
