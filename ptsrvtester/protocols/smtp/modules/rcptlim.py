"""RCPTLIM — RCPT TO recipient limit."""
import secrets, smtplib, socket, sys, threading, time

from ..._base import Out

from ..utils.helpers import *
from ..utils.results import *
from ..utils.registry import *

from ._common import eng
from .openrel import open_relay_test
from .role import test_role


__MODULELABEL__ = ""
__MODULECODE__ = "RCPTLIM"
__ORDER__ = 210


def _rl_domain_source_phrase(source: str) -> str:
    """Human label for where the RCPT-limit domain was taken from."""
    return {'domain_arg': '-d/--domain', 'banner': 'banner', 'ehlo': 'EHLO', 'fqdn': 'client FQDN', 'ptr': 'reverse DNS (PTR)', 'default': 'default fallback'}.get(source, source)


def _stream_rcpt_limit_domain_source(e, domain: str, source: str) -> None:
    src = _rl_domain_source_phrase(source)
    e._ptprint_raw(f'Domain derived from {src}: {domain}', bullet_type='TITLE', condition=not e.use_json, indent=4)


def _run_rcpt_limit_for_domain(e, smtp: smtplib.SMTP, domain: str, max_rcpt_attempts: int=RCPT_LIMIT_DEFAULT_ATTEMPTS, live_label: list[str] | None=None, attempt_hook=None, recipients: list[str] | None=None, emit_debug=None, *, send_data_at_end: bool=False, envelope_mail_from: str | None=None) -> RcptLimitResult:
    """Run MAIL FROM + RCPT TO loop for a given domain. Used so we can retry with parent domain.
        Continues on 554/550/553/450 (policy rejection) to probe session error limit (smtpd_hard_error_limit).
        Stops with no_session_limit after RCPT_LIMIT_POLICY_REJECT_CAP consecutive policy rejects when none accepted.
        max_rcpt_attempts caps RCPT iterations when the server keeps accepting (per-message limit probe).
        live_label/attempt_hook are passed from test_rcpt_limit for live progress display.
        attempt_hook(i) is called once per attempt with the current attempt index (after
        the SMTP reply is logged when emit_debug is set, so -vv lines stay on their own row).
        emit_debug (optional): callable(text, out=..., title=...) that clears the in-place
        progress row before printing verbose SMTP trace lines.

        recipients (optional): explicit list of full RCPT TO addresses (e.g. real local users from -U name file).
        When set, the probe iterates this list instead of generating synthetic 1@dom..N@dom; this is
        required for MTAs without open relay so that we can actually trigger the per-message limit.
        """
    max_try = max(1, int(max_rcpt_attempts))
    policy_reject_cap = RCPT_LIMIT_POLICY_REJECT_CAP
    explicit_recipients: list[str] = []
    if recipients:
        explicit_recipients = list(recipients)
        max_try = max(1, min(max_try, len(explicit_recipients)))

    def _reply_one_line(raw: str | bytes, limit: int=160) -> str:
        if isinstance(raw, str):
            s = raw.strip().replace('\r\n', ' ').replace('\n', ' ')
        else:
            s = e.bytes_to_str(raw).strip().replace('\r\n', ' ').replace('\n', ' ')
        return s if len(s) <= limit else s[:limit - 3] + '...'

    def _dbg(text: str, out: Out=Out.INFO, *, title: bool=False) -> None:
        if emit_debug is not None:
            emit_debug(text, out=out, title=title)
        else:
            e.ptdebug(text, out, title=title)
    mail_from_addr = (envelope_mail_from or '').strip('<>').strip() if envelope_mail_from else ''
    mail_from_bracket = e._envelope_mail_from_bracket(envelope_mail_from)

    def _attempt_data_send(accepted_count: int) -> tuple[bool, bool, int | None, str | None]:
        if not send_data_at_end or accepted_count <= 0:
            return (False, False, None, None)
        probe_uuid = secrets.token_hex(8)
        raw_msg = e._outbound_minimal_probe(from_addr=mail_from_addr or f'rls@{domain}', message_id_tag='rls', domain=domain, probe_uuid=probe_uuid)
        try:
            dcode, drp = smtp.data(raw_msg)
            drep = e.bytes_to_str(drp).strip()[:500]
            if e.args.debug and (not e.use_json):
                e._stream_smtp_trace_line(e._data_trace_entry(raw_msg, dcode, drp))
            else:
                _dbg(f'Limit-send DATA ({accepted_count} RCPT) → [{dcode}] {_reply_one_line(drep)}', Out.INFO)
            return (True, dcode == 250, dcode, drep)
        except Exception as ex:
            drep = str(ex).strip()[:500]
            _dbg(f'Limit-send DATA failed: {ex}', Out.INFO)
            return (True, False, None, drep)

    def _pack_result(accepted: int, limit_triggered: bool, server_response: str | None, rejected_addresses: bool=False, **extra) -> RcptLimitResult:
        send_attempted, send_ok, send_code, send_reply = _attempt_data_send(accepted)
        return RcptLimitResult(accepted, limit_triggered, server_response, rejected_addresses, limit_send_mode=send_data_at_end, limit_send_attempted=send_attempted, limit_send_ok=send_ok, limit_send_data_code=send_code, limit_send_data_reply=send_reply, limit_send_mail_from=mail_from_addr or None, **extra)
    try:
        status, reply = smtp.docmd('MAIL FROM:', mail_from_bracket)
        if status != 250:
            return _pack_result(0, False, e.bytes_to_str(reply), False)
        _dbg(f'MAIL FROM:{mail_from_bracket} → [{status}] {_reply_one_line(reply)}', Out.INFO)
    except (smtplib.SMTPServerDisconnected, ConnectionResetError, BrokenPipeError, EOFError, OSError) as ex:
        return _pack_result(0, True, str(ex), False)
    accepted = 0
    failed = 0
    limit_response: str | None = None
    first_policy_response: str | None = None

    def _probe_disconnect_after_limit() -> tuple[bool, int]:
        """Send up to RCPT_LIMIT_POSTHIT_PROBE_COUNT extra RCPT TOs after the per-message
            limit has been detected to determine whether the server eventually closes the session.

            Returns (disconnected, attempts_sent):
              - disconnected=True if server returned 421 or closed the socket within the probe;
              - disconnected=False if all probe iterations finished and the session stayed open.
            """
        probe_max = RCPT_LIMIT_POSTHIT_PROBE_COUNT
        for j in range(1, probe_max + 1):
            addr = f'posthit{j}@{domain}'
            try:
                pst, prep = smtp.docmd('RCPT TO:', f'<{addr}>')
                _dbg(f'POSTHIT [{j}/{probe_max}] RCPT TO:<{addr}> → [{pst}] {_reply_one_line(prep)}', Out.INFO)
                if pst == 421:
                    return (True, j)
            except (smtplib.SMTPServerDisconnected, ConnectionResetError, BrokenPipeError, EOFError, OSError):
                _dbg(f'POSTHIT server closed connection after {j} extra rejects', Out.INFO)
                return (True, j)
        return (False, probe_max)
    for i in range(1, max_try + 1):
        if explicit_recipients:
            rcpt_addr = explicit_recipients[i - 1]
        else:
            rcpt_addr = f'{i}@{domain}'
        if live_label is not None:
            live_label[0] = f'accepted {accepted} recipients. Attempt to add recipient: {rcpt_addr}'
        try:
            status, reply = smtp.docmd('RCPT TO:', f'<{rcpt_addr}>')
            reply_str = e.bytes_to_str(reply)
            _dbg(f'[{i}/{max_try}] RCPT TO:<{rcpt_addr}> → [{status}] {_reply_one_line(reply_str)}', Out.INFO)
            if attempt_hook is not None:
                attempt_hook(i)
            if status == 250:
                accepted += 1
                continue
            limit_response = f'[{status}] {reply_str}'.strip()
            if first_policy_response is None and status in (450, 550, 553, 554):
                first_policy_response = limit_response
            if status in (450, 550, 553, 554):
                failed += 1
                if accepted == 0 and failed >= policy_reject_cap:
                    _dbg(f'Server allows {failed} failed RCPTs without disconnect (no smtpd_hard_error_limit)', Out.VULN)
                    return _pack_result(0, False, first_policy_response, rejected_addresses=True, failed_before_limit=failed, session_limit_triggered=False, no_session_limit=True)
                continue
            if status == 421:
                _dbg(f'Server session limit after {i} attempts: {limit_response}', Out.INFO)
                return _pack_result(accepted, True, limit_response, rejected_addresses=accepted == 0, failed_before_limit=i, session_limit_triggered=True, no_session_limit=False)
            if status == 452:
                _dbg(f'Server per-message limit after {accepted} recipients: {limit_response}', Out.INFO)
                result = _pack_result(accepted, True, limit_response, False)
                disc, posthit_n = _probe_disconnect_after_limit()
                return result._replace(disconnect_after_limit=disc, posthit_probe_count=posthit_n)
            if 500 <= status <= 599:
                _dbg(f'Server limit after {accepted} recipients: {limit_response}', Out.INFO)
                result = _pack_result(accepted, True, limit_response, False)
                disc, posthit_n = _probe_disconnect_after_limit()
                return result._replace(disconnect_after_limit=disc, posthit_probe_count=posthit_n)
            return _pack_result(accepted, False, limit_response, False)
        except (smtplib.SMTPServerDisconnected, ConnectionResetError, BrokenPipeError, EOFError, OSError) as ex:
            _dbg(f'Server closed connection after {i} attempts', Out.INFO)
            return _pack_result(accepted, True, str(ex), rejected_addresses=accepted == 0, failed_before_limit=i, session_limit_triggered=True, no_session_limit=False)
    _dbg(f'No limit observed up to {accepted} recipients', Out.VULN)
    return _pack_result(accepted, False, None, False)


def _rl_name_list_source_phrase(e) -> str:
    """Human label for where -rl recipient names came from (-u vs -U)."""
    has_file = bool(getattr(e.args, 'users', None))
    has_cli = bool(e.args.user)
    if has_file and has_cli:
        return 'from -u and username file (-U)'
    if has_file:
        return 'from username file (-U)'
    if has_cli:
        return 'from command line (-u)'
    return 'from name list'


def _rl_build_recipients_from_wordlist(e, domain: str, max_n: int) -> list[str]:
    """Build full RCPT TO addresses from in-memory name list (-u / -U) for MTA-not-relay testing.

        Wordlist entries with ``@`` are kept verbatim (already a full address); bare local parts
        are completed with ``@<domain>`` (banner/EHLO domain). Output is deduplicated and capped
        at ``max_n`` entries to respect the user-provided RCPT TO budget.
        """
    wl = getattr(e, 'wordlist', None) or []
    if not wl:
        return []
    seen: set[str] = set()
    out: list[str] = []
    dom = (domain or '').strip().lower().rstrip('.')
    for entry in wl:
        if not isinstance(entry, str):
            continue
        v = entry.strip()
        if not v:
            continue
        if '@' in v:
            addr = v
        else:
            if not dom:
                continue
            addr = f'{v}@{dom}'
        key = addr.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(addr)
        if len(out) >= max(1, int(max_n)):
            break
    return out


def _rl_probe_accept_all_rcpt(e, smtp: smtplib.SMTP, domain: str, *, envelope_mail_from: str | None=None, emit_debug=None) -> tuple[bool, str | None]:
    """Pre-probe: does the server accept a clearly invalid local part via RCPT TO?

        Uses ``RCPT_LIMIT_ACCEPT_ALL_PROBE_LOCAL@domain`` (e.g. ``xxxfoofff@dom``).
        Leaves the session in a clean state (RSET) when the probe finishes.

        Returns ``(accept_all, rate_limit_error)`` where ``rate_limit_error`` is set when
        ``MAIL FROM`` was rejected with a ``too much mail from`` policy response.
        """
    addr = f'{RCPT_LIMIT_ACCEPT_ALL_PROBE_LOCAL}@{domain}'
    mail_bracket = e._envelope_mail_from_bracket(envelope_mail_from)

    def _reply_one_line(raw: str | bytes, limit: int=160) -> str:
        if isinstance(raw, str):
            s = raw.strip().replace('\r\n', ' ').replace('\n', ' ')
        else:
            s = e.bytes_to_str(raw).strip().replace('\r\n', ' ').replace('\n', ' ')
        return s if len(s) <= limit else s[:limit - 3] + '...'

    def _dbg(text: str, out: Out=Out.INFO) -> None:
        if emit_debug is not None:
            emit_debug(text, out=out)
        elif e.args.debug and (not e.args.json):
            e.ptdebug(text, out)
    try:
        smtp.docmd('RSET')
    except Exception:
        pass
    try:
        status, reply = smtp.docmd('MAIL FROM:', mail_bracket)
        reply_str = e.bytes_to_str(reply)
        mail_rep = _reply_one_line(reply_str)
        if status not in (250, 251):
            rate_err = _rl_extract_too_much_mail_error(reply_str)
            _dbg(f'Accept-all probe MAIL FROM:{mail_bracket} → [{status}] {mail_rep}', Out.INFO)
            return (False, rate_err)
        _dbg(f'Accept-all probe MAIL FROM:{mail_bracket} → [{status}] {mail_rep}', Out.INFO)
        status, reply = smtp.docmd('RCPT TO:', f'<{addr}>')
        reply_str = e.bytes_to_str(reply)
        _dbg(f'Accept-all probe RCPT TO:<{addr}> → [{status}] {_reply_one_line(reply_str)}', Out.INFO)
        accepted = status in (250, 251, 252)
    except Exception as ex:
        _dbg(f'Accept-all probe failed: {ex}', Out.INFO)
        accepted = False
        rate_err = None
    else:
        rate_err = None
    try:
        smtp.docmd('RSET')
    except Exception:
        pass
    return (accepted, rate_err)


def _rl_probe_envelope_mail_from_rate_limit(e, smtp: smtplib.SMTP, envelope_mail_from: str | None) -> str | None:
    """Return rate-limit text when envelope ``MAIL FROM`` is rejected with ``too much mail``."""
    mail_from_addr = (envelope_mail_from or '').strip('<>').strip() if envelope_mail_from else ''
    mail_from_bracket = e._envelope_mail_from_bracket(envelope_mail_from)
    try:
        smtp.docmd('RSET')
    except Exception:
        pass
    try:
        status, reply = smtp.docmd('MAIL FROM:', mail_from_bracket)
        if status != 250:
            return _rl_extract_too_much_mail_error(e.bytes_to_str(reply))
    except Exception:
        pass
    finally:
        try:
            smtp.docmd('RSET')
        except Exception:
            pass
    return None


def _rl_rate_limited_result(e, message: str, *, domain: str, effective_role: str | None, auth_required: bool | None, open_relay: bool | None, recipients_source: str | None) -> RcptLimitResult:
    """Early exit when the server blocks this client with ``too much mail from``."""
    e._ptprint_raw(message, bullet_type='VULN', condition=not e.use_json, indent=4)
    return RcptLimitResult(max_accepted=0, limit_triggered=False, server_response=message, rejected_addresses=False, domain_used=domain, role=effective_role, auth_required=auth_required, open_relay=open_relay, skipped=True, skip_reason='rate_limited', skip_message=message, recipients_source=recipients_source)


def _stream_rcpt_limit_precheck_role(e, effective_role: str | None, auth_required: bool | None) -> None:
    """Print ``[*] Role: …`` immediately after role identification (RCPTLIM pre-check)."""
    show = not e.use_json
    if effective_role is not None:
        e._ptprint_raw(_rl_role_label(effective_role, e.args.target.port, auth_required, rcpt_limit_submission=effective_role == 'submission'), bullet_type='TITLE', condition=show, indent=4)
    else:
        e._ptprint_raw('Role: could not be determined (pre-check failed)', bullet_type='TITLE', condition=show, indent=4)


def _stream_rcpt_limit_precheck_open_relay(e, open_relay: bool | None, domain: str, domain_source: str) -> None:
    """Print open-relay verdict and domain source right after open-relay probe."""
    show = not e.use_json
    if open_relay is True:
        e._ptprint_raw('Open relay: vulnerable (synthetic recipients accepted)', bullet_type='TITLE', condition=show, indent=4)
        _stream_rcpt_limit_domain_source(e, domain, domain_source)
    elif open_relay is False:
        e._ptprint_raw('Open relay: not vulnerable', bullet_type='TITLE', condition=show, indent=4)
        _stream_rcpt_limit_domain_source(e, domain, domain_source)


def _rl_run_precheck(e, domain: str, domain_source: str) -> dict:
    """Pre-check before -rl: detect role + (for MTA/hybrid) open-relay verdict.

        Reuses cached ``self.results.role`` / ``self.results.open_relay`` when already populated
        (e.g. from a prior -ri / -or run inside run-all). Honors ``--role`` override.

        Returns a dict with keys: ``role`` (str|None), ``auth_required`` (bool|None),
        ``auth_methods`` (list[str]), ``port_hint`` (str), ``open_relay`` (bool|None).
        """
    out: dict = {'role': None, 'auth_required': None, 'auth_methods': [], 'port_hint': None, 'open_relay': None}
    forced_role = getattr(e.args, 'smtp_role', None)
    role_obj = e.results.role
    if role_obj is None:
        try:
            if not getattr(e.results, 'info', None):
                _, info = e.initial_info(get_commands=True)
                e.results.info = InfoResult(info.banner, info.ehlo, getattr(info, 'ehlo_starttls', None))
                e.results.resolved_domain = e._get_domain_from_banner_or_ptr(e.results.info)
                e.results.banner_requested = False
                e.results.commands_requested = False
            pre_smtp = e.get_smtp_handler()
            try:
                pre_smtp.docmd('EHLO', e.fqdn)
                role_obj = test_role(e, pre_smtp, e.results.info)
                e.results.role = role_obj
            finally:
                try:
                    pre_smtp.close()
                except Exception:
                    pass
        except Exception as ex:
            e.ptdebug(f'Pre-check role detection failed: {ex}', Out.INFO)
    if role_obj is not None:
        out['role'] = forced_role or role_obj.role
        out['auth_required'] = role_obj.auth_required
        out['port_hint'] = getattr(role_obj, 'port_hint', None)
        if (rl_err := _rl_extract_too_much_mail_error(role_obj.detail)):
            out['rate_limit_error'] = rl_err
    elif forced_role:
        out['role'] = forced_role
    _stream_rcpt_limit_precheck_role(e, out.get('role'), out.get('auth_required'))
    effective_role = out['role']
    if effective_role in ('mta', 'hybrid'):
        if e.results.open_relay is not None:
            out['open_relay'] = e.results.open_relay
        else:
            try:
                or_smtp = e.get_smtp_handler()
                try:
                    or_smtp.docmd('EHLO', e.fqdn)
                    open_relay = open_relay_test(e, or_smtp, None, None)
                    e.results.open_relay = open_relay
                    out['open_relay'] = open_relay
                finally:
                    try:
                        or_smtp.close()
                    except Exception:
                        pass
            except Exception as ex:
                e.ptdebug(f'Pre-check open-relay probe failed: {ex}', Out.INFO)
        _stream_rcpt_limit_precheck_open_relay(e, out.get('open_relay'), domain, domain_source)
    return out


def _rl_role_label(role: str | None, port: int | str, auth_required: bool | None, *, rcpt_limit_submission: bool=False) -> str:
    """Format `[*] Role: ...` info line for the pre-check verdict.

        For ``-rl`` with effective ``submission`` role, EHLO may still report
        ``AUTH not required`` while the RCPT TO probe is intentionally run only
        after ``LOGIN`` (``-u``/``-p``). In that case avoid a misleading
        one-line ``AUTH not required`` that contradicts the skip message.
        """
    role_str = role or 'unknown'
    if role_str == 'indeterminate':
        return f'Role: undetermined (port {port}) — could not classify server (MTA / Submission / Hybrid)'
    if rcpt_limit_submission and role_str == 'submission':
        if auth_required is True:
            auth_label = 'EHLO: AUTH — -rl probe uses -u/-p'
        elif auth_required is False:
            auth_label = 'EHLO: AUTH not advertised — -rl probe still needs -u/-p (or --rl-no-precheck)'
        else:
            auth_label = 'EHLO: AUTH unclear — -rl probe needs -u/-p (or --rl-no-precheck)'
        return f'Role: {role_str} (port {port}, {auth_label})'
    if role_str == 'mta' and auth_required is None:
        auth_label = 'EHLO: AUTH not advertised — MTA (RCPT-auth probe skipped)'
        return f'Role: {role_str} (port {port}, {auth_label})'
    if auth_required is True:
        auth_label = 'AUTH required'
    elif auth_required is False:
        auth_label = 'AUTH not required'
    else:
        auth_label = 'AUTH inconclusive'
    return f'Role: {role_str} (port {port}, {auth_label})'


def test_rcpt_limit(e) -> RcptLimitResult:
    """
        Test RCPT TO limit per message: send MAIL FROM then many RCPT TO
        until server rejects (452 Too many recipients, 421, 5xx) or closes.

        When ``--rl-no-precheck`` is not set, the test first detects the server role
        (and, for MTA/hybrid roles, the open-relay verdict) so it can:
          • run on Submission only after authentication (``-u``/``-p``);
          • use real local recipients from ``-u`` / ``-U`` (valid local usernames) for an MTA that is not an open relay
            (synthetic ``1@dom`` would be rejected as "Relay denied");
          • when ``-u`` / ``-U`` is given, use that name list even if role is indeterminate or open-relay;
          • fall back to synthetic ``1@dom`` only when role is indeterminate/open-relay and no name list was provided.

        When the server is an MTA-not-relay and no valid local usernames are provided via ``-u``/``-U``,
        the test ends with an explicit "skipped" verdict (no false-positive vuln).
        """
    _show_progress = not e.args.json
    _start_time = time.perf_counter()
    _live_label: list[str] = ['Connecting...']
    _ticker_stop = threading.Event()
    _attempt_ref: list[int] = [0]
    _eta_ref: list[float | None] = [None]
    _max_probe_ref: list[int] = [RCPT_LIMIT_DEFAULT_ATTEMPTS]
    _print_lock = threading.Lock()
    _live_dirty = False

    def _render_progress() -> None:
        nonlocal _live_dirty
        attempt = _attempt_ref[0]
        max_p = _max_probe_ref[0]
        eta = _eta_ref[0]
        if attempt > 0 and max_p > 0:
            pct = min(100, int(attempt * 100 / max_p))
            if eta is not None and eta >= 0:
                eta_str = e._format_enum_clock_duration(eta)
                prefix = f'    {eta_str} {pct}% ({attempt}/{max_p})  '
            else:
                prefix = f'    --:--:-- {pct}% ({attempt}/{max_p})  '
        else:
            prefix = '    '
        line = f'{prefix}{_live_label[0]}'
        with _print_lock:
            sys.stdout.write(f'\x1b[2K\r{line:<120}')
            sys.stdout.flush()
            _live_dirty = True

    def _clear_progress_line() -> None:
        nonlocal _live_dirty
        if not _show_progress or not _live_dirty:
            return
        with _print_lock:
            if _live_dirty:
                sys.stdout.write('\x1b[2K\r')
                sys.stdout.flush()
                _live_dirty = False

    def _emit_probe_debug(text: str, out: Out=Out.INFO, *, title: bool=False) -> None:
        """Verbose SMTP trace that won't garble the in-place progress row."""
        nonlocal _live_dirty
        if not e.args.debug or e.args.json:
            return
        with _print_lock:
            if _show_progress and _live_dirty:
                sys.stdout.write('\x1b[2K\r')
                sys.stdout.flush()
                _live_dirty = False
        if title or not e._smtp_trace_line_as_vv(text):
            e.ptdebug(text, out, title=title)

    def _update_attempt(i: int) -> None:
        elapsed = time.perf_counter() - _start_time
        _attempt_ref[0] = i
        max_p = _max_probe_ref[0]
        remaining = max_p - i
        if i > 0:
            _eta_ref[0] = max(0.0, remaining * (elapsed / i))
        _render_progress()

    def _ticker() -> None:
        while not _ticker_stop.wait(timeout=0.2):
            _render_progress()

    def _end_progress() -> None:
        nonlocal _live_dirty
        _ticker_stop.set()
        with _print_lock:
            sys.stdout.write(f"\x1b[2K\r{' ' * 120}\r")
            sys.stdout.flush()
            _live_dirty = False
    no_precheck = bool(getattr(e.args, 'rl_no_precheck', False))
    forced_role = getattr(e.args, 'smtp_role', None)
    if _rcpt_limit_send_mode(e.args):
        e.ptdebug('RCPT TO limit test (per message, with DATA send)', title=True)
    else:
        e.ptdebug('RCPT TO limit test (per message)', title=True)
    e._ensure_initial_info(fail_label='-rl precheck')
    domain, domain_source = e._resolve_rcpt_limit_domain()
    send_mode = _rcpt_limit_send_mode(e.args)
    max_rcpt_attempts = _rcpt_limit_max_attempts(e.args)
    envelope_mail_from: str | None = None
    mail_from_raw = (getattr(e.args, 'mail_from', None) or '').strip()
    if mail_from_raw and '@' in mail_from_raw:
        envelope_mail_from = mail_from_raw.strip('<>').strip()
    _max_probe_ref[0] = max_rcpt_attempts
    precheck: dict = {}
    effective_role: str | None = None
    auth_required: bool | None = None
    open_relay: bool | None = None
    recipients: list[str] | None = None
    recipients_source = 'synthetic'
    rl_wordlist_notice: tuple[list[str], int] | None = None
    rate_limit_msg: str | None = None
    if no_precheck:
        e._ptprint_raw('Pre-check skipped (--rl-no-precheck)', bullet_type='TITLE', condition=not e.use_json, indent=4)
    else:
        precheck = _rl_run_precheck(e, domain, domain_source)
        effective_role = precheck.get('role')
        auth_required = precheck.get('auth_required')
        open_relay = precheck.get('open_relay')
        rate_limit_msg = precheck.get('rate_limit_error')
        if effective_role in ('mta', 'hybrid') and open_relay is False:
            recipients = _rl_build_recipients_from_wordlist(e, domain, max_rcpt_attempts)
            if recipients:
                recipients_source = 'wordlist'
                wl_n = len(getattr(e, 'wordlist', None) or [])
                rl_wordlist_notice = (recipients, wl_n)
            else:
                msg = 'Server is not an open relay; the test cannot run with synthetic recipients. Use -u or -U with valid local usernames (or --rl-no-precheck to attempt a raw probe).'
                e._ptprint_raw(f'Skipping: {msg}', bullet_type='TITLE', condition=not e.use_json, indent=4)
                return RcptLimitResult(max_accepted=0, limit_triggered=False, server_response=None, rejected_addresses=False, domain_used=domain, role=effective_role, auth_required=auth_required, open_relay=open_relay, skipped=True, skip_reason='mta_not_relay_no_wordlist', skip_message=msg, recipients_source=None)
        elif effective_role == 'submission':
            user, _pw = e._rl_first_creds()
            if not user or not _pw:
                msg = 'Submission server requires authenticated session for RCPT TO probe. Pass -u/--user and -p/--password (or --rl-no-precheck for an anonymous probe).'
                e._ptprint_raw(f'Skipping: {msg}', bullet_type='TITLE', condition=not e.use_json, indent=4)
                return RcptLimitResult(max_accepted=0, limit_triggered=False, server_response=None, rejected_addresses=False, domain_used=domain, role=effective_role, auth_required=auth_required, open_relay=open_relay, skipped=True, skip_reason='submission_auth_required', skip_message=msg, recipients_source=None)
        elif effective_role == 'indeterminate':
            pass
        if rate_limit_msg:
            return _rl_rate_limited_result(e, rate_limit_msg, domain=domain, effective_role=effective_role, auth_required=auth_required, open_relay=open_relay, recipients_source=None)
    if recipients is None:
        wl_recipients = _rl_build_recipients_from_wordlist(e, domain, max_rcpt_attempts)
        if wl_recipients:
            recipients = wl_recipients
            recipients_source = 'wordlist'
            wl_n = len(getattr(e, 'wordlist', None) or [])
            rl_wordlist_notice = (recipients, wl_n)
    if not no_precheck and effective_role == 'indeterminate' and (recipients_source == 'synthetic') and (not rate_limit_msg):
        e._ptprint_raw('Continuing with generic RCPT TO probe — use -U/-u for local recipients or -R to force role', bullet_type='TITLE', condition=not e.use_json, indent=4)
    smtp: smtplib.SMTP | None = None
    auth_used = False
    try:
        smtp = e.get_smtp_handler()
        smtp.docmd('EHLO', e.fqdn)
        if not no_precheck and effective_role == 'submission':
            user, passwd = e._rl_first_creds()
            if user and passwd:
                try:
                    if _show_progress:
                        _live_label[0] = f'Authenticating as {user}...'
                        _render_progress()
                    smtp.login(user, passwd)
                    auth_used = True
                    _emit_probe_debug(f'AUTH LOGIN succeeded for user {user}', Out.INFO)
                except Exception as ex:
                    msg = f'AUTH LOGIN failed for {user}: {ex}'
                    _emit_probe_debug(msg, Out.INFO)
                    if _show_progress:
                        _end_progress()
                    e._ptprint_raw(msg, bullet_type='VULN', condition=not e.use_json, indent=4)
                    return RcptLimitResult(max_accepted=0, limit_triggered=False, server_response=str(ex), rejected_addresses=False, domain_used=domain, role=effective_role, auth_required=auth_required, open_relay=open_relay, skipped=True, skip_reason='auth_failed', skip_message=msg, recipients_source=None)
        _probe_emit_debug = _emit_probe_debug if e.args.debug and _show_progress else None
        accept_all_via_rcpt, accept_all_rate_err = _rl_probe_accept_all_rcpt(e, smtp, domain, envelope_mail_from=envelope_mail_from, emit_debug=_probe_emit_debug)
        if accept_all_rate_err:
            return _rl_rate_limited_result(e, accept_all_rate_err, domain=domain, effective_role=effective_role, auth_required=auth_required, open_relay=open_relay, recipients_source=recipients_source)
        if (env_rate_err := _rl_probe_envelope_mail_from_rate_limit(e, smtp, envelope_mail_from)):
            return _rl_rate_limited_result(e, env_rate_err, domain=domain, effective_role=effective_role, auth_required=auth_required, open_relay=open_relay, recipients_source=recipients_source)
        if accept_all_via_rcpt and open_relay is not True:
            _stream_rcpt_limit_catch_all_notice(e)
        if rl_wordlist_notice is not None:
            recs, wl_n = rl_wordlist_notice
            _stream_rcpt_limit_wordlist_notices(e, recs, wl_n)
        if recipients:
            _max_probe_ref[0] = max(1, min(max_rcpt_attempts, len(recipients)))
        else:
            _max_probe_ref[0] = max_rcpt_attempts
        _live_label[0] = 'accepted 0 recipients...'
        if _show_progress:
            threading.Thread(target=_ticker, daemon=True).start()
        result = _run_rcpt_limit_for_domain(e, smtp, domain, max_rcpt_attempts=max_rcpt_attempts, live_label=_live_label, attempt_hook=_update_attempt if _show_progress else None, recipients=recipients, emit_debug=_probe_emit_debug, send_data_at_end=send_mode, envelope_mail_from=envelope_mail_from)
        domain_used = domain
        if recipients is None and getattr(result, 'rejected_addresses', False) and (not getattr(result, 'no_session_limit', False)) and (not getattr(result, 'session_limit_triggered', False)) and (not getattr(e.args, 'domain', None)) and (domain.count('.') >= 2):
            parent = e._to_parent_domain(domain)
            if parent != domain:
                _emit_probe_debug(f'Retrying RCPT TO limit with parent domain: {parent}', Out.INFO)
                try:
                    smtp.docmd('RSET')
                except Exception:
                    pass
                _live_label[0] = 'accepted 0 recipients...'
                _attempt_ref[0] = 0
                _eta_ref[0] = None
                _max_probe_ref[0] = max_rcpt_attempts
                result = _run_rcpt_limit_for_domain(e, smtp, parent, max_rcpt_attempts=max_rcpt_attempts, live_label=_live_label, attempt_hook=_update_attempt if _show_progress else None, emit_debug=_probe_emit_debug, send_data_at_end=send_mode, envelope_mail_from=envelope_mail_from)
                domain_used = parent
        return RcptLimitResult(result.max_accepted, result.limit_triggered, result.server_response, getattr(result, 'rejected_addresses', False), domain_used, getattr(result, 'failed_before_limit', 0), getattr(result, 'session_limit_triggered', False), getattr(result, 'no_session_limit', False), role=effective_role, auth_required=auth_required, auth_used=auth_used, open_relay=open_relay, skipped=False, skip_reason=None, skip_message=None, recipients_source=recipients_source, disconnect_after_limit=getattr(result, 'disconnect_after_limit', None), posthit_probe_count=getattr(result, 'posthit_probe_count', 0), accept_all_via_rcpt=accept_all_via_rcpt, limit_send_mode=getattr(result, 'limit_send_mode', send_mode), limit_send_attempted=getattr(result, 'limit_send_attempted', False), limit_send_ok=getattr(result, 'limit_send_ok', False), limit_send_data_code=getattr(result, 'limit_send_data_code', None), limit_send_data_reply=getattr(result, 'limit_send_data_reply', None), limit_send_mail_from=getattr(result, 'limit_send_mail_from', envelope_mail_from))
    finally:
        if _show_progress:
            _end_progress()
        if smtp is not None:
            try:
                smtp.close()
            except Exception:
                pass


def _rcpt_response_suggests_bad_domain(response: str | None) -> bool:
    """True when the RCPT server response indicates a domain-level rejection
        (wrong / unroutable domain) rather than a user-level rejection.
        Used to decide whether to show the -d/--domain hint.

        A '550 User unknown' answer means the domain IS known to the server –
        only the local part is absent – so no domain hint is needed.
        Responses that do suggest a bad domain include relay-policy errors,
        unresolvable-domain notices, and catch-all domain rejections."""
    if not response:
        return False
    up = response.upper()
    DOMAIN_INDICATORS = ('RELAY ACCESS DENIED', 'RELAY DENIED', 'RELAYING DENIED', 'RELAY NOT PERMITTED', 'NOT PERMITTED TO RELAY', 'RELAYING NOT PERMITTED', 'UNABLE TO RELAY', 'USER NOT LOCAL', 'NO SUCH DOMAIN', 'DOMAIN NOT FOUND', 'DOMAIN DOES NOT EXIST', 'DOMAIN UNKNOWN', 'UNKNOWN DOMAIN', 'UNROUTEABLE', 'UNRESOLVABLE', 'CANNOT ROUTE', 'INVALID DOMAIN', 'BAD DESTINATION', 'NO ROUTE TO HOST', 'HOST NOT FOUND', 'NAME OR SERVICE NOT KNOWN')
    return any((kw in up for kw in DOMAIN_INDICATORS))


def _rcpt_limit_recipient_verdict_bullet(max_accepted: int) -> str:
    """Bullet type from accepted RCPT count before limit/cap: ≤100 OK, 101–500 warn, >500 error."""
    n = max_accepted if max_accepted is not None else 0
    if n <= RCPT_LIMIT_VERDICT_OK_MAX:
        return 'NOTVULN'
    if n <= RCPT_LIMIT_VERDICT_WARN_MAX:
        return 'WARNING'
    return 'VULN'


def _stream_rcpt_limit_catch_all_notice(e) -> None:
    """Print when pre-probe RCPT TO accepts a clearly invalid local part."""
    e._ptprint_raw('Server accepts non-exist recipients in RCPT TO (likely Catch-all is configured)', bullet_type='TITLE', condition=not e.use_json, indent=4)


def _stream_rcpt_limit_wordlist_notices(e, recipients: list[str], wordlist_size: int) -> None:
    """Deferred MTA-not-relay wordlist info (after accept-all pre-probe)."""
    pp = e._ptprint_raw
    show = not e.use_json
    pp(f'Using {len(recipients)} recipient(s) {_rl_name_list_source_phrase(e)} for MTA-not-relay probe', bullet_type='TITLE', condition=show, indent=4)
    if wordlist_size < RCPT_LIMIT_MIN_RECOMMENDED_NAME_COUNT:
        pp(f'For a valid test, a username list with more than {RCPT_LIMIT_MIN_RECOMMENDED_NAME_COUNT} valid recipients is required', bullet_type='TITLE', condition=show, indent=4)


def _maybe_stream_rcpt_limit_domain_hint(e, server_response: str | None) -> None:
    """Print -d/--domain hint when auto domain looks wrong (relay / unroutable)."""
    if getattr(e.args, 'domain', None):
        return
    if not _rcpt_response_suggests_bad_domain(server_response):
        return
    e._ptprint_raw('Try -d/--domain <domain> to set recipient domain for this test', bullet_type='TITLE', condition=not e.use_json, indent=4)


def _stream_rcpt_limit_catch_all_delivery_hint(e, rlim: RcptLimitResult) -> None:
    """Manual catch-all bounce follow-up when optional ``-m`` was passed with ``-rl``."""
    bounce_mb = getattr(rlim, 'catch_all_bounce_mailbox', None)
    if not bounce_mb:
        return
    pp = e._ptprint_raw
    show = not e.use_json
    probe_local = RCPT_LIMIT_ACCEPT_ALL_PROBE_LOCAL
    probe_domain = getattr(rlim, 'domain_used', None) or 'domain'
    probe_addr = getattr(rlim, 'catch_all_delivery_rcpt', None) or f'{probe_local}@{probe_domain}'
    if getattr(rlim, 'catch_all_delivery_attempted', False):
        if getattr(rlim, 'catch_all_delivery_data_ok', False):
            pp(f'Check mailbox {bounce_mb} for delivered message', bullet_type='TITLE', condition=show, indent=4)
        else:
            pp(f'Catch-all bounce probe: could not complete delivery to {probe_addr} (MAIL FROM: {bounce_mb}) — manual bounce check may be inconclusive', bullet_type='WARNING', condition=show, indent=4)
    elif not getattr(rlim, 'accept_all_via_rcpt', False):
        pp(f'Catch-all bounce probe skipped: RCPT TO did not accept {probe_local}@{probe_domain} (no message sent; -m not used for bounce check)', bullet_type='TITLE', condition=show, indent=4)


def _stream_rcpt_limit_server_response_verbose(e, server_response: str | None) -> None:
    """Full SMTP reply lines only with -vv/--verbose (``args.debug``)."""
    if not server_response:
        return
    for line in (server_response or '').replace('\r', '').splitlines():
        e.ptdebug(line, Out.TEXT)


def _stream_rcpt_limit_result(e) -> None:
    pp = e._ptprint_raw
    show = not e.use_json
    rcptmax_advertised = None
    if (info := getattr(e.results, 'info', None)) and getattr(info, 'ehlo', None):
        rcptmax_advertised = _parse_rcptmax_from_ehlo(info.ehlo)
    if (rcpt_limit_err := e.results.rcpt_limit_error) is not None:
        if rcptmax_advertised is not None:
            pp(f'Advertised in EHLO (RFC 9422): RCPTMAX={rcptmax_advertised}', bullet_type='TITLE', condition=show, indent=4)
        pp(f'Test failed: {rcpt_limit_err}', bullet_type='VULN', condition=show, indent=4)
        return
    rlim = e.results.rcpt_limit
    if rlim is None:
        return
    if getattr(rlim, 'skipped', False):
        return
    if getattr(rlim, 'auth_used', False):
        pp('Authenticated session used for RCPT TO probe', bullet_type='TITLE', condition=show, indent=4)
    if rcptmax_advertised is not None:
        pp(f'Advertised in EHLO (RFC 9422): RCPTMAX={rcptmax_advertised}', bullet_type='TITLE', condition=show, indent=4)
    if getattr(rlim, 'session_limit_triggered', False):
        attempts = getattr(rlim, 'failed_before_limit', 0)
        attempts_suffix = f' (after {attempts} attempts)' if attempts else ''
        pp(f'Session limit enforced (421 or disconnect){attempts_suffix}', bullet_type='NOTVULN', condition=show, indent=4)
        _stream_rcpt_limit_server_response_verbose(e, rlim.server_response)
    elif getattr(rlim, 'rejected_addresses', False) and getattr(rlim, 'no_session_limit', False):
        attempts = getattr(rlim, 'failed_before_limit', 0)
        if attempts:
            pp(f'Could not test per-message limit: server rejects {attempts} tested addresses (allowed {attempts} failed RCPTs without disconnect)', bullet_type='WARNING', condition=show, indent=4)
        else:
            pp('Could not test per-message limit: server rejects tested addresses (allowed failed RCPTs without disconnect)', bullet_type='WARNING', condition=show, indent=4)
        _maybe_stream_rcpt_limit_domain_hint(e, rlim.server_response)
    elif rlim.limit_triggered:
        pp(f'Max {rlim.max_accepted} recipients per message (next recipients are rejected)', bullet_type=_rcpt_limit_recipient_verdict_bullet(rlim.max_accepted), condition=show, indent=4)
        disc = getattr(rlim, 'disconnect_after_limit', None)
        if disc is True:
            pp('Connection was disconnected after many invalid recipients', bullet_type='NOTVULN', condition=show, indent=4)
        elif disc is False:
            pp('Connection is not disconnected after many invalid recipients', bullet_type='VULN', condition=show, indent=4)
        _stream_rcpt_limit_server_response_verbose(e, rlim.server_response)
        if rlim.max_accepted == 0:
            _maybe_stream_rcpt_limit_domain_hint(e, rlim.server_response)
    elif rlim.max_accepted == 0:
        rl_err = _rl_extract_too_much_mail_error(rlim.server_response)
        if rl_err:
            pp(rl_err, bullet_type='VULN', condition=show, indent=4)
        else:
            pp('Could not test: no recipients accepted', bullet_type='TITLE', condition=show, indent=4)
        _stream_rcpt_limit_server_response_verbose(e, rlim.server_response)
        if not rl_err:
            _maybe_stream_rcpt_limit_domain_hint(e, rlim.server_response)
    pp(f'Accepted recipients: {rlim.max_accepted}', bullet_type=_rcpt_limit_recipient_verdict_bullet(rlim.max_accepted), condition=show, indent=4)
    if getattr(rlim, 'limit_send_mode', False):
        mail_from = getattr(rlim, 'limit_send_mail_from', None) or '?'
        if getattr(rlim, 'limit_send_attempted', False):
            if getattr(rlim, 'limit_send_ok', False):
                pp(f'Message with {rlim.max_accepted} recipient(s) accepted by server (DATA 250, MAIL FROM: {mail_from})', bullet_type='NOTVULN', condition=show, indent=4)
                pp(f'Check mailbox {mail_from} for NDR, bounce, or other delivery status notifications', bullet_type='TITLE', condition=show, indent=4)
            else:
                code = getattr(rlim, 'limit_send_data_code', None)
                reply = (getattr(rlim, 'limit_send_data_reply', None) or '').strip()
                code_s = str(code) if code is not None else '?'
                pp(f'Message delivery failed after {rlim.max_accepted} accepted RCPT TO (DATA [{code_s}] {reply})'.rstrip(), bullet_type='VULN', condition=show, indent=4)
        elif rlim.max_accepted == 0:
            pp('Message not sent: no RCPT TO accepted in this transaction', bullet_type='TITLE', condition=show, indent=4)
    _stream_rcpt_limit_catch_all_delivery_hint(e, rlim)


def run(ctx):
    e = eng(ctx)
    if not ctx.json:
        ctx.out(e._rcpt_limit_section_title(), "INFO", colortext=True)
    e._load_wordlist()
    try:
        e.results.rcpt_limit = test_rcpt_limit(e)
    except Exception as ex:
        e.results.rcpt_limit_error = str(ex)
        ctx.out(f"RCPTLIM failed: {ex}", "ERROR", indent=4)
        return
    _stream_rcpt_limit_result(e)
