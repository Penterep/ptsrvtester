"""ENUM — VRFY / EXPN / RCPT user enumeration."""
import os, queue, random, re, smtplib, socket, sys, threading, time
from typing import Callable

from ..._base import Out
from ..utils.helpers import get_mode
from ..utils.progress import ThreadedProgress

from ..utils.helpers import *
from ..utils.results import *
from ..utils.registry import *

from ._common import eng


__MODULELABEL__ = "User Enumeration & Catch All mailbox"
__MODULECODE__ = "ENUM"
__ORDER__ = 90


def _close_inplace_debug(e) -> None:
    """End a -vv line that was left on ``\\r`` so the next message starts below it."""
    if getattr(e.args, "debug", False) and not e.use_json:
        sys.stdout.write("\n")
        sys.stdout.flush()


def expn_vrfy_slow_down_test(e, method: str, smtp):
    if sum(e.slow_down_results.values()) >= 1:
        e.ptdebug(f'New smtp handle required, initiating new smtp connection ...', Out.INFO)
        smtp = e.get_smtp_handler()
        smtp.docmd('EHLO', f'{e.fqdn}')
    e.ptdebug(f"[{method}] SLOW DOWN TEST {' ' * 6}", Out.INFO, end='\r')
    dummy_data = [''.join(random.choices('abcdefghijk', k=random.randint(1, 5))) for i in range(29)]
    half = int(len(dummy_data) / 2)
    is_slow_down = False
    is_unstable_response = False
    initial_time = 0
    last_request_time = 0
    first_half_time = 0
    second_half_time = 0
    for index, user in enumerate(dummy_data):
        endl = '\n' if index + 1 == len(dummy_data) else '\r'
        e.ptdebug(f'[{method}] SLOW DOWN TEST [{index + 1}/{len(dummy_data)}]', Out.INFO, end=endl)
        start_time = time.time()
        try:
            smtp.docmd(method, user)
        except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError):
            _close_inplace_debug(e)
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
            _close_inplace_debug(e)
            e.ptdebug(f'[{method}] SLOW DOWN TEST [{index + 1}/{index + 1}]', Out.INFO)
            e.ptdebug(f'Unstable response (>3sec), break', Out.VULN)
            is_slow_down = True
            break
    if second_half_time - first_half_time > initial_time * 10:
        is_slow_down = True
    if is_slow_down:
        e.ptdebug(f'{method} Method have slow-down protection implemented', Out.NOTVULN)
    e.ptdebug(f'First request response time: {str(initial_time)[:8]}', Out.INFO)
    e.ptdebug(f'Last request response time:  {str(last_request_time)[:8]}', Out.INFO)
    return {method.lower(): is_slow_down}


def rcpt_slow_down_test(e, smtp):
    if sum(e.slow_down_results.values()) >= 1:
        smtp = e.get_smtp_handler()
        smtp.docmd('EHLO', f'{e.fqdn}')
    domain = e._get_rcpt_limit_domain()
    try:
        smtp.docmd('RSET')
    except Exception:
        pass
    ok_mail, _ = e._try_mail_from_for_rcpt_probe(smtp, domain)
    if not ok_mail:
        e.ptdebug('[RCPT] SLOW DOWN TEST: no MAIL FROM candidate accepted', Out.INFO)
        return {'rcpt': False}
    e.ptdebug(f"[RCPT] SLOW DOWN TEST {' ' * 6}", Out.INFO, end='\r')
    dummy_data = [''.join(random.choices('abcdefghijk', k=random.randint(1, 5))) for i in range(20)]
    half = int(len(dummy_data) / 2)
    time_data = []
    is_slow_down = False
    first_half_time = 0
    initial_time = 0
    second_half_time = 0
    last_request_time = 0
    is_unstable_response = False
    for index, user in enumerate(dummy_data):
        endl = '\n' if index + 1 == len(dummy_data) else '\r'
        e.ptdebug(f'[RCPT] SLOW DOWN TEST [{index + 1}/{len(dummy_data)}]', Out.INFO, end=endl)
        start_time = time.time()
        try:
            status, reply = smtp.docmd('RCPT TO:', f'<{user}@{domain}>')
        except Exception:
            _close_inplace_debug(e)
            raise
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
            _close_inplace_debug(e)
            is_slow_down = True
            break
    if second_half_time - first_half_time > initial_time * 10:
        is_slow_down = True
    if is_slow_down:
        e.ptdebug(f'[RCPT] Method have slow-down protection implemented', Out.NOTVULN)
    e.ptdebug(f'First request response time: {str(initial_time)[:8]}', Out.INFO)
    e.ptdebug(f'Last request response time:  {str(last_request_time)[:8]}', Out.INFO)
    return {'rcpt': is_slow_down}


def _enumeration_requested_method_set(e) -> set[str]:
    return enum_methods_from_arg(e.args.enumerate)


def _wordlist_enumeration_will_run(e, enumeration_vulns: dict[str, bool | None], catch_all: str | None) -> bool:
    """True when do_enumeration will actually iterate the wordlist (not only skip messages)."""
    if enumeration_vulns['expn']:
        return catch_all != 'configured'
    if enumeration_vulns['vrfy']:
        return catch_all != 'configured'
    if enumeration_vulns['rcpt']:
        return catch_all not in (*CATCH_ALL_INDETERMINATE_VARIANTS, 'configured')
    return False


def _stream_enumeration_method_rows(e, enum_results: list[EnumResult], catch_all: str | None) -> None:
    """Print EXPN/VRFY/RCPT status lines (same as first loop in _stream_enumeration_result)."""
    pp = e._ptprint_raw
    show = not e.use_json
    requested_set = _enumeration_requested_method_set(e)
    filtered = [e for e in enum_results if e.method.upper() in requested_set]
    for e in filtered:
        if catch_all == 'configured':
            pp(f'{e.method.upper()} method: Indeterminate (Useless due to Catch All)', bullet_type='WARNING', condition=show, indent=4)
        elif e.blocked_by_rbl:
            pp(f'{e.method.upper()} method protected by RBL/Reputation (Client IP blocked)', bullet_type='NOTVULN', condition=show, indent=4)
            if e.server_reply:
                for line in (e.server_reply or '').replace('\r', '').splitlines():
                    pp(line.strip(), bullet_type='TEXT', condition=show, indent=8)
        else:
            slowdown = ''
            if e.slowdown is not None:
                slowdown = ' (rate limited)' if e.slowdown else ' (not rate limited)'
            verdict_bullet = 'VULN' if e.vulnerable else 'NOTVULN'
            if e.vulnerable:
                if e.server_reply:
                    raw = (e.server_reply or '').replace('\r', '').splitlines()
                    parts = [re.sub(' +', ' ', p.strip()) for p in raw if p.strip()]
                    if parts:
                        if len(parts) == 1:
                            pp(f'{e.method.upper()} method is enabled ({parts[0]}){slowdown}', bullet_type=verdict_bullet, condition=show, indent=4)
                        else:
                            pp(f"{e.method.upper()} method is enabled ({parts[0]}{(')' if len(parts) == 1 else '')}{(slowdown if len(parts) == 1 else '')}", bullet_type=verdict_bullet, condition=show, indent=4)
                            for i, part in enumerate(parts[1:]):
                                is_last = i == len(parts) - 2
                                pp(f"{part}{(')' if is_last else '')}{(slowdown if is_last else '')}", bullet_type='TEXT', condition=show, indent=8)
                    else:
                        pp(f'{e.method.upper()} method is enabled{slowdown}', bullet_type=verdict_bullet, condition=show, indent=4)
                else:
                    pp(f'{e.method.upper()} method is enabled{slowdown}', bullet_type=verdict_bullet, condition=show, indent=4)
            else:
                if e.server_reply and 'Relay protection active' in e.server_reply:
                    status = 'is deny (Relay protection active)'
                elif e.server_reply and 'Administrative prohibition' in e.server_reply:
                    status = 'is deny (Administrative prohibition)'
                else:
                    status = 'is deny'
                pp(f'{e.method.upper()} method {status}{slowdown}', bullet_type=verdict_bullet, condition=show, indent=4)


def _expn_vrfy_result_strings(reply_str: str) -> list[str]:
    """Extract display/enum strings from EXPN/VRFY success reply (bracketed paths, emails, fallback)."""
    found = re.findall('<([^<>]*)>', reply_str)
    found = [x.strip() for x in found if x.strip()]
    if found:
        out: list[str] = []
        seen: set[str] = set()
        for x in found:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out
    for line in reply_str.replace('\r\n', '\n').split('\n'):
        m = re.search('[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}', line)
        if m:
            return [m.group(0)]
    lines = [ln.strip() for ln in reply_str.replace('\r\n', '\n').split('\n') if ln.strip()]
    if lines:
        tail = re.sub('^\\d{3}\\s*', '', lines[0]).strip()
        if tail and len(tail) < 500:
            return [tail]
    return []


def _smtp_command_streaming(smtp, cmd: str, args: str, on_first_hit=None, debug: bool=False, dbg: Callable[[str], None] | None=None) -> tuple[int, bytes]:
    """Send SMTP command and call on_first_hit(line_bytes) on the very first positive
        (non-5xx) response line – before reading continuation lines.
        Returns (errcode, reply_bytes) identical to smtplib.SMTP.docmd.
        Falls back to smtp.docmd when the underlying file object is not accessible.

        debug=True (-vv) enables timestamped tracing; pass ``dbg`` as ``self.ptdebug``
        so lines use the same ADDITIONS styling and indent as other verbose output.
        If ``dbg`` is omitted, falls back to writing raw bytes to stderr (fd 2)."""
    _MAXLINE: int = getattr(smtplib, '_MAXLINE', 8192)

    def _dbg(msg: str) -> None:
        if debug:
            ts = time.perf_counter()
            text = f'[DBG enum {ts:.3f}] {msg}'
            if dbg is not None:
                dbg(text)
            else:
                os.write(2, (text + '\n').encode('utf-8', errors='replace'))
    file = getattr(smtp, 'file', None)
    if file is None:
        _dbg(f'no file object, falling back to docmd({cmd!r})')
        status, reply = smtp.docmd(cmd, args)
        if on_first_hit is not None and (not 500 <= status <= 599):
            _dbg('calling on_first_hit (docmd fallback)')
            t0 = time.perf_counter()
            on_first_hit(reply[:512] if isinstance(reply, bytes) else reply)
            _dbg(f'on_first_hit done ({time.perf_counter() - t0:.3f}s)')
            try:
                sys.stdout.flush()
            except Exception:
                pass
        return (status, reply)
    try:
        sk = getattr(smtp, 'sock', None)
        if sk is not None:
            sk.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except (OSError, AttributeError):
        pass
    smtp.putcmd(cmd, args)
    _dbg(f'putcmd sent: {cmd} {args!r}')
    resp: list[bytes] = []
    first_hit_fired = False
    code = -1
    line_no = 0
    while True:
        line_no += 1
        t_rl = time.perf_counter()
        try:
            line = file.readline(_MAXLINE + 1)
        except (TimeoutError, socket.timeout):
            _dbg(f'readline #{line_no} TIMEOUT after {time.perf_counter() - t_rl:.3f}s (resp so far: {len(resp)} lines)')
            if resp:
                break
            raise smtplib.SMTPServerDisconnected('SMTP readline timed out')
        except OSError as ex:
            _dbg(f'readline #{line_no} OSError after {time.perf_counter() - t_rl:.3f}s: {ex}')
            raise smtplib.SMTPServerDisconnected(f'Connection unexpectedly closed: {ex}')
        _dbg(f'readline #{line_no} took {time.perf_counter() - t_rl:.3f}s → {repr(line[:40])}')
        if not line:
            _dbg(f'readline #{line_no} returned empty (server closed connection)')
            if resp:
                break
            raise smtplib.SMTPServerDisconnected('Connection unexpectedly closed')
        if len(line) > _MAXLINE:
            raise smtplib.SMTPResponseException(500, b'Line too long')
        resp.append(line[4:].strip(b' \t\r\n'))
        try:
            code = int(line[:3])
        except (ValueError, IndexError):
            code = -1
        if not first_hit_fired and on_first_hit is not None and (code != -1) and (not 500 <= code <= 599):
            first_hit_fired = True
            _dbg(f'calling on_first_hit (code={code})')
            t0 = time.perf_counter()
            on_first_hit(line[4:].strip(b' \t\r\n'))
            _dbg(f'on_first_hit done ({time.perf_counter() - t0:.3f}s)')
            try:
                sys.stdout.flush()
            except Exception:
                pass
        is_last = line[3:4] != b'-'
        _dbg(f'line #{line_no} code={code} last={is_last} char4={repr(line[3:4])}')
        if is_last:
            break
    _dbg(f'streaming done: code={code} lines={len(resp)}')
    return (code, b'\n'.join(resp))


def _expn_vrfy_quick_display(reply, fallback_user: str) -> str:
    """Fast display string from raw EXPN/VRFY reply (bounded scan; full parse may follow)."""
    if isinstance(reply, bytes):
        chunk = reply[:16384].decode('utf-8', errors='replace')
    else:
        chunk = str(reply)[:16384]
    for m in re.finditer('<([^<>]{1,512})>', chunk):
        x = m.group(1).strip()
        if x:
            return x
    m = re.search('[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}', chunk)
    if m:
        return m.group(0)
    lines = [ln.strip() for ln in chunk.replace('\r\n', '\n').split('\n') if ln.strip()]
    if lines:
        tail = re.sub('^\\d{3}\\s*', '', lines[0]).strip()
        if tail and len(tail) < 500:
            return tail
    return fallback_user


def _rcpt_reply_has_unknown(reply) -> bool:
    """True if RCPT reply suggests unknown user (scan without full UTF-8 decode when bytes)."""
    if isinstance(reply, bytes):
        return b'UNKNOWN' in reply.upper()
    return 'UNKNOWN' in str(reply).upper()


def _enum_vv_dbg(e, msg: str) -> None:
    """Print one -vv enum trace on its own line. Drop the live progress row first."""
    e._enum_progress_newline()
    e.ptdebug(msg)


def _enum_streaming_emit_first_finding(e, _idx: int, _total: int, display: str) -> None:
    """Print first EXPN/VRFY hit on its own line (no time/%); progress line stays separate."""
    if e.use_json or getattr(e.args, 'enum_threads', 1) > 1:
        return
    e._raw_write(f'\x1b[2K\r    {display}\n'.encode('utf-8', errors='replace'))
    e._enum_progress_line_dirty = False


def _print_enum_finding(e, _idx: int, _total: int, payload: str, *, replace_progress: bool=True) -> None:
    """Print one enumerated value (single-thread); clear the live progress line when replace_progress.

        Multi-thread enumeration prints findings via ``ThreadedProgress`` + ``PrintLock``
        (see ``utils/progress.py``); this path is single-thread only.
        """
    if e.use_json:
        return
    if replace_progress:
        e._raw_write(f'\x1b[2K\r    {payload}\n'.encode('utf-8', errors='replace'))
        e._enum_progress_line_dirty = False
    else:
        e._raw_write(f'    {payload}\n'.encode('utf-8', errors='replace'))


def expn_vrfy_enumeration(e, method, smtp) -> list[str]:
    enum_threads = getattr(e.args, 'enum_threads', 1)
    ehlo = e.results.info and e.results.info.ehlo or ''
    supports_smtputf8 = 'SMTPUTF8' in ehlo.upper()
    if getattr(e, '_wordlist_skipped', 0) > 0:
        e.ptdebug(f'Skipped {e._wordlist_skipped} invalid local parts from wordlist', Out.INFO)
    e.ptdebug(f'Enumerating users:' + (f' ({enum_threads} threads)' if enum_threads > 1 else ''), Out.INFO)
    enumerated_users: list[str] = []
    total_aliases = 0 if method == 'EXPN' else None
    wl_total = len(e.wordlist)

    def _skip_non_ascii_no_utf8(s: str) -> bool:
        return not supports_smtputf8 and any((ord(c) >= 128 for c in s))
    try:
        if enum_threads <= 1:
            if supports_smtputf8:
                smtp.command_encoding = 'utf-8'
            reconnect_after = getattr(e.args, 'enum_reconnect_after', None)
            consecutive_failures = 0
            _enum_stream_debug = getattr(e.args, 'debug', False)
            _enum_stream_dbg = (lambda m: _enum_vv_dbg(e, m)) if _enum_stream_debug else None

            def _do_enum_reconnect() -> None:
                """Reconnect to reset accumulated teergrube / rate-limit state.
                    Called after a successful find (when --enum-reconnect-after is set)
                    and after N consecutive failures."""
                nonlocal smtp, consecutive_failures
                consecutive_failures = 0
                if not e.use_json and enum_threads <= 1:
                    with e._enum_progress_print_lock:
                        if e._enum_clock_state is not None:
                            e._enum_clock_state = dict(e._enum_clock_state)
                            e._enum_clock_state['label'] = 'reconnecting...'
                            e._enum_clock_paint_unlocked()
                try:
                    smtp = e.get_smtp_handler(timeout=15.0)
                    smtp.docmd('EHLO', e.fqdn)
                    if supports_smtputf8:
                        smtp.command_encoding = 'utf-8'
                except Exception:
                    pass
            for idx, user in enumerate(e.wordlist, start=1):
                if _skip_non_ascii_no_utf8(user):
                    continue
                if not e.use_json:
                    e._enum_wait_begin(idx, wl_total, user)
                _cur_idx = idx
                _first_preview: list[str] = []

                def _on_first_hit(line_bytes, _u=user, _i=_cur_idx):
                    display = _expn_vrfy_quick_display(line_bytes, _u)
                    _first_preview.append(display)
                    if not e.use_json:
                        _enum_streaming_emit_first_finding(e, _i, wl_total, display)
                try:
                    status, reply = _smtp_command_streaming(smtp, method, user, on_first_hit=None if e.use_json else _on_first_hit, debug=_enum_stream_debug, dbg=_enum_stream_dbg)
                except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError) as ex:
                    e.ptdebug(f'{method} enumeration interrupted (connection closed/reset): {ex}', Out.INFO)
                    _first_preview.clear()
                    try:
                        smtp = e.get_smtp_handler(timeout=10.0)
                        smtp.docmd('EHLO', f'{e.fqdn}')
                        if supports_smtputf8:
                            smtp.command_encoding = 'utf-8'
                        status, reply = _smtp_command_streaming(smtp, method, user, on_first_hit=None if e.use_json else _on_first_hit, debug=_enum_stream_debug, dbg=_enum_stream_dbg)
                        try:
                            smtp.sock.settimeout(15.0)
                        except Exception:
                            pass
                    except Exception:
                        try:
                            smtp = e.get_smtp_handler(timeout=15.0)
                            smtp.docmd('EHLO', f'{e.fqdn}')
                            if supports_smtputf8:
                                smtp.command_encoding = 'utf-8'
                        except Exception:
                            break
                        status, reply = (550, b'')
                finally:
                    if not e.use_json and enum_threads <= 1:
                        e._enum_wait_end()
                if status != 550:
                    preview = _first_preview[0] if _first_preview else _expn_vrfy_quick_display(reply, user)
                    if not _first_preview and (not e.use_json):
                        _print_enum_finding(e, idx, wl_total, preview)
                    reply_str = e.bytes_to_str(reply)
                    user_email = _expn_vrfy_result_strings(reply_str)
                    if not user_email:
                        user_email = [preview]
                    enumerated_users.extend(user_email)
                    if not e.use_json:
                        for em in user_email:
                            if em != preview:
                                _print_enum_finding(e, idx, wl_total, em, replace_progress=False)
                    elif e.use_json:
                        e.ptdebug(user_email[0])
                    if method == 'EXPN' and len(user_email) > 1:
                        for alias in user_email[1:]:
                            total_aliases += len(user_email[1:])
                            e.ptdebug(f'{alias}', Out.ADDITIONS)
                    if reconnect_after is not None and reconnect_after != -1:
                        _do_enum_reconnect()
                else:
                    consecutive_failures += 1
                    if reconnect_after is not None and reconnect_after > 0 and (consecutive_failures >= reconnect_after):
                        _do_enum_reconnect()
            if not e.use_json and enum_threads <= 1:
                e._enum_progress_newline()
        else:
            valid_users = [u for u in e.wordlist if not _skip_non_ascii_no_utf8(u)]
            work_total = len(valid_users)
            user_queue: queue.Queue[str | None] = queue.Queue()
            for u in valid_users:
                user_queue.put(u)
            for _ in range(enum_threads):
                user_queue.put(None)
            result_lock = threading.Lock()
            progress = ThreadedProgress(work_total, enabled=not e.use_json)
            _enum_stream_debug = getattr(e.args, 'debug', False)
            _enum_stream_dbg = (lambda m: _enum_vv_dbg(e, m)) if _enum_stream_debug else None

            def worker() -> None:
                conn = None
                while True:
                    user = user_queue.get()
                    if user is None:
                        user_queue.task_done()
                        break
                    out = progress.new_output()
                    try:
                        if conn is None:
                            try:
                                conn = e.get_smtp_handler()
                                conn.docmd('EHLO', f'{e.fqdn}')
                                if supports_smtputf8:
                                    conn.command_encoding = 'utf-8'
                            except Exception:
                                continue
                        try:
                            status, reply = _smtp_command_streaming(conn, method, user, on_first_hit=None, debug=_enum_stream_debug, dbg=_enum_stream_dbg)
                        except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError):
                            try:
                                conn = e.get_smtp_handler()
                                conn.docmd('EHLO', f'{e.fqdn}')
                                if supports_smtputf8:
                                    conn.command_encoding = 'utf-8'
                                status, reply = conn.docmd(method, user)
                            except Exception:
                                continue
                        if status != 550:
                            preview = _expn_vrfy_quick_display(reply, user)
                            reply_str = e.bytes_to_str(reply)
                            user_email = _expn_vrfy_result_strings(reply_str)
                            if not user_email:
                                user_email = [preview]
                            with result_lock:
                                enumerated_users.extend(user_email)
                            if e.use_json:
                                e.ptdebug(user_email[0])
                            else:
                                for em in user_email:
                                    out.add_string_to_output(em)
                    finally:
                        if not e.use_json:
                            progress.flush(out, repaint=False)
                            progress.advance(label=user)
                        user_queue.task_done()
            threads_list = [threading.Thread(target=worker) for _ in range(enum_threads)]
            for t in threads_list:
                t.start()
            for t in threads_list:
                t.join()
            if not e.use_json:
                progress.finalize()
            total_aliases = 0
        additional_message = f'(total {len(enumerated_users) + (total_aliases or 0)} with aliases)' if method == 'EXPN' else ''
        e.ptdebug(f' ')
        e.ptdebug(f'-- Enumerated {len(enumerated_users)} emails {additional_message} --')
        e.ptdebug(f' ')
        e.already_enumerated = True
        return enumerated_users
    finally:
        e._enum_clock_shutdown()


def _is_rbl_blocked(reply_text: str) -> bool:
    """Return True when a 5xx reply indicates the client IP is blocked by RBL
        (e.g. Spamhaus, SpamCop). Server rejected before the test could run."""
    up = reply_text.upper()
    RBL_INDICATORS = ('LISTED AT', 'BLACKLIST', 'ON BLACKLIST', 'RBL', 'ZEN.SPAMHAUS', 'BLOCKED', 'SPAMHAUS')
    return any((kw in up for kw in RBL_INDICATORS))


def _is_admin_prohibition(reply_text: str) -> bool:
    """Return True when a 5xx VRFY/EXPN reply indicates an administrative
        block rather than a per-user differentiation response.
        These rejections mean the command is disabled by policy."""
    up = reply_text.upper()
    ADMIN_KEYWORDS = ('ADMINISTRATIVE PROHIBITION', 'DISABLED', 'NOT ALLOWED', 'NOT PERMITTED', 'COMMAND REJECTED', 'COMMAND NOT ACCEPTED', 'COMMAND DISABLED', 'ACCESS DENIED')
    return any((kw in up for kw in ADMIN_KEYWORDS))


def expn_vrfy_test(e, method, smtp) -> bool:
    """Test VRFY/EXPN for user enumeration (OWASP WSTG-IDEN-003).
        RFC 5321: 250/251/252=success, 550/551=user unknown.

        Vulnerable when server returns 550/551 for invalid user AND the response
        indicates a per-user decision (user unknown, etc.).
        NOT vulnerable when the response indicates an administrative prohibition
        (command disabled by policy) -- these are false positives for customer reports."""
    INVALID_PROBES = ('foofoofoo', 'nxuser001', 'nxuser002')
    VRFY_EXPN_ACCEPT = (250, 251, 252)
    VRFY_EXPN_REJECT = (550, 551, 553, 554)
    replies: list[tuple[int, str]] = []
    for probe in INVALID_PROBES:
        try:
            status, reply = smtp.docmd(method, probe)
            reply_str = e.bytes_to_str(reply)
            replies.append((status, reply_str))
            if 'AUTH' in reply_str.upper():
                e.ptdebug(f'Testing {method} method: server requires AUTH', Out.INFO)
                e._enum_test_replies = getattr(e, '_enum_test_replies', {})
                e._enum_test_replies[method.lower()] = f'[{status}] {reply_str.strip()} (Administrative prohibition)'
                return False
        except Exception as ex:
            e.ptdebug(f'Testing {method} method: {ex}', Out.INFO)
            return False
    first_status, first_reply = replies[0]
    e.ptdebug(f'Testing {method} method: [{first_status}] {first_reply}', Out.INFO)
    if all((s in VRFY_EXPN_ACCEPT for s, _ in replies)):
        e.ptdebug(f'Server returns 250 for all invalid addresses - cannot reliably enumerate ({method})', Out.INFO)
        return False
    first_reject = next(((s, r) for s, r in replies if s in VRFY_EXPN_REJECT), None)
    e._enum_test_replies = getattr(e, '_enum_test_replies', {})
    if first_reject is None:
        e.ptdebug(f'Server is not vulnerable to {method} enumeration', Out.INFO)
        return False
    rej_status, rej_text = first_reject
    reject_reply = f'[{rej_status}] {rej_text.strip()}'
    if rej_status in (550, 554) and _is_rbl_blocked(rej_text):
        e.ptdebug(f'{method} blocked by RBL (could not test): {reject_reply}', Out.INFO)
        e._enum_test_replies[method.lower()] = reject_reply
        e._enum_blocked_by_rbl = getattr(e, '_enum_blocked_by_rbl', set())
        e._enum_blocked_by_rbl.add(method.lower())
        return False
    if _is_admin_prohibition(rej_text):
        e.ptdebug(f'{method} blocked by administrative policy: {reject_reply}', Out.INFO)
        e._enum_test_replies[method.lower()] = f'{reject_reply} (Administrative prohibition)'
        return False
    e._enum_test_replies[method.lower()] = reject_reply
    e.ptdebug(f'Server is vulnerable to {method} enumeration: {reject_reply}', Out.VULN)
    return True


def newline_to_reply(e, reply):
    reply = e.bytes_to_str(reply)
    if not reply.endswith('\n'):
        reply += '\n'
    return reply


def _is_relay_or_auth_rejection(reply_text: str) -> bool:
    """Return True when a 5xx reply indicates a global relay/auth policy
        rather than a per-recipient user-unknown decision.
        These rejections do NOT prove user enumeration."""
    up = reply_text.upper()
    RELAY_KEYWORDS = ('RELAY', 'RELAYING', 'NOT PERMITTED', 'NOT ALLOWED', 'AUTHENTICATION REQUIRED', 'AUTH REQUIRED', 'IS NOT LOCAL', 'NOT LOCAL', 'SENDER VERIFY', 'SENDER REJECTED')
    return any((kw in up for kw in RELAY_KEYWORDS))


def _rcpt_enum_reply_for_display(reply_text: str, domain: str, probes: tuple[str, ...]) -> str:
    """Normalize RCPT probe replies for terminal/JSON display: match VRFY/EXPN style (local part only).

        Servers often echo ``<user@domain>`` in RCPT rejects; EXPN/VRFY lines use bare ``user``."""
    if not reply_text or not domain:
        return reply_text
    out = reply_text
    dom = domain.strip()
    for p in probes:
        out = re.sub(re.escape(f'<{p}@{dom}>'), p, out, flags=re.IGNORECASE)
        out = re.sub(re.escape(f'{p}@{dom}'), p, out, flags=re.IGNORECASE)
    if dom:
        out = re.sub(re.compile(f'<([^\\s<>]+)@{re.escape(dom)}>', re.IGNORECASE), lambda m: m.group(1), out)
    return out


def rcpt_test(e, smtp) -> bool:
    """RCPT enum vulnerability (OWASP WSTG-IDEN-003).
        Uses full addresses <probe@domain> so the server evaluates them against its
        virtual mailbox / alias tables.  RFC 5321: 250/251=accepted, 550/551=rejected.

        Vulnerable when server returns 550/551/553/554 for invalid recipients AND
        the response text indicates a per-recipient decision (user unknown, mailbox
        not found, etc.) -- NOT a global relay/auth policy rejection."""
    RCPT_ACCEPT = (250, 251, 252)
    RCPT_REJECT = (550, 551, 553, 554)
    INVALID_PROBES = ('foofoofoo', 'nxuser001', 'nxuser002')
    domain = e._get_rcpt_limit_domain()
    try:
        smtp.docmd('RSET')
    except Exception:
        pass
    ok_mail, _mail_used = e._try_mail_from_for_rcpt_probe(smtp, domain)
    if not ok_mail:
        e._smtp_vv_io('MAIL FROM', 'all candidates rejected')
        return False
    replies: list[tuple[int, str]] = []
    for probe in INVALID_PROBES:
        try:
            status, reply = smtp.docmd('RCPT TO:', f'<{probe}@{domain}>')
            reply_str = e.bytes_to_str(reply)
            e._smtp_vv_io(f'RCPT TO:<{probe}@{domain}>', f'{status} {reply_str.strip()[:400]}')
            replies.append((status, reply_str))
            if 'AUTH' in reply_str.upper():
                e._enum_test_replies = getattr(e, '_enum_test_replies', {})
                disp = _rcpt_enum_reply_for_display(reply_str.strip(), domain, INVALID_PROBES)
                e._enum_test_replies['rcpt'] = f'[{status}] {disp} (Relay protection active)'
                return False
        except Exception as ex:
            e._smtp_vv_io(f'RCPT TO:<{probe}@{domain}>', str(ex))
            return False
    first_status, first_reply = replies[0]
    if all((s in RCPT_ACCEPT for s, _ in replies)):
        return False
    first_reject = next(((s, r) for s, r in replies if s in RCPT_REJECT), None)
    e._enum_test_replies = getattr(e, '_enum_test_replies', {})
    if first_reject is None:
        e.ptdebug('Server is not vulnerable to RCPT enumeration', Out.NOTVULN)
        return False
    rej_status, rej_text = first_reject
    rej_disp = _rcpt_enum_reply_for_display(rej_text.strip(), domain, INVALID_PROBES)
    reject_reply = f'[{rej_status}] {rej_disp}'
    if rej_status in (550, 554) and _is_rbl_blocked(rej_text):
        e.ptdebug(f'RCPT blocked by RBL (could not test): {reject_reply}', Out.INFO)
        e._enum_test_replies['rcpt'] = reject_reply
        e._enum_blocked_by_rbl = getattr(e, '_enum_blocked_by_rbl', set())
        e._enum_blocked_by_rbl.add('rcpt')
        return False
    if _is_relay_or_auth_rejection(rej_text):
        e.ptdebug(f'RCPT rejected by relay/auth policy, not user-based: {reject_reply}', Out.INFO)
        e._enum_test_replies['rcpt'] = f'{reject_reply} (Relay protection active)'
        return False
    e._enum_test_replies['rcpt'] = reject_reply
    e.ptdebug(f'Server is vulnerable to RCPT enumeration: {reject_reply}', Out.VULN)
    return True


def test_catchall(e, smtp: smtplib.SMTP) -> CatchAllResult:
    """
        Detect Catch-All mailbox: if server accepts 3 invalid addresses as valid,
        catch-all is configured (VRFY/EXPN) or indeterminate (RCPT).
        Uses VRFY or EXPN when available; otherwise RCPT. RCPT cannot distinguish
        valid address from catch-all, so when all invalid RCPT are accepted the
        result is ``indeterminate_accept_all_rcpt`` (displayed as accept-all via RCPT).
        Per RFC 5321: 250/251/252 are success for VRFY/EXPN; 550 = user unknown.
        OWASP: RCPT uses full addresses (local@domain) for robustness.
        """
    CATCHALL_INVALID = ('catchallnx001', 'catchallnx002', 'catchallnx003')
    VRFY_EXPN_ACCEPT = (250, 251, 252)
    domain = e._get_rcpt_limit_domain()
    mail_bracket = e._envelope_mail_from_bracket()

    def _choose_method() -> str | None:
        if e.results.enum_results:
            for e in e.results.enum_results:
                if e.vulnerable and e.method in ('expn', 'vrfy', 'rcpt'):
                    return e.method
        try:
            status, _ = smtp.docmd('VRFY', 'catchallprobe')
            if status in (*VRFY_EXPN_ACCEPT, 550):
                return 'vrfy'
        except Exception as ex:
            if e._smtp_exc_is_timeout(ex):
                return 'unreachable'
        try:
            status, _ = smtp.docmd('EXPN', 'catchallprobe')
            if status in (*VRFY_EXPN_ACCEPT, 550):
                return 'expn'
        except Exception as ex:
            if e._smtp_exc_is_timeout(ex):
                return 'unreachable'
        try:
            smtp.docmd('MAIL FROM:', mail_bracket)
            status, _ = smtp.docmd('RCPT TO:', f'<catchallprobe@{domain}>')
            if status in (250, 251, 252, 550):
                return 'rcpt'
        except Exception as ex:
            if e._smtp_exc_is_timeout(ex):
                return 'unreachable'
        return None
    try:
        method = _choose_method()
        if not method:
            return 'indeterminate'
        if method in ('vrfy', 'expn'):
            cmd = 'VRFY' if method == 'vrfy' else 'EXPN'
            accepted = 0
            for user in CATCHALL_INVALID:
                try:
                    status, _ = smtp.docmd(cmd, user)
                    if status in VRFY_EXPN_ACCEPT:
                        accepted += 1
                    elif status in (550, 551, 553, 554):
                        return 'not_configured'
                except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError, TimeoutError, socket.timeout) as ex:
                    return 'unreachable' if e._smtp_exc_is_timeout(ex) else 'indeterminate'
            return 'configured' if accepted == 3 else 'indeterminate'
        else:
            try:
                smtp.docmd('RSET')
            except Exception:
                pass
            try:
                smtp.docmd('MAIL FROM:', mail_bracket)
            except Exception as ex:
                return 'unreachable' if e._smtp_exc_is_timeout(ex) else 'indeterminate'
            try:
                for user in CATCHALL_INVALID:
                    try:
                        status, reply = smtp.docmd('RCPT TO:', f'<{user}@{domain}>')
                        if status in (550, 551, 553, 554) or 'UNKNOWN' in e.bytes_to_str(reply).upper():
                            return 'not_configured'
                    except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError, TimeoutError, socket.timeout) as ex:
                        return 'unreachable' if e._smtp_exc_is_timeout(ex) else 'indeterminate'
                return 'indeterminate_accept_all_rcpt'
            finally:
                try:
                    smtp.docmd('RSET')
                except Exception:
                    pass
    except Exception as ex:
        return 'unreachable' if e._smtp_exc_is_timeout(ex) else 'indeterminate'


def rcpt_enumeration(e, smtp) -> list[str]:
    enum_threads = getattr(e.args, 'enum_threads', 1)
    ehlo = e.results.info and e.results.info.ehlo or ''
    supports_smtputf8 = 'SMTPUTF8' in ehlo.upper()
    domain = e._get_rcpt_limit_domain()
    if getattr(e, '_wordlist_skipped', 0) > 0:
        e.ptdebug(f'Skipped {e._wordlist_skipped} invalid local parts from wordlist', Out.INFO)
    e.ptdebug(f'Enumerating users (domain: {domain}):' + (f' ({enum_threads} threads)' if enum_threads > 1 else ''), Out.INFO)
    enumerated_users: list[str] = []
    wl_total = len(e.wordlist)

    def _skip(local: str) -> bool:
        return not supports_smtputf8 and any((ord(c) >= 128 for c in local))
    try:
        if enum_threads <= 1:
            if supports_smtputf8:
                smtp.command_encoding = 'utf-8'
            reconnect_after = getattr(e.args, 'enum_reconnect_after', None)
            consecutive_failures = 0

            def _do_rcpt_reconnect() -> None:
                """Reconnect to reset accumulated teergrube / rate-limit state.
                    Called after a successful find (when --enum-reconnect-after is set)
                    and after N consecutive failures."""
                nonlocal smtp, consecutive_failures
                consecutive_failures = 0
                if not e.use_json and enum_threads <= 1:
                    with e._enum_progress_print_lock:
                        if e._enum_clock_state is not None:
                            e._enum_clock_state = dict(e._enum_clock_state)
                            e._enum_clock_state['label'] = 'reconnecting...'
                            e._enum_clock_paint_unlocked()
                try:
                    smtp = e.get_smtp_handler(timeout=15.0)
                    smtp.docmd('EHLO', e.fqdn)
                    if supports_smtputf8:
                        smtp.command_encoding = 'utf-8'
                    e._try_mail_from_for_rcpt_probe(smtp, domain)
                except Exception:
                    pass
            for idx, user in enumerate(e.wordlist, start=1):
                local = user.split('@')[0].strip()
                if _skip(local):
                    continue
                label = f'{local}@{domain}'
                if not e.use_json:
                    e._enum_wait_begin(idx, wl_total, local)
                try:
                    status, reply = smtp.docmd('RCPT TO:', f'<{local}@{domain}>')
                except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError) as ex:
                    e.ptdebug(f'RCPT enumeration interrupted (connection closed/reset): {ex}', Out.INFO)
                    try:
                        smtp = e.get_smtp_handler(timeout=10.0)
                        smtp.docmd('EHLO', f'{e.fqdn}')
                        if supports_smtputf8:
                            smtp.command_encoding = 'utf-8'
                        e._try_mail_from_for_rcpt_probe(smtp, domain)
                        status, reply = smtp.docmd('RCPT TO:', f'<{local}@{domain}>')
                        try:
                            smtp.sock.settimeout(15.0)
                        except Exception:
                            pass
                    except Exception:
                        try:
                            smtp = e.get_smtp_handler(timeout=15.0)
                            smtp.docmd('EHLO', f'{e.fqdn}')
                            if supports_smtputf8:
                                smtp.command_encoding = 'utf-8'
                            e._try_mail_from_for_rcpt_probe(smtp, domain)
                        except Exception:
                            break
                        status, reply = (550, b'')
                finally:
                    if not e.use_json and enum_threads <= 1:
                        e._enum_wait_end()
                if status != 550 and (not _rcpt_reply_has_unknown(reply)):
                    if not e.use_json:
                        _print_enum_finding(e, idx, wl_total, label)
                    elif e.use_json:
                        e.ptdebug(label)
                    enumerated_users.append(label)
                    if reconnect_after is not None and reconnect_after != -1:
                        _do_rcpt_reconnect()
                else:
                    consecutive_failures += 1
                    if reconnect_after is not None and reconnect_after > 0 and (consecutive_failures >= reconnect_after):
                        _do_rcpt_reconnect()
            if not e.use_json and enum_threads <= 1:
                e._enum_progress_newline()
        else:
            locals_to_try = [u.split('@')[0].strip() for u in e.wordlist if not _skip(u.split('@')[0].strip())]
            work_total = len(locals_to_try)
            user_queue: queue.Queue[str | None] = queue.Queue()
            for local in locals_to_try:
                user_queue.put(local)
            for _ in range(enum_threads):
                user_queue.put(None)
            result_lock = threading.Lock()
            progress = ThreadedProgress(work_total, enabled=not e.use_json)

            def rcpt_worker() -> None:
                conn = None
                while True:
                    local = user_queue.get()
                    if local is None:
                        user_queue.task_done()
                        break
                    label = f'{local}@{domain}'
                    out = progress.new_output()
                    try:
                        if conn is None:
                            try:
                                conn = e.get_smtp_handler()
                                conn.docmd('EHLO', f'{e.fqdn}')
                                if supports_smtputf8:
                                    conn.command_encoding = 'utf-8'
                                e._try_mail_from_for_rcpt_probe(conn, domain)
                            except Exception:
                                continue
                        try:
                            status, reply = conn.docmd('RCPT TO:', f'<{local}@{domain}>')
                        except (smtplib.SMTPServerDisconnected, ConnectionResetError, OSError):
                            try:
                                conn = e.get_smtp_handler()
                                conn.docmd('EHLO', f'{e.fqdn}')
                                if supports_smtputf8:
                                    conn.command_encoding = 'utf-8'
                                e._try_mail_from_for_rcpt_probe(conn, domain)
                                status, reply = conn.docmd('RCPT TO:', f'<{local}@{domain}>')
                            except Exception:
                                continue
                        if status != 550 and (not _rcpt_reply_has_unknown(reply)):
                            if e.use_json:
                                e.ptdebug(label)
                            else:
                                out.add_string_to_output(label)
                            with result_lock:
                                enumerated_users.append(label)
                    finally:
                        if not e.use_json:
                            progress.flush(out, repaint=False)
                            progress.advance(label=local)
                        user_queue.task_done()
            threads_list = [threading.Thread(target=rcpt_worker) for _ in range(enum_threads)]
            for t in threads_list:
                t.start()
            for t in threads_list:
                t.join()
            if not e.use_json:
                progress.finalize()
        e.ptdebug(f' ')
        e.ptdebug(f'-- Enumerated {len(enumerated_users)} users --')
        e.ptdebug(f' ')
        e.already_enumerated = True
        return enumerated_users
    finally:
        e._enum_clock_shutdown()


def test_enumeration(e, smtp: smtplib.SMTP, enumeration_vulns: dict[str, bool | None]):
    if e.args.enumerate is None:
        return None
    if isinstance(e.args.enumerate, str) and e.args.enumerate.upper() == "ALL":
        e.args.enumerate = ["VRFY", "EXPN", "RCPT"]
    try:
        if 'EXPN' in e.args.enumerate:
            enumeration_vulns.update({'expn': expn_vrfy_test(e, 'EXPN', smtp)})
        if 'VRFY' in e.args.enumerate:
            enumeration_vulns.update({'vrfy': expn_vrfy_test(e, 'VRFY', smtp)})
        if 'RCPT' in e.args.enumerate:
            enumeration_vulns.update({'rcpt': rcpt_test(e, smtp)})
    except Exception as ex:
        msg = f'Connection terminated with server {e.args.target.ip}:{e.args.target.port} ({get_mode(e.args)}): {ex}'
        e._fail(msg)


def test_slowdown_enumeration(e, smtp: smtplib.SMTP, enumeration_vulns: dict[str, bool | None]):
    if e.args.enumerate is None:
        return None
    e.slow_down_results = {'expn': False, 'vrfy': False, 'rcpt': False}
    if 'EXPN' in e.args.enumerate and enumeration_vulns['expn']:
        e.slow_down_results.update(expn_vrfy_slow_down_test(e, 'EXPN', smtp))
    if 'VRFY' in e.args.enumerate and enumeration_vulns['vrfy']:
        e.slow_down_results.update(expn_vrfy_slow_down_test(e, 'VRFY', smtp))
    if 'RCPT' in e.args.enumerate and enumeration_vulns['rcpt']:
        e.slow_down_results.update(rcpt_slow_down_test(e, smtp))
    e.ptdebug('Slow-Down results:', Out.INFO)
    for key, value in e.slow_down_results.items():
        e.ptdebug(f'{key}:{bool(value)}')


def do_enumeration(e, smtp: smtplib.SMTP, enumeration_vulns: dict[str, bool]) -> dict[str, list[str] | None]:
    """OWASP: skip enumeration when catch-all would make results unreliable."""
    enumeration_results: dict[str, list[str] | None] = {'expn': None, 'vrfy': None, 'rcpt': None}
    catch_all = getattr(e.results, 'catch_all', None)
    if enumeration_vulns['expn']:
        if catch_all == 'configured':
            e.ptdebug('Skipping EXPN enumeration: catch-all configured (results would be false positives)', Out.INFO)
        else:
            enumeration_results['expn'] = expn_vrfy_enumeration(e, 'EXPN', smtp)
    elif enumeration_vulns['vrfy']:
        if catch_all == 'configured':
            e.ptdebug('Skipping VRFY enumeration: catch-all configured (results would be false positives)', Out.INFO)
        else:
            enumeration_results['vrfy'] = expn_vrfy_enumeration(e, 'VRFY', smtp)
    elif enumeration_vulns['rcpt']:
        if catch_all in (*CATCH_ALL_INDETERMINATE_VARIANTS, 'configured'):
            e.ptdebug(f'Skipping RCPT enumeration: catch-all {catch_all} (results would be false positives)', Out.INFO)
        else:
            enumeration_results['rcpt'] = rcpt_enumeration(e, smtp)
    return enumeration_results


def enumeration(e, smtp: smtplib.SMTP) -> list[EnumResult]:
    enumeration_vulns: dict[str, bool | None] = {'expn': None, 'vrfy': None, 'rcpt': None}
    enumeration_results = None
    e._enum_blocked_by_rbl = set()
    e._rcpt_enum_mail_from_ok = None
    e._enum_progress_line_dirty = False
    test_enumeration(e, smtp, enumeration_vulns)
    if e.args.slow_down:
        test_slowdown_enumeration(e, smtp, enumeration_vulns)
    enumeration_results: dict[str, list[str] | None] | None = None
    catch_all = getattr(e.results, 'catch_all', None)
    e._enum_methods_streamed_early = False
    e._enum_hits_streamed_live = False
    if e.wordlist is not None:
        if not e.use_json:
            partial_enum_rows: list[EnumResult] = []
            for method in enumeration_vulns.keys():
                if (vulnerable := enumeration_vulns[method]) is not None:
                    if e.args.slow_down:
                        slow_down = e.slow_down_results[method]
                    else:
                        slow_down = None
                    test_replies = getattr(e, '_enum_test_replies', {})
                    server_reply = test_replies.get(method)
                    blocked_by_rbl = method in getattr(e, '_enum_blocked_by_rbl', set())
                    partial_enum_rows.append(EnumResult(method, vulnerable, slow_down, None, server_reply, blocked_by_rbl))
            _stream_enumeration_method_rows(e, partial_enum_rows, catch_all)
            e._enum_methods_streamed_early = True
            if _wordlist_enumeration_will_run(e, enumeration_vulns, catch_all):
                e.ptprint('Enumerated', Out.INFO)
                sys.stdout.flush()
                e._enum_progress_start = time.time()
                e._enum_hits_streamed_live = True
        enumeration_results = do_enumeration(e, smtp, enumeration_vulns)
    enum_results: list[EnumResult] = []
    for method in enumeration_vulns.keys():
        if (vulnerable := enumeration_vulns[method]) is not None:
            if e.args.slow_down:
                slow_down = e.slow_down_results[method]
            else:
                slow_down = None
            if e.wordlist is not None and enumeration_results is not None:
                wordlist_result = enumeration_results[method]
            else:
                wordlist_result = None
            test_replies = getattr(e, '_enum_test_replies', {})
            server_reply = test_replies.get(method)
            blocked_by_rbl = method in getattr(e, '_enum_blocked_by_rbl', set())
            enum_results.append(EnumResult(method, vulnerable, slow_down, wordlist_result, server_reply, blocked_by_rbl))
    return enum_results


def _stream_enumeration_result(e) -> None:
    pp = e._ptprint_raw
    show = not e.use_json
    if (enum_error := e.results.enum_error) is not None:
        pp(f'Enumeration test failed: {enum_error}', bullet_type='VULN', condition=show, indent=4)
        return
    enum_results = e.results.enum_results
    if enum_results is None:
        return
    catch_all = getattr(e.results, 'catch_all', None)
    requested_set = _enumeration_requested_method_set(e)
    filtered = [e for e in enum_results if e.method.upper() in requested_set]
    skip_methods = getattr(e, '_enum_methods_streamed_early', False)
    skip_hits = getattr(e, '_enum_hits_streamed_live', False)
    if skip_methods:
        e._enum_methods_streamed_early = False
    if skip_hits:
        e._enum_hits_streamed_live = False
    if not skip_methods:
        for e in filtered:
            if catch_all == 'configured':
                pp(f'{e.method.upper()} method: Indeterminate (Useless due to Catch All)', bullet_type='WARNING', condition=show, indent=4)
            elif e.blocked_by_rbl:
                pp(f'{e.method.upper()} method protected by RBL/Reputation (Client IP blocked)', bullet_type='NOTVULN', condition=show, indent=4)
                if e.server_reply:
                    for line in (e.server_reply or '').replace('\r', '').splitlines():
                        pp(line.strip(), bullet_type='TEXT', condition=show, indent=8)
            else:
                slowdown = ''
                if e.slowdown is not None:
                    slowdown = ' (rate limited)' if e.slowdown else ' (not rate limited)'
                verdict_bullet = 'VULN' if e.vulnerable else 'NOTVULN'
                if e.vulnerable:
                    if e.server_reply:
                        raw = (e.server_reply or '').replace('\r', '').splitlines()
                        parts = [re.sub(' +', ' ', p.strip()) for p in raw if p.strip()]
                        if parts:
                            if len(parts) == 1:
                                pp(f'{e.method.upper()} method is enabled ({parts[0]}){slowdown}', bullet_type=verdict_bullet, condition=show, indent=4)
                            else:
                                pp(f"{e.method.upper()} method is enabled ({parts[0]}{(')' if len(parts) == 1 else '')}{(slowdown if len(parts) == 1 else '')}", bullet_type=verdict_bullet, condition=show, indent=4)
                                for i, part in enumerate(parts[1:]):
                                    is_last = i == len(parts) - 2
                                    pp(f"{part}{(')' if is_last else '')}{(slowdown if is_last else '')}", bullet_type='TEXT', condition=show, indent=8)
                        else:
                            pp(f'{e.method.upper()} method is enabled{slowdown}', bullet_type=verdict_bullet, condition=show, indent=4)
                    else:
                        pp(f'{e.method.upper()} method is enabled{slowdown}', bullet_type=verdict_bullet, condition=show, indent=4)
                else:
                    if e.server_reply and 'Relay protection active' in e.server_reply:
                        status = 'is deny (Relay protection active)'
                    elif e.server_reply and 'Administrative prohibition' in e.server_reply:
                        status = 'is deny (Administrative prohibition)'
                    else:
                        status = 'is deny'
                    pp(f'{e.method.upper()} method {status}{slowdown}', bullet_type=verdict_bullet, condition=show, indent=4)
    if not skip_hits:
        for e in filtered:
            if e.vulnerable and (results := e.results) is not None:
                sorted_results = sorted(results, key=str)
                for r in sorted_results:
                    pp(str(r), bullet_type='TEXT', condition=show, indent=4)
    if catch_all == 'configured':
        pp('Catch All mailbox configured', bullet_type='TITLE', condition=show, indent=4)
    elif catch_all == 'not_configured':
        pp('Catch All mailbox not configured', bullet_type='TITLE', condition=show, indent=4)
    elif catch_all == 'unreachable':
        pp('Catch-all timed out or could not connect. Not confirmed.', bullet_type='WARNING', condition=show, indent=4)
    elif catch_all == 'indeterminate_accept_all_rcpt':
        pp('Catch All mailbox indeterminate (accept-all via RCPT)', bullet_type='WARNING', condition=show, indent=4)
    elif catch_all == 'indeterminate':
        pp('Catch All mailbox indeterminate', bullet_type='WARNING', condition=show, indent=4)


def run(ctx):
    e = eng(ctx)
    save_enum = e.args.enumerate
    try:
        if e.args.enumerate is None:
            e.args.enumerate = "ALL"
        e._load_wordlist()
        smtp_enum, status, reply = e.connect(timeout=15.0)
        if status != 220:
            raise Exception(e.bytes_to_str(reply) if reply else "Connect failed")
        banner = reply.decode(errors="replace") if isinstance(reply, (bytes, bytearray)) else str(reply or "")
        ehlo = None
        try:
            _, ehlo_bytes = smtp_enum.ehlo(e.fqdn)
            if isinstance(ehlo_bytes, (bytes, bytearray)):
                ehlo = ehlo_bytes.decode(errors="replace")
            elif ehlo_bytes:
                ehlo = str(ehlo_bytes)
        except Exception:
            pass
        if getattr(e.results, "info", None) is None:
            e.results.info = InfoResult(banner, ehlo, None)
            e.results.resolved_domain = e._get_domain_from_banner_or_ptr(e.results.info)
        try:
            e.results.catch_all = test_catchall(e, smtp_enum)
        except Exception as ex:
            e.results.catch_all = "unreachable" if e._smtp_exc_is_timeout(ex) else "indeterminate"
        e.results.enum_results = enumeration(e, smtp_enum)
    except Exception as ex:
        e.results.enum_error = str(ex)
        ctx.out(f"ENUM failed: {ex}", "ERROR", indent=4)
        return
    finally:
        e.args.enumerate = save_enum
    _stream_enumeration_result(e)
