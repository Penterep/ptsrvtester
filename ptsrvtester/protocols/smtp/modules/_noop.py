"""Shared SMTP NOOP1/NOOP2 connection helpers."""
from __future__ import annotations


def _fmt_hms(seconds: float) -> str:
    seconds = max(0.0, float(seconds))
    h, rem = divmod(int(seconds), 3600)
    m, s = divmod(rem, 60)
    return f"{h}:{m:02d}:{s:02d}"


def _noop_progress_line(
    done: float, total: float, label: str, *, eta: float | None = None, count: bool = False,
) -> str:
    """Live line: remaining time, percent, then the label.

    ``count`` adds ``done/total`` right after the percent. Used while NOOP2 opens
    connections. Duration bars (NOOP1, NOOP2 storm) leave it off.
    """
    total_f = max(float(total), 1.0)
    done_i = max(0, min(int(done), int(total_f)))
    pct = min(100, max(0, int(100 * float(done) / total_f)))
    if eta is None:
        time_part = "--:--:--" if done_i <= 0 else _fmt_hms(max(0.0, total_f - float(done)))
    else:
        time_part = _fmt_hms(eta)
    counted = f" {done_i}/{int(total_f)}" if count else ""
    text = f"{time_part} {pct}%{counted} {label}".rstrip()
    return text


def _smtp_noop_open(e, timeout: float | None = None):
    timeout = float(timeout or 30.0)
    smtp, status, reply = e.connect(timeout=timeout, fatal=False)
    if status != 220:
        raise ConnectionError(f"SMTP [{status}] {e.bytes_to_str(reply)}")
    try:
        smtp.docmd("EHLO", e.fqdn)
    except Exception:
        pass
    try:
        smtp.sock.settimeout(timeout)
    except Exception:
        pass
    return smtp


def _smtp_noop_close(smtp) -> None:
    try:
        smtp.close()
    except Exception:
        pass


def _smtp_noop_safe(e, smtp, tag: str | None = None) -> tuple[bool, str | None]:
    """Send SMTP NOOP and return (success, error_msg). ``tag`` kept for IMAP -vv parity."""
    try:
        code, resp = smtp.docmd("NOOP")
        if code == 250:
            return True, None
        extra = ""
        if resp:
            extra = " " + _unwrap_smtp_error(
                e.bytes_to_str(resp) if not isinstance(resp, str) else resp
            )
        return False, f"{code}{extra}".strip()
    except Exception as ex:
        return (False, _unwrap_smtp_error(str(ex)))


def _unwrap_smtp_error(text: str) -> str:
    """imaplib formats abort/error as ``command: NAME => detail`` — keep only the detail."""
    marker = " => "
    if text.startswith("command:") and marker in text:
        return text.split(marker, 1)[1].strip()
    return text


def _noop1_duration_delay(e, default_duration: float, default_delay: float) -> tuple[float, float]:
    dur = getattr(e.args, "noop1_duration", None)
    delay = getattr(e.args, "noop1_delay", None)
    duration = float(dur) if dur is not None else float(default_duration)
    delay_s = float(delay) if delay is not None else float(default_delay)
    if duration <= 0:
        duration = float(default_duration)
    if delay_s < 0:
        delay_s = 0.0
    return duration, delay_s
