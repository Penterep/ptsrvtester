"""
Thread-safe live progress bar + per-item output for POP3 login bruteforce.

Same ptlibs pattern as SMTP enumeration: ``PtThreads`` plus ``PrintLock`` so
``-vv`` / hits print above a single live ETA line instead of interleaving it.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from typing import Callable, Iterable

from ptlibs.threads import ptthreads
from ptlibs.threads.printlock import PrintLock

from .ptprinthelper import get_colored_text


_live: ThreadedProgress | None = None
_sealed = False
_raw_live = False
_raw_sealed = False
_raw_lock = threading.Lock()


def _raw_write(data: bytes) -> None:
    try:
        os.write(1, data)
    except OSError:
        try:
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
        except Exception:
            pass


def paint_raw_line(text: str) -> None:
    """Gray ``\\r`` progress row. A fatal error finishes it on the next line."""
    global _raw_live
    with _raw_lock:
        if _raw_sealed:
            return
        line = get_colored_text(text, "ADDITIONS")
        _raw_write(f"\033[2K\r{line}".encode("utf-8", errors="replace"))
        _raw_live = True


def clear_raw_line() -> None:
    """Erase the gray progress row when the test moves on."""
    global _raw_live
    with _raw_lock:
        if not _raw_live:
            return
        _raw_write(b"\033[2K\r")
        _raw_live = False


def release_live_line() -> None:
    """Finish the live progress row so a fatal error starts on the next line."""
    global _raw_live, _raw_sealed
    bar = _live
    if bar is not None:
        bar.break_line()
    with _raw_lock:
        _raw_sealed = True
        if _raw_live:
            _raw_write(b"\n")
            _raw_live = False


class ThreadedProgress:
    """Live-progress line plus ``PrintLock``-based per-item output.

    Parameters
    ----------
    total:
        Number of items that will be processed (used for percentage / ETA).
    enabled:
        When ``False`` (e.g. JSON mode) nothing is painted; workers can still
        call every method as a no-op.
    indent:
        Leading spaces prepended to each flushed finding / ``-vv`` line.
        bar_indent:
        Leading spaces on the live ETA line (section body uses 4).
    """

    def __init__(
        self,
        total: int,
        *,
        enabled: bool = True,
        indent: int = 4,
        bar_indent: int = 4,
    ) -> None:
        self.total = max(0, int(total))
        self.indent = max(0, int(indent))
        self.bar_indent = max(0, int(bar_indent))
        self._tty = bool(getattr(sys.stdout, "isatty", lambda: False)())
        self.enabled = bool(enabled)
        self._lock = threading.Lock()
        self._start = time.time()
        self._done = 0
        self._last_label = ""
        self._active = False

    @staticmethod
    def new_output() -> PrintLock:
        return PrintLock()

    @staticmethod
    def _fmt_duration(seconds: float) -> str:
        seconds = max(0.0, float(seconds))
        h, rem = divmod(int(seconds), 3600)
        m, s = divmod(rem, 60)
        return f"{h}:{m:02d}:{s:02d}"

    def _eta_seconds(self) -> float | None:
        if self.total <= 0 or self._done <= 0:
            return None
        remaining = self.total - self._done
        if remaining <= 0:
            return 0.0
        elapsed = max(0.0, time.time() - self._start)
        return remaining * elapsed / float(self._done)

    def _paint_unlocked(self) -> None:
        if _sealed or not self.enabled or not self._tty or self.total <= 0:
            return
        pct = min(100, max(0, int(100 * self._done / self.total)))
        eta = self._eta_seconds()
        time_part = self._fmt_duration(eta) if eta is not None else "--:--:--"
        label = self._last_label or ""
        pad = " " * self.bar_indent
        line = get_colored_text(
            f"{pad}{time_part} {pct}% {self._done}/{self.total} {label}".rstrip(),
            "ADDITIONS",
        )
        self._write(f"\033[2K\r{line}")
        self._active = True
        global _live
        _live = self

    @staticmethod
    def _write(text: str) -> None:
        data = text.encode("utf-8", errors="replace")
        try:
            os.write(1, data)
        except OSError:
            try:
                sys.stdout.write(text)
                sys.stdout.flush()
            except Exception:
                pass

    def kickoff(self, label: str = "") -> None:
        """Show 0% before the first attempt finishes."""
        with self._lock:
            if label:
                self._last_label = label
            self._paint_unlocked()

    def advance(self, label: str = "") -> None:
        with self._lock:
            self._done += 1
            if label:
                self._last_label = label
            self._paint_unlocked()

    def flush(self, output: PrintLock, *, repaint: bool = True) -> None:
        if not self.enabled:
            return
        text = output.get_output_string() if output is not None else ""
        with self._lock:
            if text:
                pad = " " * self.indent
                rendered = "".join(
                    f"{pad}{ln}\n" for ln in text.splitlines() if ln
                )
                if rendered:
                    prefix = "\033[2K\r" if self._tty else ""
                    self._active = False
                    self._write(prefix + rendered)
            if repaint:
                self._paint_unlocked()

    def break_line(self) -> None:
        """Leave the live row in place and move the cursor to the next line."""
        global _live, _sealed
        with self._lock:
            _sealed = True
            if self._active:
                self._write("\n")
                self._active = False
            if _live is self:
                _live = None

    def finalize(self) -> None:
        global _live
        if not self.enabled:
            return
        with self._lock:
            if self._active:
                if self._tty:
                    self._write("\033[2K\r")
                else:
                    self._write("\n")
                self._active = False
            if _live is self:
                _live = None

    def run(
        self,
        items: Iterable,
        work: Callable[[object, PrintLock], str],
        threads: int,
        *,
        finalize: bool = True,
    ) -> list:
        """Run ``work`` over ``items`` using ``ptlibs`` ``PtThreads``."""
        results: list = []
        results_lock = threading.Lock()

        def _runner(item) -> None:
            output = self.new_output()
            try:
                label = work(item, output)
            finally:
                self.flush(output, repaint=False)
                self.advance(label="" if not isinstance(label, str) else label)
            with results_lock:
                results.append(label)

        pt = ptthreads.PtThreads()
        pt.threads(list(items), _runner, max(1, int(threads)))
        if finalize:
            self.finalize()
        return results
