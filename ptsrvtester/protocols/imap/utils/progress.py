"""
Thread-safe live progress bar + per-item output for IMAP USRENUM / USRENUMPLAIN.

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
        Leading spaces on the live ETA line (IMAP section body uses 4).
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
        if not self.enabled or not self._tty or self.total <= 0:
            return
        pct = min(100, max(0, int(100 * self._done / self.total)))
        eta = self._eta_seconds()
        time_part = self._fmt_duration(eta) if eta is not None else "--:--:--"
        label = self._last_label or ""
        pad = " " * self.bar_indent
        line = f"{pad}{time_part} {pct}% {self._done}/{self.total} {label}".rstrip()
        self._write(f"\033[2K\r{line}")
        self._active = True

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

    def finalize(self) -> None:
        if not self.enabled:
            return
        with self._lock:
            if self._active:
                if self._tty:
                    self._write("\033[2K\r")
                else:
                    self._write("\n")
                self._active = False

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
