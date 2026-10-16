"""Live credential-attempt output shared by RDP and MSRPC."""
from __future__ import annotations

import shutil
import sys
import threading
import unicodedata

from ptlibs import ptprinthelper


class CredentialProgress:
    """Render attempts immediately; completed work determines the percentage.

    A fitting terminal line is rewritten; long lines and logs get full rows.
    The caller must finish the line before printing its final findings.
    """

    def __init__(self, label: str, total: int, *, enabled: bool = True) -> None:
        self.label = label
        self.total = max(0, int(total))
        self.enabled = bool(enabled)
        self._tty = bool(getattr(sys.stdout, "isatty", lambda: False)())
        self._active = False
        self._lock = threading.Lock()

    def update(
        self,
        completed: int,
        *,
        username: str | None = None,
        password: str | None = None,
        status: str = "",
    ) -> None:
        if not self.enabled:
            return
        completed = min(self.total, max(0, int(completed)))
        # Floor to one decimal: an unfinished 9999/10000 must not show 100%.
        percent = completed * 1000 // self.total / 10 if self.total else 0.0
        line = f"{self.label} Progress: {completed}/{self.total} ({percent:.1f}%)"
        if username is not None:
            line += f" | User: {username!r}"
        if password is not None:
            line += f" | Password: {password!r}"
        if status not in {"", "testing", "completed"}:
            line += f" - {status}"
        rendered = "    " + line
        # Conservatively estimate display width so a wrapped row is never erased
        # as though it occupied just one terminal line. Keep full credentials.
        width = sum(
            2 if unicodedata.east_asian_width(char) in {"W", "F", "A"} else 1
            for char in rendered
        )
        with self._lock:
            if self._tty and width < shutil.get_terminal_size().columns:
                # ptlibs.clear_to_eol only pads POSIX output; erase on Windows too.
                ptprinthelper.ptprint(
                    "\r\033[2K" + rendered,
                    "TEXT", end="", flush=True, colortext="TITLE",
                )
                self._active = True
            else:
                if self._active:
                    sys.stdout.write("\n")
                    self._active = False
                ptprinthelper.ptprint(
                    rendered, "TEXT", flush=True,
                    colortext="TITLE" if self._tty else False,
                )

    def finish(self) -> None:
        """End the terminal line without changing the actual completed count."""
        if not self.enabled:
            return
        with self._lock:
            if self._active:
                sys.stdout.write("\n")
                sys.stdout.flush()
                self._active = False
