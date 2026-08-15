"""Thread-safe structured report accumulator for IMAP JSON output."""
from __future__ import annotations

import threading
from typing import Any


class ImapReport:
    """Modules / engine update properties/vulns; ``IMAP.output()`` emits one software node."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.properties: dict[str, Any] = {
            "software_type": None,
            "name": "imap",
            "version": None,
            "vendor": None,
            "description": None,
        }
        self.vulns: list[dict[str, Any]] = []
        self.connect_error: str | None = None

    def set_connect_error(self, message: str) -> None:
        with self._lock:
            self.connect_error = message

    def update_properties(self, **kwargs: Any) -> None:
        with self._lock:
            self.properties.update({k: v for k, v in kwargs.items() if v is not None})

    def add_vulnerability(self, *, vuln_code: str, **kwargs: Any) -> None:
        entry = {"vuln_code": vuln_code, **kwargs}
        with self._lock:
            self.vulns.append(entry)
