"""Thread-safe structured report accumulator for POP3 JSON output."""
from __future__ import annotations

import threading
from typing import Any


class Pop3Report:
    """Modules update properties/vulns here; ``POP3.output()`` emits one software node."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.properties: dict[str, Any] = {
            "software_type": None,
            "name": "pop3",
            "version": None,
            "vendor": None,
            "description": None,
        }
        self.vulns: list[dict[str, Any]] = []
        self.connect_error: str | None = None
        self.brute_creds = None
        self._vuln_poc: dict[str, str] = {}

    def set_connect_error(self, message: str) -> None:
        with self._lock:
            self.connect_error = message

    def update_properties(self, **kwargs: Any) -> None:
        with self._lock:
            self.properties.update({k: v for k, v in kwargs.items() if v is not None})

    def add_vulnerability(self, *, vuln_code: str, **kwargs: Any) -> None:
        with self._lock:
            for entry in self.vulns:
                if entry.get("vuln_code") != vuln_code:
                    continue
                extra = kwargs.get("vuln_request")
                prev = entry.get("vuln_request") or ""
                if extra and extra not in prev:
                    entry["vuln_request"] = f"{prev}; {extra}" if prev else extra
                return
            self.vulns.append({"vuln_code": vuln_code, **kwargs})

    def note_poc(self, code: str, *pairs: tuple[str, str]) -> None:
        """Remember the Send/Receive lines that prove one vulnerability.

        Later pairs for the same code are ignored. The full session stays in
        ``results.log``; this is only the proving snippet.
        """
        if not code or not pairs:
            return
        lines: list[str] = []
        for send, recv in pairs:
            if not send:
                continue
            recv_s = "(no reply)" if recv in (None, "") else " ".join(str(recv).split())
            lines.append(f"Send: {send}")
            lines.append(f"Receive: {recv_s}")
        if not lines:
            return
        text = "\r\n".join(lines)
        with self._lock:
            if code not in self._vuln_poc:
                self._vuln_poc[code] = text

    def poc_for(self, code: str | None) -> str:
        if not code:
            return ""
        with self._lock:
            return self._vuln_poc.get(code, "")
