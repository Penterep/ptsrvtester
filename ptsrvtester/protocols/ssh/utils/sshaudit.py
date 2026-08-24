"""ssh-audit runner + section helpers (ptssl-style).

The old integration called ssh-audit *in-process* as a library and read only its
``recommendations`` summary (and a ``cves`` list that ssh-audit 3.9+ always
returns empty). This module instead mirrors ``ptssl``'s testssl wrapper: run the
external ``ssh-audit`` binary **once** with JSON output, write it to a JSON file,
read that file back, and let each ``-ts`` section test (KEX / KEYALG / ENC / MAC /
FINGERPRINT) consume its own slice of the parsed result.

``ssh-audit`` emits JSON on **stdout** (``-jj``), so we capture stdout and persist
it to ``<data_dir>/sshaudit_<host>_<port>.json``. The parsed structure (see
``ssh_audit.ssh_audit.build_struct``) is::

    {
      "banner": {"raw", "protocol", "software", "comments"},
      "target": "host:port",
      "compression": [...],
      "kex":  [{"algorithm", "notes": {"fail":[...], "warn":[...], "info":[...]}, "keysize"?}],
      "key":  [{"algorithm", "notes": {...}, ...}],   # host-key algorithms
      "enc":  [{"algorithm", "notes": {...}}],        # ciphers
      "mac":  [{"algorithm", "notes": {...}}],
      "fingerprints": [{"hostkey", "hash_alg", "hash"}],
      "recommendations": {...}, "additional_notes": [...]
    }

Per-algorithm severity is decided *here* from ``notes``: a non-empty ``fail`` list
is a VULN, a non-empty ``warn`` list is a WARNING, otherwise OK.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
from dataclasses import dataclass, field

from ptsrvtester.protocols.ssh.utils.ssh_helpers import is_reachable

SSH_AUDIT_TIMEOUT = 30.0

DHEAT_DEFAULT_CONNECTIONS = 10
DHEAT_DEFAULT_DURATION = 20.0
DHEAT_STOP_GRACE = 15.0


@dataclass
class SSHAuditRun:
    """Outcome of one ssh-audit execution shared by every section test."""
    ok: bool
    data: dict | None = None
    error: str | None = None
    json_path: str | None = None


def _data_dir() -> str:
    """Directory for the persisted ssh-audit JSON file (falls back to tmp)."""
    try:
        from ptlibs.app_dirs import AppDirs
        d = AppDirs("ptsrvtester").get_data_dir()
    except Exception:
        import tempfile
        d = os.path.join(tempfile.gettempdir(), "ptsrvtester")
    os.makedirs(d, exist_ok=True)
    return d


def _ssh_audit_cmd() -> list[str]:
    """The ssh-audit invocation: prefer the console script, fall back to ``-m``."""
    binary = shutil.which("ssh-audit") or shutil.which("ssh-audit.py")
    if binary:
        return [binary]
    return [sys.executable, "-m", "ssh_audit"]


def run_ssh_audit(host: str, port: int, *, timeout: float = SSH_AUDIT_TIMEOUT) -> SSHAuditRun:
    """Run ssh-audit once against ``host:port`` and return the parsed JSON.

    ``--skip-rate-test`` disables the DHEat connection-rate probe (which opens
    dozens of TCP connections and only matters for the DoS check), keeping this a
    plain configuration audit. Output is written to a JSON file and read back.
    """
    if not is_reachable(host, port):
        return SSHAuditRun(ok=False, error=f"host {host}:{port} is not reachable")

    cmd = _ssh_audit_cmd() + ["-jj", "-n", "--skip-rate-test", "-p", str(port), host]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return SSHAuditRun(ok=False, error=f"ssh-audit timed out after {timeout:.0f}s")
    except FileNotFoundError:
        return SSHAuditRun(ok=False, error="ssh-audit executable not found")
    except OSError as e:
        return SSHAuditRun(ok=False, error=f"could not run ssh-audit: {e}")

    stdout = proc.stdout or ""
    stripped = stdout.lstrip()
    if not stripped.startswith("{"):
        detail = (proc.stderr or stdout or "").strip().splitlines()
        msg = detail[0] if detail else f"ssh-audit exited with code {proc.returncode}"
        return SSHAuditRun(ok=False, error=msg)

    safe_host = re.sub(r"[^A-Za-z0-9_.-]", "_", host)
    json_path = os.path.join(_data_dir(), f"sshaudit_{safe_host}_{port}.json")
    try:
        with open(json_path, "w", encoding="utf-8") as f:
            f.write(stdout)
    except OSError:
        json_path = None

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as e:
        return SSHAuditRun(ok=False, error=f"could not parse ssh-audit JSON: {e}")

    return SSHAuditRun(ok=True, data=data, json_path=json_path)


class SSHAuditShared:
    """Run-once, thread-safe holder so all section tests share a single scan.

    The same instance is injected onto every module's ``ctx`` (via the protocol's
    ``build_context``); the first section test to call :meth:`get` triggers the
    scan, the rest reuse the cached :class:`SSHAuditRun`. Lazy, so a run that
    selects only non-crypto tests (e.g. ``-ts BANNER``) never spawns ssh-audit.
    """

    def __init__(self, host: str, port: int, *, timeout: float = SSH_AUDIT_TIMEOUT) -> None:
        self._host = host
        self._port = port
        self._timeout = timeout
        self._lock = threading.Lock()
        self._result: SSHAuditRun | None = None

    def get(self) -> SSHAuditRun:
        with self._lock:
            if self._result is None:
                self._result = run_ssh_audit(self._host, self._port, timeout=self._timeout)
            return self._result


@dataclass
class DHeatRun:
    """Outcome of a ``--dheat`` DoS test run.

    ``vulnerable``: True = server appears NOT rate-limited (susceptible), False =
    rate-limited (safe), None = inconclusive (e.g. run too short, or the server
    offers no Diffie-Hellman kex to attack).
    """
    ok: bool
    vulnerable: bool | None = None
    verdict: str | None = None
    stats: list[str] = field(default_factory=list)
    error: str | None = None
    raw_path: str | None = None


_DHEAT_STAT_LABELS = (
    "Run time:",
    "Attempted TCP connections:",
    "Successful TCP connections:",
    "Successful DH KEX replies:",
    '"Exceeded MaxStartups"',
    '"Not allowed at this time"',
)


def _parse_dheat_output(output: str) -> tuple[bool | None, str | None, list[str]]:
    """Extract ``(vulnerable, verdict_line, stat_lines)`` from ssh-audit --dheat text.

    ssh-audit prints continuous progress, then (after SIGINT) a STATISTICS block and
    a verdict sentence naming whether the target *is / is NOT using rate limiting*.
    We parse only the final report (after the last "STATISTICS" marker) so repeated
    progress lines don't interfere.
    """
    idx = output.rfind("STATISTICS")
    report = output[idx:] if idx != -1 else output
    lines = [ln.strip() for ln in report.splitlines() if ln.strip()]

    vulnerable: bool | None = None
    verdict: str | None = None
    for ln in lines:
        if "is NOT using rate limiting" in ln:
            vulnerable, verdict = True, ln
            break
        if "is using rate limiting" in ln:
            vulnerable, verdict = False, ln
            break
        if "under 5 seconds" in ln:
            vulnerable, verdict = None, ln
            break

    stats = [
        ln for ln in lines
        if any(lbl in ln for lbl in _DHEAT_STAT_LABELS)
        and ("/sec" in ln or "Run time:" in ln)
    ]
    return vulnerable, verdict, stats


def run_ssh_audit_dheat(
    host: str,
    port: int,
    *,
    dheat_arg: str | None = None,
    duration: float = DHEAT_DEFAULT_DURATION,
) -> DHeatRun:
    """Run ssh-audit's DHEat DoS attack (``--dheat``) for ``duration`` seconds.

    This is a **separate**, aggressive ssh-audit invocation (not the shared config
    scan): ``ssh-audit -n --dheat N[:kex[:e_len]] -p <port> <host>``. The attack
    runs continuously until interrupted, so we start it, let it run for ``duration``
    seconds, send SIGINT so ssh-audit prints its statistics + verdict, then parse it.
    """
    if not is_reachable(host, port):
        return DHeatRun(ok=False, error=f"host {host}:{port} is not reachable")

    arg = str(dheat_arg) if dheat_arg else str(DHEAT_DEFAULT_CONNECTIONS)
    cmd = _ssh_audit_cmd() + ["-n", "--dheat", arg, "-p", str(port), host]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
    except FileNotFoundError:
        return DHeatRun(ok=False, error="ssh-audit executable not found")
    except OSError as e:
        return DHeatRun(ok=False, error=f"could not run ssh-audit: {e}")

    def _signal_group(sig: int) -> None:
        try:
            os.killpg(os.getpgid(proc.pid), sig)
        except (ProcessLookupError, PermissionError, OSError):
            pass

    try:
        stdout, stderr = proc.communicate(timeout=duration)
    except subprocess.TimeoutExpired:
        _signal_group(signal.SIGINT)
        try:
            stdout, stderr = proc.communicate(timeout=DHEAT_STOP_GRACE)
        except subprocess.TimeoutExpired:
            _signal_group(signal.SIGKILL)
            try:
                stdout, stderr = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate()

    output = stdout or ""

    safe_host = re.sub(r"[^A-Za-z0-9_.-]", "_", host)
    raw_path = os.path.join(_data_dir(), f"dheat_{safe_host}_{port}.txt")
    try:
        with open(raw_path, "w", encoding="utf-8") as f:
            f.write(output)
            if stderr:
                f.write("\n--- stderr ---\n")
                f.write(stderr)
    except OSError:
        raw_path = None

    vulnerable, verdict, stats = _parse_dheat_output(output)

    if verdict is None and not stats:
        detail = [
            ln.strip() for ln in (stderr or output or "").splitlines()
            if ln.strip() and ("error" in ln.lower() or "not " in ln.lower() or "do not" in ln.lower())
        ]
        if detail:
            return DHeatRun(ok=True, vulnerable=None, verdict=detail[0], raw_path=raw_path)
        return DHeatRun(
            ok=False,
            error="ssh-audit produced no DHEat result (target may offer no Diffie-Hellman kex)",
            raw_path=raw_path,
        )

    return DHeatRun(ok=True, vulnerable=vulnerable, verdict=verdict, stats=stats, raw_path=raw_path)


def classify_algorithm(entry: dict) -> tuple[str, str]:
    """Map one algorithm entry to ``(severity, note)``.

    ``fail`` notes -> ``VULN``, ``warn`` notes -> ``WARNING``, otherwise ``OK``.
    ``note`` is a human-readable reason (empty for OK; info notes are not shown).
    """
    notes = entry.get("notes") or {}
    fail = [n for n in notes.get("fail", []) if n]
    warn = [n for n in notes.get("warn", []) if n]
    if fail:
        return "VULN", "; ".join(fail)
    if warn:
        return "WARNING", "; ".join(warn)
    return "OK", ""


def report_algorithm_section(ctx, section: str, *, vuln_request: str) -> None:
    """Shared body for the KEX/KEYALG/ENC/MAC section tests.

    Pulls the shared ssh-audit result, prints each algorithm in the ``section``
    with its OK/WARNING/VULN status, and (if any weak algorithms were found)
    records one INSECURECRYPTO vulnerability for the section.
    """
    from ptsrvtester.protocols.ssh.utils.results import VULNS

    run = ctx.ssh_audit.get()
    if not run.ok:
        ctx.out(f"ssh-audit did not run: {run.error}", "WARNING", indent=4)
        with ctx.results_lock:
            ctx.properties["sshauditStatus"] = run.error or "error"
        return

    with ctx.results_lock:
        ctx.properties["sshauditStatus"] = "ok"

    entries = (run.data or {}).get(section) or []
    if not entries:
        ctx.out("ssh-audit reported no algorithms for this section", "NOTVULN", indent=4)
        return

    from ptlibs.ptprinthelper import get_colored_text

    weak: list[str] = []
    for entry in entries:
        alg = entry.get("algorithm", "?")
        severity, note = classify_algorithm(entry)
        # Algorithm and its reason on one line; the reason goes in grey parentheses.
        if note:
            line = f"{alg} {get_colored_text(f'({note})', 'ADDITIONS')}"
        else:
            line = alg
        ctx.out(line, severity, indent=4)
        if severity != "OK":
            weak.append(f"{alg}: {note}" if note else alg)

    if weak:
        with ctx.results_lock:
            ctx.deferred_vulns.append({
                "vuln_code": VULNS.InsecureCrypto.value,
                "vuln_request": vuln_request,
                "vuln_response": "\n".join(weak),
            })