"""USRENUM — mailbox enumeration via USER and one wrong PASS.

Nmap pop3-brute and Hydra only report a successful login. POP3 has no VRFY.
RFC 1939 allows +OK for an unknown mailbox, so +OK alone is not a finding.
The oracle is a reply that differs from two names that cannot exist.
RFC 3206 says an [AUTH] code on USER means that mailbox exists.
"""
from __future__ import annotations

import random
import re
import threading
import time
from dataclasses import dataclass

import poplib

from ..utils.connection import _pop3_reply, _pop3_vv, connect_pop3
from ..utils.helpers import Creds, auth_enum_candidate_names, text_or_file
from ..utils.progress import ThreadedProgress
from ..utils.results import VULNS

__MODULELABEL__ = "User enumeration"
__MODULECODE__ = "USRENUM"
__ORDER__ = 65

_WRONG_PASSWORD = "PtsrvUEnumWrongPass!77~"
_BASELINE_COUNT = 2


@dataclass
class _Probe:
    username: str
    baseline: bool
    user_reply: str = ""
    pass_reply: str | None = None
    pass_ok: bool = False
    elapsed_ms: float | None = None
    error: str | None = None


def _status(reply: str) -> str:
    up = reply.upper()
    if up.startswith("+OK"):
        return "+OK"
    if up.startswith("-ERR"):
        return "-ERR"
    return "OTHER"


def _norm(reply: str, username: str) -> str:
    """Drop the echoed mailbox name so '+OK alice' and '+OK bob' compare equal."""
    text = " ".join(reply.split())
    if username:
        text = re.sub(rf"(?i)\b{re.escape(username)}\b", " ", text)
    return " ".join(text.split()).casefold()


def _sig(probe: _Probe) -> tuple:
    user = _norm(probe.user_reply, probe.username)
    if probe.pass_reply is None:
        return (_status(probe.user_reply), user, None, None)
    return (
        _status(probe.user_reply),
        user,
        _status(probe.pass_reply),
        _norm(probe.pass_reply, probe.username),
    )


def _unsupported(reply: str) -> bool:
    low = reply.lower()
    return any(part in low for part in ("unknown command", "not implemented", "unrecognized"))


def _candidates(args) -> tuple[list[str], bool]:
    wordlist = text_or_file(None, args.users) if getattr(args, "users", None) else None
    names, used_default = auth_enum_candidate_names(args, wordlist=wordlist)
    seen: set[str] = set()
    cleaned: list[str] = []
    for name in names:
        if not name or name in seen or any(ch in name for ch in " \t\r\n"):
            continue
        seen.add(name)
        cleaned.append(name)
    return cleaned, used_default


def _baselines(taken: set[str]) -> list[str]:
    names: list[str] = []
    while len(names) < _BASELINE_COUNT:
        name = f"enumtest_invalid_{random.getrandbits(32):08x}"
        if name not in taken and name not in names:
            names.append(name)
    return names


def _probe(ctx, username: str, loglock: threading.Lock) -> _Probe:
    def vv(send: str, recv: str) -> None:
        with loglock:
            _pop3_vv(ctx.debug, send, recv)

    try:
        pop3 = connect_pop3(ctx.args)
    except OSError as exc:
        vv("(connect)", str(exc))
        return _Probe(username=username, baseline=False, error=str(exc))
    try:
        try:
            user_reply = _pop3_reply(pop3.user(username))
        except poplib.error_proto as exc:
            user_reply = _pop3_reply(exc)
        except (OSError, TimeoutError) as exc:
            vv(f"USER {username}", str(exc))
            return _Probe(username=username, baseline=False, error=str(exc))
        vv(f"USER {username}", user_reply)
        if not user_reply.upper().startswith("+OK"):
            return _Probe(username=username, baseline=False, user_reply=user_reply)
        started = time.perf_counter()
        try:
            pass_reply = _pop3_reply(pop3.pass_(_WRONG_PASSWORD))
            passed = True
        except poplib.error_proto as exc:
            pass_reply = _pop3_reply(exc)
            passed = pass_reply.upper().startswith("+OK")
        except (OSError, TimeoutError) as exc:
            vv(f"PASS {_WRONG_PASSWORD}", str(exc))
            return _Probe(username=username, baseline=False, user_reply=user_reply, error=str(exc))
        elapsed = (time.perf_counter() - started) * 1000
        vv(f"PASS {_WRONG_PASSWORD}", pass_reply)
        return _Probe(
            username=username,
            baseline=False,
            user_reply=user_reply,
            pass_reply=pass_reply,
            pass_ok=passed,
            elapsed_ms=elapsed,
        )
    finally:
        try:
            pop3.quit()
        except Exception:
            try:
                pop3.close()
            except Exception:
                pass


def _timing_hit(baselines: list[_Probe], probe: _Probe) -> bool:
    if _sig(probe) != _sig(baselines[0]) or probe.elapsed_ms is None:
        return False
    samples = [item.elapsed_ms for item in baselines if item.elapsed_ms is not None]
    if len(samples) < _BASELINE_COUNT:
        return False
    slowest = max(samples)
    return probe.elapsed_ms >= slowest * 3 and probe.elapsed_ms >= slowest + 1000


def _poc(baseline: _Probe, hit: _Probe, *, mark_pass: bool) -> str:
    pairs = [(f"USER {baseline.username}", baseline.user_reply)]
    if baseline.pass_reply is not None:
        pairs.append((f"PASS {_WRONG_PASSWORD}", baseline.pass_reply))
    pairs.append((f"USER {hit.username}", hit.user_reply))
    if hit.pass_reply is not None:
        pairs.append((f"PASS {_WRONG_PASSWORD}", hit.pass_reply))
    mark_at = len(pairs) - 1 if mark_pass and hit.pass_reply is not None else len(pairs) - (2 if hit.pass_reply is not None else 1)
    blocks: list[str] = []
    for index, (send, recv) in enumerate(pairs):
        shown = recv
        if index == mark_at and "**" not in shown and "\n" not in shown:
            shown = f"**{shown}**"
        shown = shown.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n")
        blocks.append(f"Send:\r\n{send}\r\n\r\nReceive:\r\n{shown}")
    return "\r\n\r\n".join(blocks)


def _remember(ctx, code: str, poc: str) -> None:
    with ctx.report._lock:
        ctx.report._vuln_poc.setdefault(code, poc)
    ctx.report.add_vulnerability(vuln_code=code)


def run(ctx):
    names, used_default = _candidates(ctx.args)
    if not names:
        ctx.out("No usernames to test", "WARNING", indent=4)
        return
    if used_default:
        ctx.out("Built-in names: " + ", ".join(names), "TEXT", indent=4)

    baselines = _baselines(set(names))
    items = [("base", name) for name in baselines] + [("cand", name) for name in names]
    threads = int(getattr(ctx.args, "noop2_threads", None) or 1)
    show_bar = not ctx.json and not ctx.verbose
    progress = ThreadedProgress(len(items), enabled=show_bar, indent=4, bar_indent=4)
    found: list[_Probe] = []
    lock = threading.Lock()
    loglock = threading.Lock()

    def work(item, _output):
        kind, name = item
        probe = _probe(ctx, name, loglock)
        probe.baseline = kind == "base"
        with lock:
            found.append(probe)
        return name

    progress.kickoff(baselines[0])
    progress.run(items, work, threads)

    by_name = {probe.username: probe for probe in found}
    base_rows = [by_name[name] for name in baselines if name in by_name]
    cand_rows = [by_name[name] for name in names if name in by_name]
    if any(row.error for row in base_rows) or len(base_rows) < _BASELINE_COUNT:
        ctx.out("Could not connect. User enumeration was not tested.", "WARNING", indent=4)
        return
    if all(_unsupported(row.user_reply) for row in base_rows):
        ctx.out("USER is not offered", "NOTVULN", indent=4)
        return
    if len({_sig(row) for row in base_rows}) != 1:
        ctx.out("Unknown names did not answer the same way", "WARNING", indent=4)
        return

    base = base_rows[0]
    base_sig = _sig(base)
    hits: list[tuple[_Probe, bool]] = []
    for row in cand_rows:
        if row.error:
            continue
        text_diff = _sig(row) != base_sig and not row.pass_ok
        timing = _timing_hit(base_rows, row)
        user_same = (
            _status(row.user_reply) == _status(base.user_reply)
            and _norm(row.user_reply, row.username) == _norm(base.user_reply, base.username)
        )
        if text_diff or timing:
            hits.append((row, bool(row.pass_reply) and (user_same or timing)))
        if row.pass_ok:
            creds = set(ctx.report.brute_creds or ())
            creds.add(Creds(row.username, _WRONG_PASSWORD))
            ctx.report.brute_creds = creds
            ctx.report.note_poc(
                VULNS.WeakCreds.value,
                (f"USER {row.username}", row.user_reply),
                (f"PASS {_WRONG_PASSWORD}", row.pass_reply or ""),
            )
            ctx.report.add_vulnerability(vuln_code=VULNS.WeakCreds.value)

    if not hits:
        ctx.out("No difference from unknown names", "NOTVULN", indent=4)
        return
    for row, mark_pass in hits:
        suffix = " (slower PASS)" if _timing_hit(base_rows, row) and _sig(row) == base_sig else ""
        ctx.out(f"{row.username}{suffix}", "VULN", indent=4)
    first, mark_pass = hits[0]
    _remember(ctx, VULNS.UserEnum.value, _poc(base, first, mark_pass=mark_pass))
