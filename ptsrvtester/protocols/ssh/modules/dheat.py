"""DHEAT — DHEat DoS attack test (ssh-audit --dheat, CVE-2002-20001).

Aggressive, opt-in test: it actively runs ssh-audit's DHEat Diffie-Hellman DoS
attack against the target for a bounded time, then reports whether the server
appears to throttle connections (safe) or not (vulnerable).

Unlike the crypto section tests, this uses its own ssh-audit invocation (the
``--dheat`` switch, not the shared config scan) and is excluded from the default /
ALL sweep (``__RUN_IN_ALL__ = False``) because it is disruptive and runs longer —
it only runs when explicitly selected with ``-ts DHEAT``.

While the attack runs, a live progress line (spinner + elapsed-seconds counter) is
written straight to the terminal; it is erased when the run finishes, then the
buffered verdict/statistics are printed like every other test.
"""
import itertools
import sys
import threading
import time

from ptlibs.ptprinthelper import ptprint, clear_line

from ptsrvtester.protocols.ssh.utils.sshaudit import (
    DHEAT_DEFAULT_DURATION,
    run_ssh_audit_dheat,
)
from ptsrvtester.protocols.ssh.utils.results import VULNS

__MODULELABEL__ = "DHEat DoS attack (CVE-2002-20001)"
__MODULECODE__ = "DHEAT"
__ORDER__ = 80
__RUN_IN_ALL__ = False


def _progress(stop_event: threading.Event, ip: str, port: int, duration: float) -> None:
    """Temporary live line (spinner + elapsed counter) erased when the run ends.

    Uses ptlibs ``ptprint`` (``end="\\r"`` + ``clear_to_eol``) for the self-updating
    line and ``clear_line`` to erase it — the same progress mechanism ptssl uses.
    """
    frames = itertools.cycle("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
    start = time.time()
    sys.stdout.write("\033[?25l")  # hide cursor
    sys.stdout.flush()
    try:
        while not stop_event.is_set():
            elapsed = time.time() - start
            if elapsed < duration:
                phase = f"attacking… {elapsed:0.0f}s / {duration:0.0f}s"
            else:
                phase = f"stopping & collecting statistics… {elapsed:0.0f}s"
            ptprint(
                f"    {next(frames)} DHEat DoS attack {ip}:{port} — {phase}",
                "TEXT", end="\r", flush=True, clear_to_eol=True, colortext="TITLE",
            )
            time.sleep(0.1)
    finally:
        clear_line(end="\r")           # erase the temporary line (ptlibs)
        sys.stdout.write("\033[?25h")  # restore cursor
        sys.stdout.flush()


def run(ctx):
    ip, port = ctx.target
    dheat_arg = getattr(ctx.args, "dheat", None)
    duration = getattr(ctx.args, "dheat_duration", None) or DHEAT_DEFAULT_DURATION

    ctx.out(
        f"Running the DHEat DoS attack against {ip}:{port} for ~{duration:.0f}s "
        f"(active attack, CVE-2002-20001)",
        "WARNING", indent=4,
    )

    show_progress = not ctx.json and sys.stdout.isatty()
    stop_event = threading.Event()
    spinner = None
    if show_progress:
        spinner = threading.Thread(target=_progress, args=(stop_event, ip, port, duration), daemon=True)
        spinner.start()
    try:
        result = run_ssh_audit_dheat(ip, port, dheat_arg=dheat_arg, duration=duration)
    finally:
        if spinner is not None:
            stop_event.set()
            spinner.join()

    if not result.ok:
        ctx.out(f"DHEat test did not run: {result.error}", "WARNING", indent=4)
        with ctx.results_lock:
            ctx.properties["dheatStatus"] = result.error or "error"
        return

    if result.vulnerable is True:
        ctx.out(result.verdict or "Server is NOT rate-limiting DH key exchange", "VULN", indent=4)
    elif result.vulnerable is False:
        ctx.out(result.verdict or "Server is rate-limiting connections", "OK", indent=4)
    else:
        ctx.out(result.verdict or "DHEat result inconclusive", "WARNING", indent=4)

    for line in result.stats:
        ctx.out(line, "TEXT", indent=8)

    with ctx.results_lock:
        ctx.properties["dheatStatus"] = (
            "vulnerable" if result.vulnerable is True
            else "safe" if result.vulnerable is False
            else "inconclusive"
        )
        if result.vulnerable is True:
            ctx.deferred_vulns.append({
                "vuln_code": VULNS.DHEat.value,
                "vuln_request": f"ssh-audit --dheat against {ip}:{port}",
                "vuln_response": "\n".join([result.verdict or ""] + result.stats).strip(),
            })
