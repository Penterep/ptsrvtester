"""TEMPLATE — copy this file to modules/<yourmodule>.py to add a module.

The generic main (main.py) discovers every ``modules/*.py`` that is NOT
prefixed with ``_`` and exposes a callable ``run(ctx)``. This file starts with
``_`` on purpose, so it is documentation only and is never executed.

Required / optional module-level attributes
--------------------------------------------
    __MODULELABEL__  (str, required)  one-line label; the main prints it as the
                                    section header before your run() executes.
    __MODULECODE__   (str, optional)  the -ts code; defaults to FILENAME.upper().
    __ORDER__      (int, optional)  run/print order; smaller runs first (default 100).

The run(ctx) entry point
------------------------
``ctx`` carries everything you need — you do NOT manage threads, output ordering
or the section header yourself:

    ctx.args        parsed CLI args (SMTPArgs) — all -m/-r/--tls/... options
    ctx.target      (ip, port) tuple, already resolved
    ctx.ptjsonlib   shared PtJsonLib — add structured results for JSON mode
    ctx.print_lock  this module's output buffer (advanced use)
    ctx.out(text, category="TEXT", colortext=False, indent=0)
                    buffer a line; categories: TEXT/INFO/OK/VULN/NOTVULN/
                    WARNING/ERROR/TITLE/ADDITIONS (text mode only)
    ctx.debug(text) buffer a line shown only with -vv
    ctx.json        True in --json mode  (emit via ctx.ptjsonlib, not ctx.out)
    ctx.verbose     True in -vv mode
    ctx.<extra>     protocol handles from build_context(): ctx.host, ctx.ip,
                    ctx.port, ctx.fqdn, ctx.tls, ctx.starttls, ...

Contract:
  * run() takes exactly one argument (ctx) and returns None.
  * Do NOT print with builtin print()/sys.stdout — use ctx.out()/ctx.debug()
    so output stays isolated per module and ordered by the main.
  * Raising is safe: the main catches it and reports the module as failed without
    aborting the other selected modules.
"""

__TESTLABEL__ = "Encryption status information"
__TESTCODE__ = ""
__ORDER__ = 12

def run(ctx):
    ip, port = ctx.target
    ctx.out(f"Would check {ip}:{port} here.", "TEXT")
    # For JSON mode, add structured findings instead of text, e.g.:
    #   ctx.ptjsonlib.add_vulnerability("PTV-SMTP-...")