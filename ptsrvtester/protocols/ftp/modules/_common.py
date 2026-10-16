"""Shared helpers for FTP modules."""
from __future__ import annotations

from ..utils.helpers import Creds, check_if_brute, simple_bruteforce, text_or_file


def eng(ctx):
    return ctx.engine.bind_ctx(ctx)


def ensure_info(ctx, *, get_commands: bool = True):
    e = eng(ctx)
    if e.results.info is not None or getattr(e.results, "info_error", None):
        return e
    try:
        e._dbg("Initial server information")
        e.ftp = e.connect(trace=True)
        e.results.info = e.info(get_commands=get_commands)
    except Exception as ex:
        msg = str(ex)
        e._dbg(f"Initial server probe failed: {e._snip(msg)}")
        e.results.info_error = msg
        ctx.report.set_connect_error(msg)
        ctx.out(msg, "ERROR", indent=4)
    return e


def ensure_creds(ctx) -> Creds | None:
    """Populate results.anonymous / results.creds so engine helpers can resolve a login.

    - ``-A/--anonymous``: probe anonymous login (does not print ANON section)
    - ``-u/-p`` (or wordlists): attempt login(s) into ``results.creds``
    - Prior ANON / BRUTE modules: reuse their results
    """
    e = eng(ctx)
    existing = e._get_path_enum_creds()
    if existing is not None:
        return existing

    if getattr(ctx.args, "anonymous", False) and e.results.anonymous is None:
        try:
            if e.ftp is None:
                e.ftp = e.connect()
            e.results.anonymous = e.anonymous()
        except Exception:
            e.results.anonymous = False
        if e.results.anonymous:
            return Creds("anonymous", "")

    if check_if_brute(ctx.args) and not e.results.creds:
        creds = simple_bruteforce(
            e._try_login,
            ctx.args.user,
            ctx.args.users,
            ctx.args.password,
            ctx.args.passwords,
            ctx.args.spray,
            10 if getattr(ctx.args, "threads", None) is None else ctx.args.threads,
        )
        e.results.creds = set(creds) if creds else set()

    return e._get_path_enum_creds()


def _clean_name_list(raw: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for p in raw:
        p = p.strip().lstrip("\ufeff").strip()
        if not p or p.startswith("#"):
            continue
        if p in seen:
            continue
        seen.add(p)
        out.append(p)
    return out


def load_paths_wordlist(args) -> list[str]:
    path = getattr(args, "paths_wordlist", None)
    if not path:
        return []
    return _clean_name_list(text_or_file(None, path))


def load_enum_files(args) -> list[str]:
    path = getattr(args, "enum_files", None)
    if not path:
        return []
    return _clean_name_list(text_or_file(None, path))
