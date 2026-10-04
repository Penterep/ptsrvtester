"""AUTHLIST — EHLO AUTH mechanisms (auth-focused JSON)."""
from ..._base import Out
from ..utils.helpers import _parse_ehlo_commands
from ._common import ensure_info


__MODULELABEL__ = ""
__MODULECODE__ = "AUTHLIST"
__ORDER__ = 26


def _auth_displays(ehlo_raw: str, connection_encrypted: bool) -> list[tuple[str, str]]:
    """AUTH mechanisms from one EHLO reply. Other extensions are left out."""
    rows = []
    for display, level in _parse_ehlo_commands(ehlo_raw, connection_encrypted=connection_encrypted):
        key = display.upper()
        if key.startswith("AUTH ") or key.startswith("AUTH="):
            rows.append((display, level))
    return rows


def _stream_authlist(e) -> None:
    info = getattr(e.results, "info", None)
    if info is None or info.ehlo is None:
        return
    show = not e.use_json

    def _print_auth(ehlo_raw: str, connection_encrypted: bool) -> None:
        rows = _auth_displays(ehlo_raw, connection_encrypted)
        if not rows:
            e._ptprint_raw("AUTH is not offered", bullet_type="WARNING", condition=show, indent=4)
            return
        for display_str, level in rows:
            if level == "ERROR":
                bullet = "VULN"
            elif level == "WARNING":
                bullet = "WARNING"
            else:
                bullet = "NOTVULN"
            e._ptprint_raw(display_str, bullet_type=bullet, condition=show, indent=4)

    ehlo_starttls = getattr(info, "ehlo_starttls", None)
    if ehlo_starttls:
        e.ptprint("AUTH mechanisms (PLAIN)", Out.INFO)
        if info.ehlo:
            _print_auth(info.ehlo, False)
        e.ptprint("AUTH mechanisms (STARTTLS)", Out.INFO)
        _print_auth(ehlo_starttls, True)
        return
    encrypted = e.args.target.port == 465 or bool(e.args.tls)
    label = " (TLS)" if encrypted else " (PLAIN)"
    e.ptprint(f"AUTH mechanisms{label}", Out.INFO)
    if info.ehlo:
        _print_auth(info.ehlo, encrypted)


def run(ctx):
    e = ensure_info(ctx, get_commands=True)
    e.results.authentications_requested = True
    if getattr(e.results, "info_error", None):
        return
    _stream_authlist(e)
