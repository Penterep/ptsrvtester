"""ENUMPATH — Path enumeration."""
__MODULELABEL__ = "Path enumeration"
__MODULECODE__ = "ENUMPATH"
__ORDER__ = 80

from ._common import eng, ensure_creds, load_paths_wordlist


def run(ctx):
    e = eng(ctx)
    e.args.enum_paths = True
    creds = ensure_creds(ctx)
    if creds is None:
        e.results.path_enum_error = "No valid credentials for path enumeration"
        e._stream_path_enum_result()
        return
    try:
        paths = load_paths_wordlist(ctx.args)
        e.results.path_enum = e.path_enumeration(creds, paths)
    except Exception as ex:
        e.results.path_enum_error = str(ex)
        ctx.out(f"ENUMPATH failed: {ex}", "ERROR", indent=4)
        return
    e._stream_path_enum_result()
