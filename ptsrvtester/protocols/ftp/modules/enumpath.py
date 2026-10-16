"""ENUMPATH — Path enumeration."""
__MODULELABEL__ = "Path enumeration"
__MODULECODE__ = "ENUMPATH"
__ORDER__ = 80

from ._common import eng, ensure_creds, load_enum_files, load_paths_wordlist


def run(ctx):
    e = eng(ctx)
    e.args.enum_paths = True
    creds = ensure_creds(ctx)
    if creds is None:
        e.results.path_enum_error = e._missing_login_line()
        e._stream_path_enum_result()
        return
    try:
        directories = load_paths_wordlist(ctx.args)
        files = load_enum_files(ctx.args)
        raw_depth = getattr(ctx.args, "enum_depth", 1)
        depth = 1 if raw_depth is None else int(raw_depth)
        e.results.path_enum = e.path_enumeration(creds, directories, files, depth)
    except Exception as ex:
        e.results.path_enum_error = str(ex)
        ctx.out(f"Path enumeration failed: {ex}", "ERROR", indent=4)
        return
    e._stream_path_enum_result()
