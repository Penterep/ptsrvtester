def eng(ctx):
    return ctx.engine.bind_ctx(ctx)


def run_probe(ctx, code: str, result_field: str, method_name: str) -> None:
    """Run one engine method and retain unexpected failures for JSON output."""
    engine = eng(ctx)
    try:
        setattr(engine.results, result_field, getattr(engine, method_name)())
    except Exception as exc:
        engine.record_module_error(code, exc)
        ctx.out(f"{code} failed: {exc}", "ERROR", indent=4)
