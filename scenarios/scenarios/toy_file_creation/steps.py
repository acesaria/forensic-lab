from pathlib import Path


def verify_toy_file(ctx, step):
    toy_name = ctx.parameters.get("toy_name", "toy.txt")
    path = Path(ctx.work_dir) / toy_name
    if not path.is_file():
        raise RuntimeError(f"toy file not found: {path}")
