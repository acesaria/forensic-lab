from pathlib import Path


def verify_toy_file(ctx, step):
    toy_name = ctx.parameters.get("toy_name", "toy.txt")
    path = Path(ctx.work_dir) / toy_name
    if not path.is_file():
        raise RuntimeError(f"toy file not found: {path}")
    ctx.record_truth(
        str(step.get("id", "verify_toy_file")),
        {
            "event_type": "file_observed",
            "object_type": "path",
            "object_identity": str(path),
            "action": "verify",
            "actor": "lab",
            "time": ctx.now(),
            "evidence_basis": ["disk"],
            "attck": [],
            "details": {"size_bytes": path.stat().st_size},
        },
    )
