# Anti-circularity lint: collect every instance-looking string literal from
# canonical run artifacts (artifact expectations and execution truth, real runs
# and fixtures) and fail if any appears verbatim in a detector rule under
# detectors/rules/.
#
# A detection rule that hardcodes an instance value is a circularity leak: it
# would "detect" the seeded artifact by memorising it, and would break on the
# next random seed. Behavioral patterns (classes of paths, message shapes) are
# fine; the specific planted constant is not.

import json
import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
_RULES_DIR = _ROOT / "detectors" / "rules"

# Ground truth lives next to runs and in test fixtures. Scan both so a leak is
# caught whether it came from a real run or a fixture.
_GT_GLOBS = (
    "matcher/tests/fixtures/artifact_expectations.jsonl",
    "shared/experiments/*/dumps/artifact_expectations.jsonl",
    "shared/experiments/*/dumps/execution_truth.jsonl",
    "shared/experiments/*/artifact_expectations.jsonl",
    "shared/experiments/*/execution_truth.jsonl",
)

# Tokens too generic to be "instance" values; matching them would be noise, not
# a real leak (every preload rule legitimately says /etc/ld.so.preload).
_GENERIC = {
    "/etc/ld.so.preload",  # T1574.006 mechanism path, intrinsic not instance
    "ld.so.preload",
    "ubuntu-22.04",
    "UTC",
    "user1",
    "labuser",
    "root",
}


def _iter_gt_strings():
    for pattern in _GT_GLOBS:
        for path in _ROOT.glob(pattern):
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except OSError:
                continue
            for line in lines:
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                yield from _strings_in(obj)


def _strings_in(obj):
    if isinstance(obj, str):
        if obj and obj not in _GENERIC:
            yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _strings_in(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings_in(v)


def _instance_literals() -> set[str]:
    # Keep only values that look like instance constants worth guarding:
    # filesystem paths, basenames with an extension, ip:port sockets, and exact
    # timestamps. Plain class words (technique ids) are excluded.
    out: set[str] = set()
    for s in _iter_gt_strings():
        if s.startswith("/") and len(s) > 1:
            out.add(s)
            base = s.rstrip("/").rsplit("/", 1)[-1]
            # Only guard basenames that actually look like a randomized instance
            # filename (long enough, and carrying a dot/underscore/digit). Trivial
            # names like "x" are not secrets and would flag every rule.
            if len(base) >= 5 and (
                "." in base or "_" in base or any(c.isdigit() for c in base)
            ):
                out.add(base)
        elif re.match(r"^\d+\.\d+\.\d+\.\d+(:\d+)?$", s):
            out.add(s)
        elif re.match(r"^\d{4}-\d{2}-\d{2}T", s):
            out.add(s)
    return {x for x in out if x not in _GENERIC}


def _rule_files():
    return [p for p in _RULES_DIR.rglob("*.yml") if p.is_file()]


def test_no_instance_literal_in_detector_rules():
    literals = _instance_literals()
    if not literals:
        return  # nothing seeded yet; lint is a no-op until a run/fixture exists
    offenders = []
    for rule in _rule_files():
        text = rule.read_text(encoding="utf-8")
        for lit in literals:
            if lit in text:
                offenders.append((rule.relative_to(_ROOT).as_posix(), lit))
    assert not offenders, f"instance literals leaked into rules: {offenders}"
