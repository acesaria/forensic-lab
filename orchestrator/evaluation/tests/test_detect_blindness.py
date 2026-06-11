# Phase 1 boundary test: nothing under orchestrator/evaluation/detect/ may import, read, open,
# or receive any GT manifest or scenario definition. Scans the source for the
# forbidden references and fails on any hit.

import ast
import re
from pathlib import Path

import pytest

_DETECT_DIR = Path(__file__).resolve().parent.parent / "detect"

# Substrings that betray GT awareness. "ground_truth"/"gt_manifest" are the
# manifest; "orchestrator.evaluation.scenario"/"orchestrator.attacks" are scenario modules.
_FORBIDDEN = (
    "gt_manifest",
    "ground_truth",
    "orchestrator.evaluation.scenario",
    "orchestrator.attacks",
    "matching.yaml",
)


def _detect_py_files():
    return sorted(p for p in _DETECT_DIR.rglob("*.py"))


def test_detect_dir_exists():
    assert _DETECT_DIR.is_dir()
    assert _detect_py_files(), "no python files under orchestrator/evaluation/detect/"


@pytest.mark.parametrize("path", _detect_py_files(), ids=lambda p: p.name)
def test_no_forbidden_text(path: Path):
    text = path.read_text(encoding="utf-8")
    # Strip comments/strings is overkill; the tokens must not appear at all,
    # even in a docstring, because their presence signals a design leak.
    for token in _FORBIDDEN:
        assert token not in text, f"{path.name} references forbidden token '{token}'"


@pytest.mark.parametrize("path", _detect_py_files(), ids=lambda p: p.name)
def test_no_scenario_or_match_imports(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        mods: list[str] = []
        if isinstance(node, ast.Import):
            mods = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods = [node.module]
        for mod in mods:
            assert not mod.startswith("orchestrator.evaluation.match"), f"{path.name} imports {mod}"
            assert not mod.startswith("orchestrator.evaluation.scenario"), f"{path.name} imports {mod}"
            assert not re.match(r"orchestrator\.attacks", mod), f"{path.name} imports {mod}"
