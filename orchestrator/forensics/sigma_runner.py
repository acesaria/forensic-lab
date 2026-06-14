# orchestrator/forensics/sigma_runner.py
#
# Thin Sigma-rule I/O over the vendored SigmaHQ subset (vendor/sigma/). No
# classes, no GT awareness: this module only LOADS and logsource-FILTERS rules
# for the Linux/Plaso pipeline. Evaluation against events and Finding emission
# happen one layer up, in orchestrator/evaluation/detect/sigma_vendored.py, so
# this stays in the forensics tool-I/O layer (no evaluation imports).
#
# pySigma is used to parse/validate rules when installed; otherwise the rules are
# read with PyYAML (the in-memory evaluator only needs the detection/logsource
# dicts, which both paths produce identically).

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

_log = logging.getLogger(__name__)

_VENDOR_DIR = Path(__file__).resolve().parents[2] / "vendor" / "sigma"

# Plaso emits Linux log/process events; only these Sigma logsources can match.
_PLASO_LOGSOURCES: tuple[tuple[str | None, str | None], ...] = (
    # (category, service); None means "do not constrain on this field".
    ("process_creation", None),
    (None, "syslog"),
    (None, "auth"),
    (None, "sshd"),
    (None, "cron"),
    (None, "sudo"),
)


def vendored_rules_dir() -> Path:
    return _VENDOR_DIR / "rules" / "linux"


def pinned_commit() -> str | None:
    # The pinned upstream commit recorded next to the vendored tree.
    f = _VENDOR_DIR / "COMMIT.txt"
    if not f.is_file():
        return None
    for line in f.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            return line
    return None


def _logsource_matches(rule: dict[str, Any]) -> bool:
    ls = rule.get("logsource", {}) or {}
    product = ls.get("product")
    if product not in (None, "linux"):
        return False
    cat, svc = ls.get("category"), ls.get("service")
    for want_cat, want_svc in _PLASO_LOGSOURCES:
        if want_cat is not None and cat != want_cat:
            continue
        if want_svc is not None and svc != want_svc:
            continue
        return True
    # A product:linux rule with no recognised category/service is still kept; the
    # evaluator will simply not match if its fields are absent.
    return product == "linux"


def load_rules(rules_dir: Path | None = None) -> list[dict[str, Any]]:
    # Returns the Linux Sigma rule documents that can match Plaso events. Tries
    # pySigma for parsing/validation, then reads the raw YAML the evaluator needs.
    d = rules_dir or vendored_rules_dir()
    if not d.is_dir():
        _log.warning("vendored Sigma rules dir missing: %s", d)
        return []

    paths = sorted(d.rglob("*.yml")) + sorted(d.rglob("*.yaml"))
    _maybe_validate_with_pysigma(paths)

    rules: list[dict[str, Any]] = []
    for p in paths:
        try:
            for doc in yaml.safe_load_all(p.read_text(encoding="utf-8")):
                if isinstance(doc, dict) and "detection" in doc:
                    doc.setdefault("_path", str(p))
                    if _logsource_matches(doc):
                        rules.append(doc)
        except yaml.YAMLError as exc:
            _log.warning("skipping unparseable Sigma rule %s: %s", p, exc)
    return rules


def _maybe_validate_with_pysigma(paths: list[Path]) -> None:
    # Best-effort: when pySigma is installed, parse the rules so a malformed rule
    # surfaces here rather than silently never matching. Parsing only; we do not
    # convert to a backend query (we evaluate in-memory downstream).
    try:
        from sigma.collection import SigmaCollection  # type: ignore
    except ImportError:
        return
    for p in paths:
        try:
            SigmaCollection.from_yaml(p.read_text(encoding="utf-8"))
        except Exception as exc:  # pragma: no cover - depends on optional dep
            _log.warning("pySigma rejected %s: %s", p, exc)
