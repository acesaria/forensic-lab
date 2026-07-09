# Test Reliability Audit

Status: hygiene-pass test orientation for Father/Scenario-F metrics cleanup.
Passing tests are useful guardrails, but they are not proof of forensic
correctness or thesis validity.

## Latest Pytest Results

Verified during the hygiene cleanup on 2026-07-09 using the repository
virtualenv:

- Collection command: `.venv/bin/python -m pytest --collect-only -q`
- Collection result: 41 tests collected.
- Smoke command: `.venv/bin/python -m pytest -q`
- Smoke result: 41 passed.

The post-cleanup verification used `PYTHONDONTWRITEBYTECODE=1` to avoid
recreating repo-local `__pycache__` directories during the hygiene pass.

## Meaningful Behavior Guards

- `detectors/tests/test_rule_leakage.py` checks detector rules for scenario
  instance-literal leakage.
- `detectors/tests/test_baseline.py` guards source-family separation, memory
  pass-through, atime exclusion, and symlink retarget behavior for baseline
  filtering.
- `detectors/tests/test_engine.py` checks GT-blind detector output shape,
  detector CLI operation, and memory correlation deduplication.
- `matcher/tests/test_matcher.py` guards many-to-one matching, scored-only
  denominators, exact identity over basename matching, residual-claim
  vocabulary, baseline filter passthrough, and temporal-offset identity rules.
- `matcher/tests/test_pipeline_offline.py` is a compact adapters -> detectors
  -> matcher cross-layer smoke test.
- `orchestrator/adapters/tests/test_tool_adapters.py` covers bodyfile MACB
  metadata, Plaso fallback classification, Volatility row shapes, and adapter
  GT-blindness.
- `orchestrator/core/tests/test_baseline_cache.py` checks cache identity,
  manifest reuse/rejection, and detector/matcher handling of filtered versus
  unfiltered findings.
- `orchestrator/scenarios/tests/test_userland_father_ldpreload.py` guards the
  Father scenario shape, scoring set, real source archive presence, and a
  minimal cached pipeline path.

## Implementation-Coupled Or Vibe-Coded Areas

- Some tests assert exact rule inventory rather than rule behavior rationale.
- The mocked orchestrator baseline test protects call routing, not real
  acquisition or real tool behavior.
- Canonical round-trip fixtures still use historical names such as
  `scenario_01` and `ld_preload_payload`.
- Some detector fixtures intentionally carry historical fields such as
  `temporal_quality` and `time: "unknown"` to preserve backward-load behavior.
- Father tests assert the exact step list and a lower-bound coverage outcome,
  but they do not prove the thesis-level interpretation of the run.
- Adapter tests use small fixture rows and cannot fully represent real Plaso,
  Sleuth Kit, or Volatility output drift.

## Critical Untested Areas

- Live VM lifecycle and power-state behavior.
- Real memory acquisition and disk acquisition.
- Real Plaso/log2timeline/psort behavior on current images.
- Real Volatility3 plugin drift across kernels and versions.
- Full Father no-cleanup live-run metric reproducibility.
- Cleanup-variant behavior and expected artifacts.
- A second full-depth scenario.
- Exact report schema and thesis-facing wording beyond targeted matcher checks.
- Whether planned Sigma/YARA paths are actually wired into the canonical
  detector pipeline.

## Interpretation Rule

Use the tests as regression tripwires for source-shape and methodology
invariants. Do not treat a green suite as evidence that the forensic metrics are
correct, that a live acquisition will work, or that a thesis claim is valid.
