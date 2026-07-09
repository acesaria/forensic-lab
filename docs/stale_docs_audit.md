# Stale Documentation Audit

Status: updated after the stale-planning archive pass. This file classifies the
active planning/docs surface for future Codex/Fable prompts before Father
metrics/rule/report cleanup.

Archived documents are historical only. Do not treat archived TODO, REFACTOR,
AUDIT, or prompt files as current instructions.

## Source-Of-Truth Hierarchy

1. `PROJECT_CONTEXT.md` and `AGENTS.md`, when present and current.
2. `METHODOLOGY.md` for evaluation vocabulary, matching, and metrics.
3. `TODO.md` for the active execution plan.
4. `docs/repo_map.md` for repository orientation.
5. Latest explicit `report.md`, `metrics.json`, and `outcomes.jsonl` for a
   named run.

## Active Files

| File | Status | Notes |
|---|---|---|
| `PROJECT_CONTEXT.md` | current | Repo identity, canonical pipeline, source map, and invariants. |
| `AGENTS.md` | current | Agent behavior contract and definition of done. |
| `METHODOLOGY.md` | current | Normative matcher/metrics semantics. |
| `TODO.md` | current | Single active execution plan for the thesis rescue phase. |
| `README.md` | current | High-level thesis framing and repository layout. |
| `docs/repo_map.md` | current | Hygiene-pass orientation; use with the root truth files. |
| `docs/test_reliability_audit.md` | current | Test-suite trust map and warning that tests do not prove forensic correctness. |
| `docs/stale_docs_audit.md` | current | This classification file. |
| `scenarios/scenarios/userland_father_ldpreload/README.md` | current | Father scenario scope and safety limits. |
| `detectors/rules/README.md` | current | Detector rule-pack format and GT-blindness reminder. |

## Archived Historical Planning Files

Archived under `docs/archive/stale-planning-2026-07-08/` with filenames
preserved:

- `REFACTOR_PLAN.md`
- `AUDIT_NOTES.md`
- `codex-prompts.md`
- `refactor-5.md`

These files preserve rationale and old handoff context only. They are not part
of the active instruction surface.

## Partially Stale Files Kept With Warning Banners

| File | Status | Notes |
|---|---|---|
| `docs/father_ldpreload_walkthrough.md` | historical/partially stale | Kept for cached-run examples, but it contains old report names, counts, and candidate-stream language. |
| `docs/detection_rule_audit.md` | historical/partially stale | Kept for rule critique and rationale, but current rule work must verify against `TODO.md`, `METHODOLOGY.md`, `docs/repo_map.md`, and latest metrics. |

## Remaining Docs Hazards

- `orchestrator/forensics/pipeline.yaml` still names planned Sigma/YARA paths
  and retired `orchestrator/evaluation` config paths. Treat this as a
  future/reproducibility manifest until a task verifies current wiring.
- `requirements.txt` still has comments tied to the retired evaluation stack.
  Dependency cleanup is out of scope for this documentation pass.
- `orchestrator/forensics/yara_runner.py` still has comments about
  evaluation-era YARA emission and `scenario_01`. Do not infer current pipeline
  behavior from those comments.
- `.claude/settings.local.json` is ignored/local and was not edited. Local
  Claude settings may contain stale permissions or paths and should not be
  treated as project documentation.

## Prompt Context Rule

Use the active source-of-truth hierarchy above for future prompts. Historical
docs may be cited for rationale only after checking current source and the
latest explicit run artifacts.

For the next implementation step, it is safe to proceed with the
Father/Scenario-F no-cleanup metrics/rule/report cleanup prompt, provided that
prompt does not reopen VM orchestration, acquisition, scenario payload changes,
or major tool integrations.
