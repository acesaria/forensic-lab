# Stale Documentation Audit

Status: updated after the manual-investigation pivot. This file classifies the
active planning/docs surface for future Codex/Fable prompts during the
automatic-pipeline migration.

Archived documents are historical only. Do not treat archived TODO, REFACTOR,
AUDIT, or prompt files as current instructions.

## Source-Of-Truth Hierarchy

1. `PROJECT_CONTEXT.md` and `AGENTS.md`, when present and current.
2. `METHODOLOGY.md` for manual investigation, provenance, profile comparison,
   and explicit non-goals.
3. `TODO.md` for the active execution plan.
4. `docs/repo_map.md` for repository orientation.
5. Named run artifacts: manifest, command log, raw TSK/Plaso/Volatility
   exports, hashes, tool failures, and analyst notes.

## Active Files

| File | Status | Notes |
|---|---|---|
| `PROJECT_CONTEXT.md` | current | Repo identity, migration state, target workflow, source map, and invariants. |
| `AGENTS.md` | current | Agent behavior contract and definition of done. |
| `METHODOLOGY.md` | current | Normative manual-investigation methodology. |
| `TODO.md` | current | Single active execution plan for the migration phase. |
| `README.md` | current | High-level thesis framing and repository layout. |
| `docs/repo_map.md` | current | Migration orientation; use with the root truth files. |
| `docs/test_reliability_audit.md` | current/legacy-aware | Test-suite trust map and warning that tests do not prove forensic correctness or manual-investigation quality. |
| `docs/stale_docs_audit.md` | current | This classification file. |
| `scenarios/scenarios/userland_father_ldpreload/README.md` | current | Father scenario scope and safety limits. |
| `detectors/rules/README.md` | removed | Legacy detector rule-pack format removed with the automatic pipeline. |

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
| `docs/father_ldpreload_walkthrough.md` | historical/partially stale | Kept for cached-run examples from the automatic-reconstruction era; not current methodology. |
| `docs/detection_rule_audit.md` | historical/partially stale | Kept for rule critique and rationale from the automatic-reconstruction era; not current methodology. |

## Remaining Docs Hazards

- Legacy automatic-evaluation source under `orchestrator/adapters/`,
  `orchestrator/canonical/`, `detectors/`, and `matcher/` has been removed.
- `orchestrator/forensics/pipeline.yaml` now tracks raw extraction tool
  versions, not detector rulesets or matching config.
- `orchestrator/forensics/yara_runner.py` still has comments about
  evaluation-era YARA emission and `scenario_01`. Do not infer current thesis
  behavior from those comments.
- `.claude/settings.local.json` is ignored/local and was not edited. Local
  Claude settings may contain stale permissions or paths and should not be
  treated as project documentation.

## Prompt Context Rule

Use the active source-of-truth hierarchy above for future prompts. Historical
docs may be cited for rationale only after checking current source and the
latest explicit run artifacts.

For later cleanup, prioritize remaining historical terminology over new
detector/matcher work. Do not reopen VM orchestration, acquisition, scenario
payload changes, tests, dependencies, or major tool integrations unless the task
explicitly asks.
