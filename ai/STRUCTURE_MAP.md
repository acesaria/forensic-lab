# ICM structure map

Current map of the tracked internal coordination layer. Enter through
`ai/INDEX.md`; do not load this map unless structural review is needed.

## Authority order

1. The user's exact task and stop gate.
2. `ai/DECISIONS.md`.
3. The selected stage's `CONTEXT.md` and stable `references/`.
4. Validated run/investigation artifacts outside `ai/` for factual results.
5. Stage `output/` handoffs.
6. `ai/archive/`, historical prompts/reports, and the historical thesis plan.

An ICM note never overrides current code, manifests, acquisition records, or
accepted forensic evidence.

## Directories

| Directory | Purpose | Current state |
|---|---|---|
| `_config/` | Small global scope, conventions, and done criteria | Active rules; `review-report.md` is historical |
| `01_refactor/` | Bounded behavior-preserving code changes | One historical Father handoff |
| `02_experiments/` | Scenario execution and acquisition | Historical Father handoff; task selects the active run |
| `03_investigation/` | Per-run disk, memory, and timeline work | Father only implemented; active results contract in `references/` |
| `04_docs/` | Simple project/scenario documentation | No handoff yet |
| `05_thesis/` | Bounded `.tex` fragments from validated evidence | No handoff yet |
| `archive/` | Superseded methodology and completed prompts/plans | Background only |

## Stable files

- `INDEX.md`: single entry point and short executor-prompt rule.
- `IDENTITY.md`: global boundaries and read order.
- `ROUTING.md`: stage selection and handoff chain.
- `DECISIONS.md`: active/superseded decisions.
- `_config/{conventions,scope,done}.md`: small workspace rules.
- every stage `CONTEXT.md`: short stage-specific authority.
- `03_investigation/references/investigation-architecture.md`: current
  investigation implementation shape.
- `03_investigation/references/investigation-guidelines.md`: notebook style.
- `03_investigation/references/results-tables-methodology.md`: active RQs,
  tables, coverage, triage/rejected-candidate, recovery, and review rules.
- `05_thesis/references/thesis-review-checklist.md`: portable scientific and
  presentation gate, loaded only for thesis audit/refactor/final review.
- source-specific technical references in `03_investigation/references/`, read
  only when a task needs them.

## Generated or historical material

- Files under a stage `output/` are task handoffs/research notes, not automatic
  authority for later tasks.
- `03_investigation/output/metrics-methodology-deep-research-report.md` is
  background; the simpler results-methodology reference supersedes it.
- `thesis-finalization-plan.md` is a historical planning snapshot and is not
  loaded by default.
- `icm-cleanup-prompt.md` and `_config/review-report.md` document the completed
  Phase-1 cleanup.
- `archive/` is never an active entry point.

## Real work products

- Experiments/evidence: `shared/experiments/<RUN_ID>/`.
- Derived investigations: `shared/investigations/<RUN_ID>/`.
- Reusable investigation workflows: `investigations/<scenario>/`.
- Project documentation: `docs/` and repository README/scenario docs.
- Thesis sources: the active thesis tree named by the stage-05 task.

## Current known boundaries

- Only `investigations/father/` exists; the ptrace, Diamorphine, and BadBPF
  investigation workflows still need bounded scenario-specific work.
- Father disk and deleted-content recovery work is incomplete; no ICM summary
  may promote provisional observations to final results.
- Cross-distribution results are descriptive and compared within the same
  scenario using the same reconstruction-item list/procedure.
- Claude is routed with a short task prompt through `ai/INDEX.md`; it does not
  load unrelated stages or receive duplicated project summaries.
