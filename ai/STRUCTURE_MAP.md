# ICM Structure Map

Produced during the 2026-08-20 ICM cleanup. Maps `ai/` as it exists, flags
source-of-truth vs generated files, and lists inconsistencies. `ai/` is
local-only (gitignored).

## Per-directory map

### `_config/` — workspace rules
- **Source of truth:** `conventions.md`, `scope.md`, `done.md`,
  `review-report.md`.
- No `output/`/`references/`.

### `01_refactor` — bounded refactors
- Purpose: behavior-preserving code refactors, minimal diffs.
- `output/father-rootkit-integration.md` — **generated** handoff (Phase B
  result). Keep (documents completed work).
- No `references/`.

### `02_experiments` — scenario execution
- Purpose: run + record one scenario experiment; acquire evidence.
- `output/father/` — **generated** handoffs: `experiment-summary.md`,
  `artifacts.md`, `metrics.md`, `handoff.md` (run `father-u22-20260818-01`).
  Keep.
- No `references/`.

### `03_investigation` — forensic analysis
- Purpose: disk/memory/timeline investigation per `RUN_ID`.
- `references/` — **stable:**
  - `linux-dfir-artifacts.md` (reusable artifact-source table)
  - `tsk-ext4-cheatsheet.md` (imported TSK/ext4 runbook)
  - `investigation-architecture.md` (architecture-of-record, relocated from
    CONTEXT.md in this cleanup)
- `output/` — **generated** handoffs, chronological refactor trail:
  - `notebook-implementation.md` — **superseded** (documents
    `runme_investigate.md`, which was renamed to `history_seed_notebook.md`;
    the executable-Markdown approach was replaced). → archive candidate.
  - `investigation-layer-refactor.md` — partially superseded (its disk portion
    was replaced by the disk notebook) but memory/timeline content still
    current. Keep.
  - `disk-notebook-refactor.md` — current disk-phase implementation record.
    Keep.
  - `disk-investigation-refactor-plan.md` — current planning doc with
    **unresolved open decisions** (§8). Keep.

### `04_docs` — project documentation
- Purpose: simple README/module/scenario docs from validated outputs.
- No `output/`/`references/` yet (nothing produced).

### `05_thesis` — thesis fragments
- Purpose: `.tex` fragments from validated outputs.
- No `output/`/`references/` yet.

## Source-of-truth files (keep, edit carefully)

`IDENTITY.md`, `ROUTING.md`, `DECISIONS.md`, `INDEX.md`, `STRUCTURE_MAP.md`,
`_config/*`, every `CONTEXT.md`, and `03_investigation/references/*`.

## Generated output (regenerable handoffs)

Everything under any `*/output/` directory.

## Inconsistencies found (fixed in this cleanup unless noted)

1. **Stage-numbering drift** — `_config/done.md` and `DECISIONS.md` used the old
   4-stage numbering (`03_docs`, `04_thesis`) instead of the actual 5 stages.
   **Fixed.**
2. **`ai/ai/` double-path bug** — `02_experiments/CONTEXT.md`,
   `phase-a-inspect.md`, `phase-b-implement.md` referenced non-existent
   `ai/ai/...` paths. Fixed in `02_experiments/CONTEXT.md` (rewritten); the two
   phase-* files are archive candidates (see below), not path-fixed.
3. **Stale CONTEXT titles** — `04_docs/CONTEXT.md` was titled "03 Docs";
   `05_thesis/CONTEXT.md` was "04 Thesis". **Fixed.**
4. **Oversized CONTEXT** — `03_investigation/CONTEXT.md` (274 lines) held four
   architecture-of-record sections. **Moved** to
   `references/investigation-architecture.md`; CONTEXT trimmed. No content lost.
5. **`gitignore.snippet` stale/redundant** — lists old dir names and duplicates
   the real `.gitignore` (which already has `/ai/`). Delete candidate (see
   below).
6. **Doc drift (outside write scope, noted only):** `investigations/father/`
   `README.md` mentions `save_raw_output`; the actual helper is `save_raw`
   (per `disk-investigation-refactor-plan.md` §1). Not changed here.
7. **Convention vs reality:** `conventions.md` says every stage must contain
   `references/` and `output/`; `01`, `04`, `05` do not yet. Left as-is (empty
   dirs add no value); noted for awareness.

## Archive / delete candidates (NOT acted on — awaiting confirmation)

Move to a proposed `ai/archive/`:
- `ai/03_investigation/output/notebook-implementation.md` (superseded draft)
- `ai/phase-a-inspect.md`, `ai/phase-b-implement.md` (Father refactor complete;
  historical prompts, also carry the `ai/ai/` bug)
- `ai/father-refactor-plan.md` (Father refactor complete; keep as historical
  decision record, or archive)

Delete permanently:
- `ai/gitignore.snippet` (stale + redundant with the real `.gitignore`)
