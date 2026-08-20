# ICM Cleanup — Review Report (Phase 1)

> **Status:** historical Phase-1 report. Current routing and decisions live in
> `ai/INDEX.md`, `ai/DECISIONS.md`, and the stage `CONTEXT.md` files.

Date: 2026-08-20. Scope: read/map/clean the `ai/` ICM workspace before metrics
definition. `ai/` is local-only (gitignored).

## What I found (main problems)

1. **Stage-numbering drift.** The workspace was renumbered from 4 to 5 stages
   (a dedicated `03_investigation` was inserted, pushing docs→`04_docs`,
   thesis→`05_thesis`), but `_config/done.md`, `DECISIONS.md`, and
   `gitignore.snippet` still referenced the old `03_docs`/`04_thesis` names.
2. **`ai/ai/` double-path bug.** `02_experiments/CONTEXT.md`,
   `phase-a-inspect.md`, and `phase-b-implement.md` pointed at non-existent
   `ai/ai/...` paths.
3. **Oversized CONTEXT.** `03_investigation/CONTEXT.md` was 274 lines and mixed
   short routing with four architecture-of-record sections.
4. **Stale CONTEXT titles.** `04_docs` was titled "03 Docs"; `05_thesis` was
   "04 Thesis".
5. **Superseded draft.** `03_investigation/output/notebook-implementation.md`
   documents `runme_investigate.md`, which no longer exists (renamed to
   `history_seed_notebook.md` when executable-Markdown was dropped).
6. **Stale, redundant file.** `gitignore.snippet` duplicates the real
   `.gitignore` (which already ignores `/ai/`) and lists old dir names.
7. **Minor doc drift (outside write scope).** `investigations/father/README.md`
   mentions `save_raw_output`; the real helper is `save_raw`.

## What I did (concrete actions)

- Rewrote `_config/done.md` and `DECISIONS.md` to the correct 5-stage numbering;
  added D-008 recording the split into `03_investigation` and the 5-stage
  structure.
- Rewrote all five `CONTEXT.md` files to a short Problem → Current state →
  Next steps shape; fixed the `ai/ai/` paths in `02_experiments/CONTEXT.md` and
  the stale titles in `04_docs`/`05_thesis`.
- Moved the four architecture sections out of `03_investigation/CONTEXT.md` into
  `03_investigation/references/investigation-architecture.md` (no content lost).
- Created `INDEX.md` (agent-facing navigation) and `STRUCTURE_MAP.md` (this
  cleanup's map); added a Navigation block to `ROUTING.md` pointing at both.
- Verified all paths referenced by `ROUTING.md` and the new docs exist.

## What remains to be done (pending)

- **Confirm archival/deletion** (not acted on — see list below).
- **Resolve the six open decisions** in
  `03_investigation/output/disk-investigation-refactor-plan.md` §8 before
  redesigning disk findings/metrics.
- **Metrics definition** (the reason for this cleanup) — the candidate metric
  set is in that same plan §6.
- Optionally fix the `save_raw_output` → `save_raw` drift in
  `investigations/father/README.md` (a stage-03/04 doc task, not this cleanup).

## Archive / delete candidates (awaiting your confirmation)

Archive (to a proposed `ai/archive/`): `notebook-implementation.md`,
`phase-a-inspect.md`, `phase-b-implement.md`, `father-refactor-plan.md`.
Delete: `gitignore.snippet`. Details and rationale in `STRUCTURE_MAP.md`.

## Unverified assertions requiring human validation

These appear in the workspace/handoffs and should be validated, not taken as
settled:

1. **"The deleted `/tmp/rk.so` is byte-for-byte identical to the installed
   `/usr/lib/selinux.so.3`"** (`disk-investigation-refactor-plan.md`) — holds
   for run `father-u22-20260819-03`; confirm it is stable across runs before
   generalizing "content recovery is moot".
2. **"ext4 journal shows directory-entry corroboration but zero ELF headers →
   no file-content recovery"** — a run-specific result; re-verify per run, not a
   universal claim.
3. **Adjacent-hidden-file limitation is only single-view demonstrated**
   (`father-rootkit-integration.md`) — the two-view hooked-vs-bypass comparison
   was never implemented; do not describe it as fully proven.
4. **"TSK reads the E01 directly via libewf, no raw conversion required"** and
   the combined flag spellings (`fls -rd`, `blkls -e`, `tsk_recover -e`,
   `ils -r`, `ifind -d`) — the plan itself flags these as "verify against the
   installed TSK version".
5. **Memory ISF fallback** ("newest same-family ISF if no exact kernel match")
   is a stated misattribution risk — validate per kernel.
6. **Metric denominators** (`disk-investigation-refactor-plan.md` §6/§8.4) —
   whether metric 5's denominator is 2 (surviving staged files) or 3 (incl. the
   deleted `rk.so`) is unresolved.

## Recommendations for the future

- Every new file follows `_config/conventions.md`: factual, concise, exact
  paths; task handoffs go in the stage `output/`, stable reusable material in
  `references/`.
- Keep `CONTEXT.md` ≤ 1 page (Problem → Current state → Next steps); push
  durable detail into `references/`.
- When renaming/renumbering stages, update `done.md`, `DECISIONS.md`,
  `ROUTING.md`, `INDEX.md`, and `STRUCTURE_MAP.md` together.
- Keep run-specific findings out of `references/`; they belong under
  `shared/investigations/<RUN_ID>/`.
