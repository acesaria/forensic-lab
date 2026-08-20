# Decisions

- D-001 | 2026-08-18 | Adopt minimal ICM-style local AI workspace with numbered stages | active
- D-002 | 2026-08-18 | Delete previous AI layer completely | active
- D-003 | 2026-08-18 | Keep workspace local-only and excluded from version control (`/ai/` in `.gitignore`) | superseded-by-D-012
- D-004 | 2026-08-18 | `02_experiments` runs/acquires scenarios; `runme.sh`-based analytical material moved to its own stage (see D-008) | superseded-by-D-008
- D-005 | 2026-08-18 | `04_docs` is for simple README-style project/scenario documentation only | active
- D-006 | 2026-08-18 | `05_thesis` writes only `.tex` fragments and only from validated outputs/docs | active
- D-007 | 2026-08-18 | Avoid unnecessary new tests; preserve current working behavior | active
- D-008 | 2026-08-18 | Split forensic investigation into a dedicated stage `03_investigation`, shifting docs to `04_docs` and thesis to `05_thesis` (5-stage structure) | active
- D-009 | 2026-08-20 | Use the simple investigation-results method in `03_investigation/references/results-tables-methodology.md`: scenario-execution table, reconstruction matrix, source/triage summary, manual coverage, and rejected-candidate accounting | active
- D-010 | 2026-08-20 | Treat deleted-content recovery as a research question with treatment details still open; use one descriptive run per scenario/distribution and a targeted second review | active
- D-011 | 2026-08-20 | Report benign/unrelated outputs from candidate-generating checks as rejected candidates under RQ3 triage burden; keep them outside reconstruction coverage and do not calculate a false-positive rate without a defined negative universe | active
- D-012 | 2026-08-20 | Keep `ai/` as a tracked internal coordination layer; it routes work but is not forensic evidence or a thesis deliverable | active
- D-013 | 2026-08-20 | Route Claude with short task prompts that start at `ai/INDEX.md`, name one stage and a bounded allowlist, and rely on ICM instead of repeating project context | active
- D-014 | 2026-08-20 | Keep the personal thesis-review skill as an ICM-aware Codex helper; place only its concise tool-neutral review gate in stage 05 so Claude does not depend on personal skill installation | active
