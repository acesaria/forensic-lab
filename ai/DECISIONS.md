# Decisions

- D-001 | 2026-08-18 | Adopt minimal ICM-style local AI workspace with numbered stages | active
- D-002 | 2026-08-18 | Delete previous AI layer completely | active
- D-003 | 2026-08-18 | Keep workspace local-only and excluded from version control (`/ai/` in `.gitignore`) | active
- D-004 | 2026-08-18 | `02_experiments` runs/acquires scenarios; `runme.sh`-based analytical material moved to its own stage (see D-008) | superseded-by-D-008
- D-005 | 2026-08-18 | `04_docs` is for simple README-style project/scenario documentation only | active
- D-006 | 2026-08-18 | `05_thesis` writes only `.tex` fragments and only from validated outputs/docs | active
- D-007 | 2026-08-18 | Avoid unnecessary new tests; preserve current working behavior | active
- D-008 | 2026-08-18 | Split forensic investigation into a dedicated stage `03_investigation`, shifting docs to `04_docs` and thesis to `05_thesis` (5-stage structure) | active
