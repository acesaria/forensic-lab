# Comparative results

Cross-run manual evidence-recovery coverage. One row per source per run, plus a
union row. Descriptive post-mortem coverage — not automatic detection accuracy;
no precision/recall/F1, no weighting, no averaging of per-source rates.
Definitions and method are frozen in `REPORT_GUIDE.md`. Each run's auditable
target-by-source table lives in that run's report.

`DR` = Found / Total applicable (manual evidence-recovery coverage). `FP` is a
count of rejected candidates (`N/A` when a source generated none). `TTD` is
prospective wall-clock; `not measured` when not recorded live. `QoR` is
High/Medium/Low.

| Run | Scenario | Source | Found / Total | Coverage (DR) | FP | TTD | QoR | Principal tools | Notes |
|---|---|---|---|---|---|---|---|---|---|
| ubuntu-22.04_userland_father_ldpreload_20260722-175300 | userland_father_ldpreload (vanilla) | Filesystem | 8 / 8 | 100% | N/A | not measured | High | TSK (`fls`/`istat`/`icat`) | Full persistence chain; M08 command strings partial (no timing). |
| ubuntu-22.04_userland_father_ldpreload_20260722-175300 | userland_father_ldpreload (vanilla) | Timeline | 8 / 9 | 88.9% | N/A | not measured | Medium | Plaso 20260512 | M08 not observed — no `#<epoch>` history → 0 `text/bash_history`; M03 partial. |
| ubuntu-22.04_userland_father_ldpreload_20260722-175300 | userland_father_ldpreload (vanilla) | Memory | 3 / 3 | 100% | 2 | not measured | High | Volatility 3 2.28.0 | FP = 2 rejected `malfind` heuristic rows (PID 365, PID 438). |
| ubuntu-22.04_userland_father_ldpreload_20260722-175300 | userland_father_ldpreload (vanilla) | Union | 11 / 11 | 100% | 2 case-wide | not measured | — | disk + timeline + memory | Observed calibration result, not a pass condition. |
