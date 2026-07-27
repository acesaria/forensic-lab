# Comparative results

Cross-run manual evidence-recovery coverage. One row per source per run, plus a
union row. Descriptive post-mortem coverage — not automatic detection accuracy;
no precision/recall/F1, no weighting, no averaging of per-source rates.
Definitions and method are frozen in `REPORT_GUIDE.md`. Each run's auditable
target-by-source table lives in that run's report.

`DR` = Found / Total applicable (manual evidence-recovery coverage). `FP` is a
count of rejected candidates (`0` when candidate generation was applied and no
rejected candidates remain; `N/A` when no candidate-generating method was
applied). `TTD` is prospective wall-clock; `not measured` when not recorded
prospectively. `QoR` is `High`, `Medium`, `Low`, or `N/A`; the union row is
`N/A` because no aggregate union QoR is assigned.

| Run | Scenario | Source | Found / Total | Coverage (DR) | FP | TTD | QoR | Principal tools | Notes |
|---|---|---|---|---|---|---|---|---|---|
| ubuntu-22.04_userland_father_ldpreload_20260722-175300 | userland_father_ldpreload (vanilla) | Filesystem | 8 / 8 | 100% | N/A | not measured | High | TSK (`fls`/`istat`/`icat`) | Full persistence chain; M08 command strings partial (no timing). |
| ubuntu-22.04_userland_father_ldpreload_20260722-175300 | userland_father_ldpreload (vanilla) | Timeline | 8 / 9 | 88.9% | N/A | not measured | Medium | Plaso 20260512 | M08 not observed — no `#<epoch>` history → 0 `text/bash_history`; M03 partial. |
| ubuntu-22.04_userland_father_ldpreload_20260722-175300 | userland_father_ldpreload (vanilla) | Memory | 3 / 3 | 100% | 2 | not measured | High | Volatility 3 2.28.0 | FP = 2 rejected `malfind` heuristic rows (PID 365, PID 438). |
| ubuntu-22.04_userland_father_ldpreload_20260722-175300 | userland_father_ldpreload (vanilla) | Union | 11 / 11 | 100% | 2 case-wide | not measured | N/A | TSK + Plaso + Volatility 3 | Observed calibration result, not a pass condition. |
| ubuntu-22.04_userland_father_ldpreload_cleanup_20260724-162708 | userland_father_ldpreload_cleanup (vanilla) | Filesystem | 7 / 11 | 63.6% | 23 | 0 s (1 s resolution) | High | TSK (`fls`/`istat`/`icat`/`blkls`/`blkcalc`), ext4magic 0.3.2 | `src/config.h` recovered at level 5 (block 589851); archive, `rk.so`, `.bash_history` remain level 0—not recovered by the bounded method. FP = 18 `ustar` output lines, 1 ELF header, 4 `Makefile` matches. |
| ubuntu-22.04_userland_father_ldpreload_cleanup_20260724-162708 | userland_father_ldpreload_cleanup (vanilla) | Timeline | 7 / 12 | 58.3% | N/A | 12 s | Medium | Plaso 20260512 | Journal `sudo` records preserve the deleted tree's path and the install/activate/restart commands; no literal deletion event for any cleanup target; M08 and C02 partial. |
| ubuntu-22.04_userland_father_ldpreload_cleanup_20260724-162708 | userland_father_ldpreload_cleanup (vanilla) | Memory | 3 / 3 | 100% | 2 | 1 min 16 s | High | Volatility 3 2.28.0 | FP = 2 rejected `malfind` RWX rows (PID 368, PID 446). Acquisition metadata does not establish shutdown overlap. |
| ubuntu-22.04_userland_father_ldpreload_cleanup_20260724-162708 | userland_father_ldpreload_cleanup (vanilla) | Union | 11 / 14 | 78.6% | 25 case-wide | 0 s (1 s resolution) | N/A | TSK + Plaso + Volatility 3 | Not found in any source: M01 archive staged, C01 archive cleanup, C03 history cleanup. Observed result, not a pass condition. |
