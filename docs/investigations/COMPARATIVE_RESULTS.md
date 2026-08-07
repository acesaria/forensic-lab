# Comparative results

Cross-run manual evidence-recovery results for accepted authoritative
investigations. There is exactly one row per run ID; draft and superseded runs
are excluded. The exact status, coverage, contribution, candidate, and timing
definitions are fixed in [METHODOLOGY.md](../../METHODOLOGY.md). Each case's
target inventory, applicability decisions, evidence locators, and limitations
remain auditable in its `runme_case_summary.md`.

These are descriptive post-mortem metrics, not automatic detection accuracy.
No precision, recall, F1, qualitative quality score, source weighting, or
average of per-source rates is used. Source cells use
`O/P/N/TF; Found/A (Coverage)`. `TTF` appears only when measured prospectively.

| Run | Case | Layer / technique | Filesystem | Timeline | Memory | Union | Cross-source | Rejected candidates | TTF | Principal methods |
|---|---|---|---|---|---|---|---|---|---|---|
| ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919 | userland_father_ldpreload_cleanup (vanilla) | Userland / system-wide `LD_PRELOAD` | `4/1/6/0`; `5/11` (45.5%) | `5/1/6/0`; `6/12` (50.0%) | `3/0/0/0`; `3/3` (100%) | `8/1/5/0`; `9/14` (64.3%) | `U/C/S: 2/4/3`; `X: 0`; gain `+3` targets | FS `0`; TL `N/A`; Mem `2`; union `2` | Not measured for any source | FS: TSK, ext4magic 0.3.2, PhotoRec; TL: Plaso 20260512 `psort`; Mem: Volatility 3 2.28.0 |

For this case, persistence/activation and runtime are well exposed while
staging/build recovery and direct cleanup-event evidence remain incomplete.
That asymmetry is a result of the cleanup treatment and bounded methods, not an
acceptance failure.
