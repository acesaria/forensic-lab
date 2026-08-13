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

Coverage denominators are source-specific and case-specific. Each coverage
figure is descriptive within its own declared applicability set and must not be
used to rank the source families, nor to compare cases whose target inventories
differ. `Union gain` names the contributing target IDs, because a gain drawn
from targets outside the comparator source's applicability is a weaker claim
than one drawn from a target an applicable source missed. Where a case derives
its timeline from the same acquired disk image as its filesystem examination,
those two families are separate for counting but are not separate acquisitions;
the case summary states per target whether a corroboration rests on different
artifact classes or on parser-level replication.

| Run | Case | Layer / technique | Filesystem `O/P/N/TF; Found/A (Cov)` | Timeline `O/P/N/TF; Found/A (Cov)` | Memory `O/P/N/TF; Found/A (Cov)` | Union `O/P/N/TF; Found/A (Cov)` | Cross-source | Rejected candidates | TTF | Principal methods |
|---|---|---|---|---|---|---|---|---|---|---|
| ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919 | userland_father_ldpreload_cleanup (vanilla) | Userland / system-wide `LD_PRELOAD` | `4/1/6/0`; `5/11` (45.5%) | `5/1/6/0`; `6/12` (50.0%) | `3/0/0/0`; `3/3` (100.0%) | `8/1/5/0`; `9/14` (64.3%) | `U/C/S: 2/4/3`; `X: 0`; gain `+3` (M03, M09, M10) | FS `0`; TL `N/A`; Mem `2`; union `2` | Not measured for any source | FS: TSK, ext4magic 0.3.2, PhotoRec; TL: Plaso 20260512 `psort`; Mem: Volatility 3 2.28.0 |
| ubuntu-22.04_ptrace_fa_20260813-173337 | ptrace_fa (vanilla; dirty-revision exception) | Userland / `ptrace` foreign-allocation shellcode injection | `4/0/0/0`; `4/4` (100.0%) | `3/0/0/0`; `3/3` (100.0%) | `5/0/0/0`; `5/5` (100.0%) | `8/0/0/0`; `8/8` (100.0%) | `U/C/S: 0/3/5`; `X: 0`; gain `+3` (P01, P03, P04) | FS `N/A`; TL `N/A`; Mem `3`; union `3` | FS `21s`; TL `122s`; Mem `55s` | FS: TSK 4.15.0; TL: Plaso 20260512 `log2timeline`/`psort`; Mem: Volatility 3 2.28.0 |

For this case, persistence/activation and runtime are well exposed while
staging/build recovery and direct cleanup-event evidence remain incomplete.
That asymmetry is a result of the cleanup treatment and bounded methods, not an
acceptance failure. M03 rests on ground-truth-guided recovery; discounting it
gives filesystem `4/11` (36.4%), union `8/14` (57.1%), and union gain `+2`. The
case summary carries the full sensitivity and the observed-only lower bound.

For the current prepared-binary `ptrace_fa` case, the small 8-target inventory
is fully exposed: filesystem and timeline describe runtime staging and static
capability (P01-P04, read from the same acquired disk through two tools), while
memory recovers every behavioral target (P05-P08). The `+3` gain remains drawn
from targets outside memory applicability. All three TTF values were recorded
prospectively; timeline's 122 seconds includes two recoverable Plaso partition-
selection failures. The manifest revision ends in `-dirty` because the human
explicitly waived the clean-tree gate for unrelated parallel deadline work.
The case summary treats this as weaker provenance than a clean authoritative
run and does not conceal it.
