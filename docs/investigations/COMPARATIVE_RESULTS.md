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
| ubuntu-22.04_userland_father_ldpreload_20260813-224442 | userland_father_ldpreload (vanilla) | Userland / system-wide `LD_PRELOAD` | `3/1/4/0`; `4/8` (50.0%) | `2/0/1/0`; `2/3` (66.7%) | `3/0/1/0`; `3/4` (75.0%) | `6/1/4/0`; `7/11` (63.6%) | `U/C/S: 1/1/5`; `X: 0`; gain `+3` (M09, M10, M11) | FS `0`; TL `N/A`; Mem `0`; union `0` | not measured | FS: TSK 4.15.0; TL: on-disk `auth.log`/`syslog` (no Plaso); Mem: Volatility 3 2.28.0 |
| ubuntu-22.04_ptrace_fa_20260813-224646 | ptrace_fa (vanilla) | Process / `ptrace` foreign-allocation shellcode injection | `--`; out of scope | `--`; out of scope | `5/0/0/0`; `5/5` (100.0%) | `5/0/0/0`; `5/5` (100.0%) | `U/C/S: 0/0/5`; `X: 0`; gain `+0` | FS `N/A`; TL `N/A`; Mem `2`; union `2` | not measured | Mem: Volatility 3 2.28.0 (`malfind`,`proc.Maps`,`pslist`,`pstree`,`sockstat`) |
| ubuntu-22.04_kernel_diamorphine_20260813-224854 | kernel_diamorphine (vanilla) | Kernel / self-hiding LKM rootkit | `--`; out of scope | `--`; out of scope | `2/0/2/0`; `2/4` (50.0%) | `2/0/2/0`; `2/4` (50.0%) | `U/C/S: 0/0/2`; `X: 0`; gain `+0` | FS `N/A`; TL `N/A`; Mem `0`; union `0` | not measured | Mem: Volatility 3 2.28.0 (`lsmod`,`check_modules`,`hidden_modules`,`modxview`,`check_syscall`,`CheckFtrace`) |
| ubuntu-22.04_kernel_ebpf_badbpf_20260813-225102 | kernel_ebpf_badbpf (vanilla) | Kernel / eBPF process hiding | `--`; out of scope | `--`; out of scope | `5/0/0/0`; `5/5` (100.0%) | `5/0/0/0`; `5/5` (100.0%) | `U/C/S: 0/0/5`; `X: 0`; gain `+0` | FS `N/A`; TL `N/A`; Mem `0`; union `0` | not measured | Mem: Volatility 3 2.28.0 (`pslist`,`psaux`,`proc.Maps`,`ebpf`,`sockstat`) |
| ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919 | userland_father_ldpreload_cleanup (vanilla) | Userland / system-wide `LD_PRELOAD` | `4/1/6/0`; `5/11` (45.5%) | `5/1/6/0`; `6/12` (50.0%) | `3/0/0/0`; `3/3` (100.0%) | `8/1/5/0`; `9/14` (64.3%) | `U/C/S: 2/4/3`; `X: 0`; gain `+3` (M03, M09, M10) | FS `0`; TL `N/A`; Mem `2`; union `2` | Not measured for any source | FS: TSK, ext4magic 0.3.2, PhotoRec; TL: Plaso 20260512 `psort`; Mem: Volatility 3 2.28.0 |
| ubuntu-22.04_ptrace_fa_20260813-173337 | ptrace_fa (vanilla; dirty-revision exception) | Userland / `ptrace` foreign-allocation shellcode injection | `4/0/0/0`; `4/4` (100.0%) | `3/0/0/0`; `3/3` (100.0%) | `5/0/0/0`; `5/5` (100.0%) | `8/0/0/0`; `8/8` (100.0%) | `U/C/S: 0/3/5`; `X: 0`; gain `+3` (P01, P03, P04) | FS `N/A`; TL `N/A`; Mem `3`; union `3` | FS `21s`; TL `122s`; Mem `55s` | FS: TSK 4.15.0; TL: Plaso 20260512 `log2timeline`/`psort`; Mem: Volatility 3 2.28.0 |

The frozen `…_20260813-224442` row is the thesis Chapter 5 exemplar (base,
non-cleanup scenario; commit `2e5dadc`). Its temporal column is bounded
system-log context read from the same acquired disk image, not an independent
Plaso timeline, so filesystem and timeline there are not separate acquisitions;
memory is the only independent acquisition. Its `+3` union gain (M09, M10, M11)
is entirely source-exclusive — targets outside filesystem applicability — rather
than targets an applicable source missed; the single such "applicable-but-missed"
target is M08, classed `U`. No `O`/`P` rests on ground-truth-guided recovery;
the only ground-truth touch point is the M07 filename match after technique-led
discovery of the file. Full detail and the observed-only lower bound are in its
[`runme_case_summary.md`](./userland_father_ldpreload/ubuntu-22.04_userland_father_ldpreload_20260813-224442/runme_case_summary.md).

For the cleanup case row, persistence/activation and runtime are well exposed
while staging/build recovery and direct cleanup-event evidence remain incomplete.
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
