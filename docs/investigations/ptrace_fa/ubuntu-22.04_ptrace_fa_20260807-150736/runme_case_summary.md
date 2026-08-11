---
cwd: ../../../..
shell: bash
---

# ptrace_fa case summary and metrics

__Run:__ `ubuntu-22.04_ptrace_fa_20260807-150736`

**Scope:** cross-source interpretation and manual evidence-recovery metrics
for the accepted disk, memory, and timeline investigations of the
authoritative `ptrace_fa` scenario.

Source notebooks:

- [memory investigation](./runme_memory_investigation.md) (primary source)
- [disk investigation](./runme_disk_investigation.md)
- [timeline investigation](./runme_timeline_investigation.md)

## Metric contract

The P01–P08 target inventory is fixed before this investigation began (task
specification, not a code artifact) and is reused unchanged here. Applicability
is fixed by source capability, not by tool success:

- filesystem: P01, P02, P03, P04;
- timeline: P01, P02, P03; and
- memory: P02, P05, P06, P07, P08.

The fixed definitions and formulae are in
[METHODOLOGY.md](../../../../METHODOLOGY.md). `O` means observed, `P`
partially observed, `N` not observed, `TF` tool failed, and `--` not
applicable. `U`, `C`, `S` mean unique, corroborated, and specialized
cross-source contribution; `X` counts contradictions separately. Scenario
validation defines the expected treatment but never counts as a forensic
locator. No target in this case is assigned `P`: every applicable source
either fully observed a target (`O`) or the target is out of that source's
declared scope (`--`); consequently the observed-only lower bound `O/A` is
identical to the reported `Found/A` for every source and is not shown
separately.

The Plaso timeline is generated from the same acquired disk image as the
filesystem examination, using the `filestat`, syslog, and journal parsers
(the run's `bash_history` parser produced zero events). Filesystem and
timeline are therefore separate source families for counting purposes but not
separate acquisitions: P01, P02, and P03 are corroborated by both through the
same underlying ext4 `filestat` structure, which is parser-level replication
— it excludes a TSK- or Plaso-specific tool defect, not a forged or misread
on-disk structure. Memory is the only independent acquisition; P02 is the one
target where memory's live-process observation is genuinely independent of
that shared disk structure.

None of the accepted `O` results in this case rest on ground-truth-guided
selection: every candidate (the staging tree, the victim/shell process chain,
the anonymous mapping, the decoded endpoint, the established socket) was
selected from generic operating-system structure or technique-level
examination before the manifest's `scenario_facts` were consulted, so no
sensitivity recomputation is required.

## Per-artifact evidence matrix

| ID | Phase/category | Expected artifact or fact | Filesystem | Timeline | Memory | Contribution | Principal method(s) | Accepted locator or limitation |
|---|---|---|---:|---:|---:|---:|---|---|
| P01 | Staging/build | Source/build tree staged in a writable temporary location | O | O | -- | C | TSK `ifind`/`fls -r`; Plaso `psort` | Disk D-01 `/tmp/forensic-lab/ptrace_fa`, inode `258110`, complete `src/`+`common/` tree; timeline T-03 `fs:stat` Creation Time on the same inodes. Parser-level replication between filesystem and timeline (same ext4 structure). |
| P02 | Staging/build | Compiled victim executable present at its staging path | O | O | O | C | TSK `ifind`/`istat`/`icat`; Plaso `psort`; Volatility 3 `linux.proc.Maps` | Disk D-02 inode `258159`, SHA-256 `951f93a6...060bebc`; timeline T-03 `fs:stat` same inode; memory M-04 maps the live victim process to the same path/inode — the one target with a genuinely independent (non-disk) corroborating source. |
| P03 | Staging/build | Compiled injector executable present at its staging path | O | O | -- | C | TSK `ifind`/`istat`/`icat`; Plaso `psort` | Disk D-03 inode `258148`, SHA-256 `9c6c8f4b...3572c8db`; timeline T-03 `fs:stat` same inode. Not memory-applicable: the injector process had already exited by acquisition. |
| P04 | Staging/build | Staged injector material implements ptrace-based process injection | O | -- | -- | S | TSK `icat`; `nm`/`readelf`/`grep` (static) | Disk D-04: injector imports `ptrace`/`waitpid`; recovered `ptrace_utils.c` (inode `258150`) implements `PTRACE_ATTACH`/`GETREGS`/`SETREGS`/`PEEKTEXT`/`POKETEXT`/`CONT`/`SINGLESTEP`/`DETACH`; recovered `shellcode_inject_fa.c` (inode `258158`) sets up a remote `__NR_mmap`. Static capability only; does not itself prove execution against the victim. |
| P05 | Runtime | Live victim process retains a child shell at acquisition | -- | -- | O | S | Volatility 3 `linux.pstree.PsTree`, `linux.pslist.PsList`, `linux.psscan.PsScan` | Memory M-01: PID `701` `victim` (UID `1000`) → PID `703` `sh`, created ~84 ms later; `psscan` additionally shows exited `id`/`ld` remnants parented by PID 703. |
| P06 | Runtime | Victim contains an anonymous executable mapping consistent with injected code | -- | -- | O | S | Volatility 3 `linux.malfind.Malfind`, `linux.proc.Maps` | Memory M-04/M-05: one `r-x` anonymous mapping at `0x7f5b5ae40000` in PID 701, agreed by both plugins. 3 of 4 `malfind` candidates across the whole image were reviewed and rejected (2 unrelated loader-adjacent false positives, 1 flagged-but-distinct `libc.so.6` dirty-page region). |
| P07 | Runtime | Injected memory content permits recovery of the configured reverse-shell endpoint | -- | -- | O | S | Volatility 3 `linux.malfind.Malfind` (hexdump/disasm); manual byte decode | Memory M-05: the injected region's own bytes (`c0 a8 64 01` / `11 5c`) decode to `192.168.100.1:4444`, independent of the live socket observation (P08) that shows the same endpoint. |
| P08 | Runtime | Child shell maintains an established TCP connection to that endpoint | -- | -- | O | S | Volatility 3 `linux.sockstat.Sockstat` | Memory M-03: PID 703 FDs 0–3 share one socket object `0x939787059180`, `192.168.100.41:43042` → `192.168.100.1:4444`, `ESTABLISHED`. Four descriptors, one connection. |

A ninth item, an active `linux.ptrace.Ptrace` tracer/tracee relationship, was
examined (memory M-06) and returned zero rows. Per the fixed pre-investigation
scope this is a bounded negative observation, not a metric target: the
injector's own recovered source calls `PTRACE_DETACH` on success, so a
zero result at acquisition is the expected outcome of a completed, detached
injection.

## Source metric summary

For source rows, `U/C/S` counts the classified targets to which that source
contributes. The union row reports the case-wide partition. `Union gain` is
shown only on the union row.

| Source | O | P | N | TF | Found / A | Coverage | U / C / S | X | Union gain | Rejected candidates | TTF | Principal methods |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| Filesystem | 4 | 0 | 0 | 0 | 4 / 4 | 100.0% | 0 / 3 / 1 | 0 | -- | N/A | 43s | TSK 4.15.0 (`ifind`, `fls`, `istat`, `icat`); `nm`/`readelf` |
| Timeline | 3 | 0 | 0 | 0 | 3 / 3 | 100.0% | 0 / 3 / 0 | 0 | -- | N/A | 80s | Plaso 20260512 `psort` |
| Memory | 5 | 0 | 0 | 0 | 5 / 5 | 100.0% | 0 / 1 / 4 | 0 | -- | 3 | not measured | Volatility 3 2.28.0 |
| Union | 8 | 0 | 0 | 0 | 8 / 8 | 100.0% | 0 / 3 / 5 | 0 | +3 (P01, P03, P04) | FS N/A; TL N/A; Mem 3; union 3 case-wide | FS 43s; TL 80s; Mem not measured | TSK + Plaso + Volatility 3 |

The category-level union results are staging/build `4 / 4` (100.0%) and
runtime `4 / 4` (100.0%): both phases of this scenario are fully exposed
within the fixed inventory's bounds. This is a smaller, deliberately bounded
inventory (8 targets) than the Father cleanup case (14), consistent with a
technique-led runtime-injection scenario that leaves comparatively little
static persistence for filesystem/timeline to describe.

Every source's `Found` equals its `O` count (no `P` occurs anywhere in this
matrix), so the observed-only lower bound is numerically identical to the
reported coverage for every row and is not restated separately.

The `+3` union gain (P01, P03, P04) is entirely composed of targets **outside
memory's applicability set** (memory is the strongest single source by count,
`Found = 5`): the injector executable had already exited by acquisition
(P03), and P01/P04 describe staged/static material that memory does not
apply to at all. This is the weaker form of union gain the methodology
distinguishes: it demonstrates complementary source coverage (each source
answers a different phase of the scenario), not that combining sources
recovered a target an applicable source had already tried for and missed. No
target in this case is applicable to two-or-more source families where those
families disagreed or one missed what another found — the three
multi-source-applicable targets (P01, P02, P03) were found by every source
applicable to them, hence `U = 0` case-wide.

Memory's candidate-generating method (`malfind`) produced 4 candidates
case-wide; 1 was accepted (the injected region in PID 701) and 3 were
rejected (2 unrelated loader-adjacent processes, 1 flagged-but-distinct
`libc.so.6` region in the same victim process). Filesystem and timeline used
direct, targeted resolution rather than a candidate-generating search, so
their rejected-candidate counts are `N/A`, not `0`.

TTF was recorded prospectively in
[`shared/investigations/ubuntu-22.04_ptrace_fa_20260807-150736/investigation_command_log.txt`](../../../../shared/investigations/ubuntu-22.04_ptrace_fa_20260807-150736/investigation_command_log.txt),
by a single analyst not blind to the treatment, in the disclosed order
**memory, then filesystem, then timeline**. Filesystem (`43s`, to P01/P02/P03
in one `fls -r` listing) and timeline (`80s`, to the same three targets in one
`psort` export) were both recorded immediately after their first accepted
result. Memory's `TTF-FIRST` marker was written only after several further
plugin invocations beyond the first (`pstree`) that actually produced the
first accepted target (P05); because that marker was not recorded
immediately, it does not reflect a genuine time-to-first-locator, and memory
`TTF` is reported as **not measured** per the methodology's rule against
reconstructing an unreliable timestamp. The raw log line is retained
unmodified (append-only) for audit.

## Cross-source conclusion

Filesystem and timeline together fully describe the scenario's staging/build
phase (P01–P03, plus filesystem-only static ptrace capability in P04) by
reading the same acquired disk through two different tools — corroboration
that rules out a tool-specific misread but not a forged or altered on-disk
structure. Memory independently corroborates the compiled victim executable's
identity (P02) and is the only source for the scenario's actual runtime
behavior: the victim's live child shell (P05), the injected anonymous
executable mapping (P06), the endpoint recovered directly from that injected
code (P07), and the established connection from the shell to that same
endpoint (P08).

No materially contradictory accepted observation was recorded (`X = 0`). The
scenario's static build artifacts and its runtime injection behavior are
complementary rather than overlapping: disk and timeline show that the
material to perform ptrace-based injection was staged and built, while only
memory shows that the injection produced a running anonymous code region, a
recoverable endpoint, and a live connection matching it. This asymmetry —
`U = 0`, `C = 3`, `S = 5` — is a property of a technique-led runtime scenario
with minimal persistence, not a metric weakness: this case does not claim a
disk- or timeline-side artifact for behavior that only exists in the live
process image.
