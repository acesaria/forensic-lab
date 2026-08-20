---
cwd: ../../../..
shell: bash
---

# ptrace_fa case summary and metrics

__Run:__ `ubuntu-22.04_ptrace_fa_20260813-173337`

**Scope:** cross-source interpretation and manual evidence-recovery metrics
for the prepared-binary `ptrace_fa` treatment on Ubuntu 22.04.

Source notebooks:

- [memory investigation](./runme_memory_investigation.md) (primary source)
- [disk investigation](./runme_disk_investigation.md)
- [timeline investigation](./runme_timeline_investigation.md)

## Acceptance and provenance limitation

Scenario, run, memory acquisition, disk acquisition, and EWF verification all
completed. The copied `shellcode_inject_fa`, `victim`, and `build.json` are
byte-identical to the prepared input and match the manifest hashes. The VM was
off after acquisition.

The manifest records
`aef7d0015bbcd1a87f051e16f4fe722f73507993-dirty`, not a clean revision.
The human explicitly waived the clean-tree gate because unrelated eBPF work was
in progress in parallel. The ptrace implementation itself was committed at
`aef7d00` before execution, but Git cannot identify the unrelated dirty bytes
from the manifest alone. This run is accepted only under that disclosed
deadline exception; it is weaker provenance than a clean authoritative run.

## Metric contract

The established P01-P08 inventory is retained but its staging language follows
the current prepared-binary executor:

- filesystem: P01-P04;
- timeline: P01-P03; and
- memory: P02 and P05-P08.

`O`, `P`, `N`, `TF`, applicability, coverage, contribution, contradiction,
candidate, and timing rules are those in
[METHODOLOGY.md](../../../../ai/archive/METHODOLOGY.md). Filesystem and timeline both read
the acquired disk, so P01-P03 corroboration between TSK and Plaso is
parser-level replication, not an independent acquisition. Memory independently
corroborates P02 and is the only applicable source for P05-P08.

Candidate selection began from generic structures: a shell with an unusual
parent, an executable anonymous mapping, `/tmp` filesystem structure, and a
bounded location timeline. Manifest facts were consulted only afterwards for
labelled validation. No accepted result rests on ground-truth-guided recovery.

## Per-artifact evidence matrix

| ID | Phase/category | Expected artifact or fact | Filesystem | Timeline | Memory | Contribution | Principal method(s) | Accepted locator or limitation |
|---|---|---:|---:|---:|---:|---:|---|---|
| P01 | Runtime staging | Prepared-binary staging tree in writable temporary storage | O | O | -- | C | TSK `ifind`/`fls`; Plaso `psort` | Disk D-01 `/tmp/forensic-lab/ptrace_fa`, inode `258129`, contains injector, victim, and `victim.log`; timeline T-03 shows those files plus the two upload-stage files. No source/build tree is expected under the current executor. |
| P02 | Runtime staging | Victim executable present at its runtime path | O | O | O | C | TSK `istat`/`icat`; Plaso `psort`; Volatility `linux.proc.Maps` | Disk inode `258131`, SHA-256 `951f93a6...060bebc`; timeline same inode; memory maps PID 1042 to the same path and inode. |
| P03 | Runtime staging | Injector executable present at its runtime path | O | O | -- | C | TSK `istat`/`icat`; Plaso `psort` | Disk inode `258130`, SHA-256 `9c6c8f4b...3572c8db`; timeline same inode. `psscan` retains exited PID 1043 as contextual memory evidence, but P03 remains outside memory applicability. |
| P04 | Static capability | Prepared injector implements ptrace/foreign-allocation injection capability | O | -- | -- | S | TSK `icat`; `nm`/`strings` | Recovered injector imports `ptrace`/`waitpid` and retains attach, detach, register-control, continuation, `mmap`, and injected-shellcode symbols/messages. Static capability only; runtime behavior is P05-P08. |
| P05 | Runtime | Live victim retains a child shell at acquisition | -- | -- | O | S | Volatility `pstree`, `pslist`, `psscan` | Memory M-01: PID 1042 `victim` -> PID 1044 `sh`, same UID/GID 1000, created about 22 ms apart. |
| P06 | Runtime | Victim contains an anonymous executable mapping consistent with injected code | -- | -- | O | S | Volatility `linux.proc.Maps`, `linux.malfind` | PID 1042 has one accepted anonymous `r-x` mapping at `0x7f3f67547000`; three other `malfind` candidates were rejected. |
| P07 | Runtime | Injected bytes permit recovery of the reverse-shell endpoint | -- | -- | O | S | Volatility `linux.malfind`; bounded byte decode | Bytes `c0 a8 64 01` / `11 5c` decode to `192.168.100.1:4444`. |
| P08 | Runtime | Child shell maintains an established connection to that endpoint | -- | -- | O | S | Volatility `linux.sockstat` | PID 1044 FDs 0-3 share socket `0x8b7cc444d780`, `192.168.100.32:38876` -> `192.168.100.1:4444`, `ESTABLISHED`. |

`linux.ptrace` returned zero active relationships. This is an expected bounded
negative after injector detachment, not a ninth target and not evidence that
injection failed.

## Source metric summary

| Source | O | P | N | TF | Found / A | Coverage | U / C / S | X | Union gain | Rejected candidates | TTF | Principal methods |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| Filesystem | 4 | 0 | 0 | 0 | 4 / 4 | 100.0% | 0 / 3 / 1 | 0 | -- | N/A | 21s | TSK 4.15.0; `nm`, `strings` |
| Timeline | 3 | 0 | 0 | 0 | 3 / 3 | 100.0% | 0 / 3 / 0 | 0 | -- | N/A | 122s | Plaso 20260512 `log2timeline`/`psort` |
| Memory | 5 | 0 | 0 | 0 | 5 / 5 | 100.0% | 0 / 1 / 4 | 0 | -- | 3 | 55s | Volatility 3 2.28.0 |
| Union | 8 | 0 | 0 | 0 | 8 / 8 | 100.0% | 0 / 3 / 5 | 0 | +3 (P01, P03, P04) | FS N/A; TL N/A; Mem 3; union 3 | FS 21s; TL 122s; Mem 55s | TSK + Plaso + Volatility 3 |

TTF was recorded prospectively in
`shared/investigations/ubuntu-22.04_ptrace_fa_20260813-173337/investigation_command_log.txt`
in the order memory, filesystem, timeline. The timeline duration includes two
failed pre-extraction Plaso attempts: one omitted partition selection and one
used an identifier the installed dfVFS rejected. The successful invocation used
`--partitions all` with the same bounded Linux filter. Because later accepted
methods succeeded, the applicable targets remain `O`; the secondary tool
failures are retained rather than converted into target-level `TF` statuses.

The `+3` union gain is composed entirely of targets outside memory's
applicability set, so it demonstrates complementary phase coverage rather than
recovery of targets memory attempted and missed. The three multi-source targets
P01-P03 were found by every applicable source; `X = 0`.

## Cross-source conclusion

Filesystem and timeline expose the prepared runtime staging phase. Memory
independently corroborates the victim executable and supplies the behavioral
evidence: the victim-to-shell relationship, executable anonymous mapping,
decoded endpoint, and matching established connection. The static and runtime
sources complement one another without a materially contradictory accepted
observation.

The treatment is fully observed within this fixed eight-target scope. The
conclusion remains explicitly limited by the dirty-revision exception, a
single point-in-time RAM image, correlated `Maps`/`malfind` VMA semantics, and
two recoverable Plaso setup failures.
