---
cwd: ../../../..
shell: bash
---

# Father cleanup case summary and metrics

__Run:__ `ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919`

**Scope:** cross-source interpretation and manual evidence-recovery metrics for
the accepted disk, memory, and timeline investigations.

Source notebooks:

- [disk investigation](./runme_disk_investigation.md)
- [memory investigation](./runme_memory_investigation.md)
- [timeline investigation](./runme_timeline_investigation.md)

## Metric contract

The M01–M11/C01–C03 inventory was documented before this authoritative run and
is reused unchanged. The pre-registration is auditable in Git history: the
M01–M11 targets appear in commit `011db22` (2026-07-24) and the C01–C03 cleanup
extension in `692ecdd` (2026-07-27), both predating this run of 2026-08-05.
Applicability is fixed by source capability rather than by tool success:

- filesystem: M01–M08 and C01–C03;
- timeline: M01–M08, M11, and C01–C03; and
- memory: M05, M09, and M10.

The fixed definitions and formulae are in
[METHODOLOGY.md](../../../../METHODOLOGY.md). In the tables below, `O` means
observed, `P` partially observed, `N` not observed, `TF` tool failed, and `--`
not applicable. `U`, `C`, and `S` mean unique, corroborated, and specialized
cross-source contribution; `X` counts contradictions separately. Scenario
validation defines the expected treatment but never counts as a forensic
locator.

The inventory and applicability are not changed after seeing the results merely
to improve coverage.

The Plaso timeline is generated from the same acquired disk image as the
filesystem examination, using the `filestat`, syslog, journal, and
`bash_history` parsers. Filesystem and timeline are therefore separate source
families for counting purposes but not separate acquisitions. Where both rest
on the same ext4 inode structure their agreement is parser-level replication,
which excludes tool error but not a forged or misread structure; where the
timeline instead contributes a journal or syslog record, the two supports are
different artifact classes. The matrix states which applies per target. Memory
is the only independent acquisition.

## Per-artifact evidence matrix

| ID | Phase/category | Expected artifact or fact | Filesystem | Timeline | Memory | Contribution | Principal method(s) | Accepted locator or limitation |
|---|---|---|---:|---:|---:|---:|---|---|
| M01 | Staging/build | Source archive staged | N | N | -- | -- | TSK `fls -d`; ext4magic; PhotoRec; Plaso `psort` | Disk D-02/D-05 and timeline T-05 did not recover or expose it within their bounds. |
| M02 | Staging/build | Source/build tree extracted | P | O | -- | C | TSK `blkls`/`blkcalc`/`blkcat`; Plaso `psort` | Disk D-04 recovers a `config.h` content candidate at unallocated block `589864` without pathname/inode; timeline T-04 preserves the `Father-4eb2712...` working directory. |
| M03 | Staging/build | Modified `config.h` applied | O | N | -- | U | TSK `blkls`/`blkcalc`/`blkcat` | Disk D-04 recovers the complete 740-byte boundary-delimited candidate, SHA-256 `d14ebf96...120ad4`; this is ground-truth-guided recovery. |
| M04 | Staging/build | `rk.so` built | N | N | -- | -- | TSK `fls`; ext4magic; Plaso `psort` | The installed library survives, but the bounded methods do not independently recover or time the build output. |
| M05 | Persistence/activation | Library installed and mapped | O | O | O | C | TSK `ifind`/`istat`/`icat`; Plaso `psort`; Volatility 3 `LibraryList`, `Elfs`, `Files`, `InodePages` | Disk D-01 inode `62345`; timeline T-03/T-04 `fs:stat` plus sudo install record; memory M-04 mappings and cached-file recovery for the same inode. |
| M06 | Persistence/activation | `/etc/ld.so.preload` configured | O | O | -- | C | TSK `ifind`/`istat`/`icat`; Plaso `psort` | Disk D-01 inode `61596`; timeline T-03/T-04 `fs:stat` plus sudo `tee` record. The later inode timestamp does not date the explicit invocation. |
| M07 | Persistence/activation | Controlled hidden file created | O | O | -- | C | TSK `fls`/`istat`; Plaso `psort` | Disk D-01 and timeline T-03 identify probe inode `260193`. Both read the same ext4 inode structure, so this is the one corroborated target supported by parser-level replication rather than by two artifact classes. Memory M-06 supplies additional path/inode context outside the fixed denominator. |
| M08 | Persistence/activation | Interactive command activity | N | P | -- | U | TSK `fls`; ext4magic; Plaso `psort` | Timeline T-04 records only the three privileged sudo invocations; Bash-history parsing produced no event data type. |
| M09 | Runtime | Privileged shell parented by `sshd` | -- | -- | O | S | Volatility 3 `PsList`, `PsScan`, `PsTree`, `PsAux` | Memory M-01/M-02: PID `877` `sshd` to PID `879` root `sh`, GID/EGID `1337`. |
| M10 | Runtime | Established backdoor connection | -- | -- | O | S | Volatility 3 `Sockstat` | Memory M-03: one established `192.168.100.41:22` to `192.168.100.1:54321` socket shared by the selected processes. |
| M11 | Persistence/activation | SSH restart during activation | -- | O | -- | S | Plaso `psort` | Timeline T-04 records the `ssh.service` stop/start lifecycle. |
| C01 | Cleanup event | Archive cleanup | N | N | -- | -- | TSK `fls`; ext4magic; PhotoRec; Plaso `psort` | Cleanup-command success is scenario validation; no forensic locator proves the cleanup event. |
| C02 | Cleanup event | Source/build-tree cleanup | N | N | -- | -- | TSK `fls`/`blkcat`; ext4magic; Plaso `psort` | Unallocated content and parent-directory change are compatible with cleanup but do not prove a deletion event. |
| C03 | Cleanup event | Bash-history cleanup | N | N | -- | -- | TSK `fls`; ext4magic; Plaso `psort` | Cleanup-command success is scenario validation; bounded disk and timeline methods did not recover history evidence. |

## Source metric summary

For source rows, `U/C/S` counts the classified targets to which that source
contributes. The union row reports the case-wide partition. `Union gain` is
shown only on the union row.

| Source | O | P | N | TF | Found / A | Coverage | U / C / S | X | Union gain | Rejected candidates | TTF | Principal methods |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|
| Filesystem | 4 | 1 | 6 | 0 | 5 / 11 | 45.5% | 1 / 4 / 0 | 0 | -- | 0 | not measured | TSK; ext4magic 0.3.2; PhotoRec |
| Timeline | 5 | 1 | 6 | 0 | 6 / 12 | 50.0% | 1 / 4 / 1 | 0 | -- | N/A | not measured | Plaso 20260512 `psort` |
| Memory | 3 | 0 | 0 | 0 | 3 / 3 | 100.0% | 0 / 1 / 2 | 0 | -- | 2 | not measured | Volatility 3 2.28.0 |
| Union | 8 | 1 | 5 | 0 | 9 / 14 | 64.3% | 2 / 4 / 3 | 0 | +3 (M03, M09, M10) | 2 case-wide | not measured | TSK + Plaso + Volatility 3 |

The category-level union results are staging/build `2 / 4` (50.0%),
persistence/activation `5 / 5` (100.0%; four observed and one partial), runtime
`2 / 2` (100.0%), and cleanup-event evidence `0 / 3` (0.0%). The result is not
evidence that the controlled treatment was poorly executed: the lower union
coverage records incomplete staging/build recovery and the absence of a direct
forensic cleanup event under the bounded methods.

Two robustness readings accompany the headline numbers. Counting only `O`, the
observed-only lower bound is filesystem `4 / 11` (36.4%), timeline `5 / 12`
(41.7%), memory `3 / 3` (100.0%), and union `8 / 14` (57.1%); this recomputable
bound is why `P` needs no fractional weight. Separately, M03 rests on
ground-truth-guided recovery (disk D-04) rather than technique-led discovery,
and discounting it gives filesystem `4 / 11` (36.4%), union `8 / 14` (57.1%),
union gain `+2`, and `U / C / S` of `1 / 4 / 3`. The two adjustments coincide
numerically because each removes exactly one found target; they are not the
same adjustment.

The `+3` union gain is also not homogeneous. Measured against the strongest
single source by count (timeline, `6`), M03 is a target the timeline was
applicable to and did not find, whereas M09 and M10 fall outside the timeline's
applicability altogether. Only the first is evidence that combining sources
recovered something an applicable source missed; the other two record that the
inventory contains memory-exclusive targets.

Filesystem candidate generation returned one accepted `config.h` candidate and
no rejected candidate. The timeline used targeted bounded selections rather
than a candidate-generating method. The two memory candidates are the
loader-adjacent `malfind` regions excluded from the selected Father chain; they
are not proven benign. TTF was not measured prospectively and is therefore not
reconstructed from scenario or evidence timestamps.

## Cross-source conclusion

Timeline evidence records the privileged install, preload configuration, and
SSH restart. Disk evidence preserves the resulting preload configuration,
installed ELF, retained probe path, and one ground-truth-guided unallocated
`config.h` candidate. Memory preserves the mapped library, privileged child
shell, and established backdoor connection at acquisition time.

Combining the sources exposes three more targets than the strongest single
source by count. Four found targets were found by two or more applicable source
families. Of those, M02, M05, and M06 rest on different artifact classes —
unallocated block content or inode metadata alongside a `sudo` journal record —
and M05 additionally on the independent memory acquisition, so their
corroboration is evidentiary; M07 is parser-level replication of a single inode
structure and is the weaker case. Two targets are unique contributions where
another source was applicable but did not find the target, and three are
specialized findings whose only applicable source found them. No materially
contradictory accepted observation was recorded.

No forensic source directly records the three cleanup operations. Their command
success remains scenario validation; the bounded recovery failures are
source-scoped negative findings. This separation is the principal result of the
cleanup case, not a metric defect.
