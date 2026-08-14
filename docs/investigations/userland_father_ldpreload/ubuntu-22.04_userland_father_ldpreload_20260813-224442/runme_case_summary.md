---
cwd: ../../../..
shell: bash
---

# Father case summary and metrics

__Run:__ `ubuntu-22.04_userland_father_ldpreload_20260813-224442`

**Scope:** cross-source interpretation and manual evidence-recovery metrics for
the accepted disk and memory investigations of the base (non-cleanup)
`userland_father_ldpreload` scenario. This is the thesis Chapter 5 exemplar
case.

Source notebooks:

- [disk investigation](./runme_disk_investigation.md)
- [memory investigation](./runme_memory_investigation.md)

## Case identity and integrity

| Field | Value |
|---|---|
| Run ID | `ubuntu-22.04_userland_father_ldpreload_20260813-224442` |
| Repository revision | `2e5dadcc4c952261cb2fa6a7b54548d8bd607eb6` |
| Platform | Ubuntu 22.04.5 LTS, kernel `5.15.0-179-generic`, `vanilla`, UTC guest |
| Scenario interval | `2026-08-13T20:44:42.511Z` – `20:44:43.875Z` |
| Memory image | `dumps/memory/mem.raw`, SHA-256 `4d370432…dab04` (verified) |
| Disk image | EWF `dumps/disk/evidence_disk.E01/.E02`, SHA-256 `f12d21e3…159ad4`; `ewfverify 20240506` exit 0 at acquisition |
| Installed library | `/usr/lib/selinux.so.3` SHA-256 `87fece49…0711` = manifest input `rk.so` |

Examination is read-only on the immutable evidence. The memory image hash was
re-verified against the acquisition sidecar before analysis.

## Metric contract

The M01–M11 target inventory is the pre-registered Father inventory (commit
`011db22`, 2026-07-24), reused unchanged; this base run does not use the
C01–C03 cleanup extension. Applicability is fixed by source capability before
examination:

- filesystem: M01–M08;
- log timeline: M05, M08, M11; and
- memory: M05, M08, M09, M10.

**Timeline scope for this run.** A full Plaso timeline was not regenerated for
this exact run. The temporal ("TL") column is bounded system-log context
(`auth.log`, `syslog`) read read-only from the same acquired disk image inside
the disk notebook. Filesystem and log-timeline are therefore separate views for
counting but **not** separate acquisitions; where both rest on the same ext4
structure their agreement is same-acquisition replication, not independent
evidence. Memory is the only independent acquisition. This scoping is a
declared limitation of this case, not a metric defect.

Status codes follow `METHODOLOGY.md`: `O` observed, `P` partially observed, `N`
not observed within the stated bound, `TF` tool failed, `--` not applicable.
`U`/`C`/`S` are unique/corroborated/specialized; `X` counts contradictions.
Scenario facts define the expected treatment and never count as a forensic
locator.

## Per-artifact evidence matrix

| ID | Phase/category | Expected artifact or fact | Filesystem | Timeline | Memory | Contribution | Principal method(s) | Accepted locator or limitation |
|---|---|---|---:|---:|---:|---:|---|---|
| M01 | Staging/build | Source archive staged | N | -- | -- | -- | TSK `fls` | Staging removed by scenario; not exposed under `/tmp` within bounds; unallocated recovery not pursued. |
| M02 | Staging/build | Build tree extracted | N | -- | -- | -- | TSK `fls` | Not present on the live filesystem; unallocated/journal recovery out of this case's bound. |
| M03 | Staging/build | Modified `config.h` | N | -- | -- | -- | TSK `fls`/`blkls` | Not recovered within bounds. |
| M04 | Staging/build | `rk.so` built | N | -- | -- | -- | TSK `fls` | Installed copy survives (M05); the build event is not independently dated. |
| M05 | Persistence/activation | Library installed and mapped | O | O | O | C | TSK `ifind`/`istat`/`icat`; on-disk `auth.log`; Vol3 `proc.Maps` | FS inode `74172`, 32,784 B, SHA-256 `87fece49…0711` = manifest `rk.so`; TL `sudo`/`sshd` restart at `20:44:43Z`; Mem five-segment mapping of inode `74172` in PID 1054/1056. |
| M06 | Persistence/activation | `/etc/ld.so.preload` configured | O | -- | -- | S | TSK `istat`/`icat` | FS inode `74210`, content `/lib/selinux.so.3` (resolves via `/lib`→`/usr/lib` symlink). |
| M07 | Persistence/activation | Concealable file created | O | -- | -- | S | TSK `fls`/`istat` | FS `/tmp/__malicious_file` inode `74173`, visible offline though the `readdir` hook would hide it live. Filename matches the disclosed `__malicious_` prefix (ground-truth-informed name). |
| M08 | Persistence/activation | Interactive command activity | P | N | N | U | TSK `fls`/ext4 journal; `auth.log`; Vol3 `bash` | FS bash-history text in the home-directory journal without `#<epoch>` time lines; TL `auth.log` records only privileged `sudo` invocations; Mem `linux.bash` returned 0 rows. |
| M09 | Runtime | Privileged shell parented by `sshd` | -- | -- | O | S | Vol3 `pslist`/`pstree`/`psaux` | Mem PID 1054 `sshd` → PID 1056 `sh`, UID/EUID 0, GID/EGID 1337. |
| M10 | Runtime | Established backdoor connection | -- | -- | O | S | Vol3 `sockstat` | Mem socket `0x8b3849b03480`, `192.168.100.32:22` ↔ `192.168.100.1:54321`, shared by PID 1054 (FD 5) and PID 1056 (FDs 0/1/2/5); one connection. |
| M11 | Persistence/activation | SSH restart during activation | -- | O | -- | S | on-disk `auth.log` | TL `auth.log`: PID 655 `Received signal 15`, PID 1054 `Server listening … port 22` at `20:44:43Z`. |

## Source metric summary

Source rows count the classified targets to which that source contributes; the
union row carries the case-wide partition. `Union gain` is on the union row.

| Source | O | P | N | TF | Found / A | Coverage | U / C / S | X | Union gain | Rejected candidates | TTF | Principal methods |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|
| Filesystem | 3 | 1 | 4 | 0 | 4 / 8 | 50.0% | 1 / 1 / 2 | 0 | -- | 0 | not measured | TSK 4.15.0 (`fls`,`ifind`,`istat`,`icat`,`fsstat`) |
| Timeline (log) | 2 | 0 | 1 | 0 | 2 / 3 | 66.7% | 0 / 1 / 1 | 0 | -- | N/A | not measured | on-disk `auth.log`/`syslog` (no Plaso store) |
| Memory | 3 | 0 | 1 | 0 | 3 / 4 | 75.0% | 0 / 1 / 2 | 0 | -- | 0 | not measured | Volatility 3 2.28.0 (`proc.Maps`,`pslist`,`pstree`,`psaux`,`sockstat`,`bash`) |
| Union | 6 | 1 | 4 | 0 | 7 / 11 | 63.6% | 1 / 1 / 5 | 0 | +3 (M09, M10, M11) | 0 case-wide | not measured | TSK + on-disk logs + Volatility 3 |

Category-level union results: staging/build `0 / 4` (0.0%),
persistence/activation `4 / 5` (80.0%; three observed plus one partial, M08),
runtime `2 / 2` (100.0%).

**Robustness readings.** Counting only `O`, the observed-only lower bound is
filesystem `3 / 8` (37.5%), timeline `2 / 3` (66.7%), memory `3 / 4` (75.0%),
union `6 / 11` (54.5%). No accepted `O`/`P` in this run rests on
ground-truth-guided *recovery*; the only ground-truth touch point is the M07
filename match, which validates a name after technique-led discovery of the
file and does not change any status.

**Union gain is source-exclusive.** The `+3` gain over the strongest single
source by count (filesystem, 4) comprises M09, M10, and M11 — all outside
filesystem applicability. It records that the inventory contains memory- and
log-exclusive targets, not that combining sources recovered a target an
applicable source missed. The one target found by exactly one of several
applicable sources is M08 (filesystem partial; log and memory applicable and
not found), classed `U`.

**Rejected candidates.** Technique-led selection (the anomalous `selinux.so.3`
mapping in `proc.Maps`) produced the accepted `sshd`→`sh` chain with no rejected
candidate within the bounded examination. `malfind` was not used as a
candidate-generating method for this run.

## Cross-source conclusion

Disk evidence establishes persistence: the preload configuration (M06), the
exact identity of the installed library by hash equality with the built object
(M05), its statically read concealment/backdoor capability, and a concealable
file that survives offline (M07). Log context dates the activation mechanism —
the privileged SSH restart that loads the library (M11) and brackets the
install (M05). Memory establishes runtime effect: the same library inode mapped
in the restarted `sshd` (M05), a root child shell (M09), and one established
backdoor connection (M10).

The combination adds information in two distinct ways. For M05 the disk↔memory
inode-`74172` coincidence is corroboration across different artifact classes and
across the one independent acquisition (memory), excluding both single-tool
error and a disk-only artifact with no runtime effect. For M09/M10/M11 the
non-filesystem sources instead *expose* targets no cold source could reach; that
union gain reflects source-exclusive targets rather than a recovery an applicable
source missed. Keeping this distinction explicit is the methodological point of
the case. No materially contradictory accepted observation was recorded (`X` 0).

Declared limitations: build staging is not recovered within the bounded methods
(M01–M04 negative); command history preserves text but not per-command times
(M08 partial/negative across sources); static ELF inspection proves capability,
not hook execution; no memory mapping was hashed, so library identity is
disk-derived only; and the temporal column is bounded log context sharing the
disk acquisition, not an independent Plaso timeline.
