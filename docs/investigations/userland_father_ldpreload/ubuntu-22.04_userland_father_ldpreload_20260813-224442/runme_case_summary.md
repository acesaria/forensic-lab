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
- [timeline investigation](./runme_timeline_investigation.md)

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
C01–C03 cleanup extension. Applicability is fixed by source capability and by
scenario design before examination:

- filesystem: M05–M08;
- log timeline: M05, M08, M11; and
- memory: M05, M08, M09, M10.

**Why M01–M04 are not applicable to this run.** The inventory was frozen when
Father was compiled on the victim, so the four staging/build targets described
events that then happened on the acquired host. Under the current prebuilt-
artifact design they do not. `scenarios/userland_father_ldpreload/runner.py`
confines archive upload, extraction, the `config.h` edit and `make` to `build()`
on a separate builder VM (`_BUILDER_ARCHIVE`, `_BUILDER_SCRIPT`,
`_BUILDER_BUILD_ROOT`, and `files/build.sh`). The victim receives exactly one
object — the finished `rk.so` uploaded to `/tmp/rk.so` — so no source archive,
build tree, modified `config.h`, or compilation event ever exists on the
acquired image. Per `METHODOLOGY.md` these are `--` (not applicable), not `N`:
the sources cannot answer a question the treatment never posed to them. They
therefore leave the denominators, and this case's coverage figures are **not**
comparable with the earlier calibration or cleanup Father runs, whose
inventories did include a victim-side build.

**Timeline scope for this run.** The timeline notebook examines a curated Plaso
20260512 store (`derived/timeline/timeline.plaso`, SHA-256
`682dd82a…18d0b`, 16,483 events) and an unfiltered control (`father.plaso`,
310,316 events). Filesystem and timeline remain separate views for counting but
are **not** separate acquisitions: both read the same acquired disk image, so
`filestat` agreement with TSK is parser-level replication. The independently
acquired memory image is compared separately, without treating unlike time
bases as directly commensurable.

Status codes follow `METHODOLOGY.md`: `O` observed, `P` partially observed, `N`
not observed within the stated bound, `TF` tool failed, `--` not applicable.
`U`/`C`/`S` are unique/corroborated/specialized; `X` counts contradictions.
Scenario facts define the expected treatment and never count as a forensic
locator.

## Per-artifact evidence matrix

| ID | Phase/category | Expected artifact or fact | Filesystem | Timeline | Memory | Contribution | Principal method(s) | Accepted locator or limitation |
|---|---|---|---:|---:|---:|---:|---|---|
| M01 | Staging/build | Source archive staged | -- | -- | -- | -- | -- | Not applicable: `father-upstream-4eb2712.tar` is uploaded only to the builder VM (`_BUILDER_ARCHIVE`); it never reaches the acquired host. |
| M02 | Staging/build | Build tree extracted | -- | -- | -- | -- | -- | Not applicable: `files/build.sh` extracts under `_BUILDER_BUILD_ROOT` on the builder VM; no build tree exists on the acquired host. |
| M03 | Staging/build | Modified `config.h` | -- | -- | -- | -- | -- | Not applicable: the `STRING` edit is applied by `files/build.sh` on the builder VM; no `config.h` exists on the acquired host. |
| M04 | Staging/build | `rk.so` built | -- | -- | -- | -- | -- | Not applicable: `make father` runs on the builder VM. The victim receives the finished object by upload, so no compilation event exists on the acquired host; the installed copy is M05. |
| M05 | Persistence/activation | Library installed and mapped | O | P | O | C | TSK `ifind`/`istat`/`icat`; Plaso `filestat`/`systemd_journal`; Vol3 `proc.Maps` | FS inode `74172`, 32,784 B, SHA-256 `87fece49…0711` = manifest `rk.so`; TL install PID 1040 at `20:44:43.374899` and inode-74172 crtime `20:44:43.372000`, but no in-RAM mapping; Mem five-segment mapping of inode `74172` in PID 1054/1056. |
| M06 | Persistence/activation | `/etc/ld.so.preload` configured | O | -- | -- | S | TSK `istat`/`icat` | FS inode `74210`, content `/lib/selinux.so.3` (resolves via `/lib`→`/usr/lib` symlink). Timeline context: its MAC time `20:44:46.472` postdates the journal `tee` command (`20:44:43.429`) by about 3 s, so MAC time alone mis-orders configuration. |
| M07 | Persistence/activation | Concealable file created | O | -- | -- | S | TSK `fls`/`istat` | FS `/tmp/__malicious_file` inode `74173`, visible offline though the `readdir` hook would hide it live. Filename matches the disclosed `__malicious_` prefix (ground-truth-informed name). |
| M08 | Persistence/activation | Interactive command activity | P | N | N | U | TSK `fls`/ext4 journal; Plaso `bash_history`/system logs; Vol3 `bash` | FS bash-history text in the home-directory journal without `#<epoch>` time lines; TL `bash:history:entry` produced 0 events and system logs expose only privileged `sudo` invocations; Mem `linux.bash` returned 0 rows. |
| M09 | Runtime | Privileged shell parented by `sshd` | -- | -- | O | S | Vol3 `pslist`/`pstree`/`psaux` | Mem PID 1054 `sshd` → PID 1056 `sh`, UID/EUID 0, GID/EGID 1337. |
| M10 | Runtime | Established backdoor connection | -- | -- | O | S | Vol3 `sockstat` | Mem socket `0x8b3849b03480`, `192.168.100.32:22` ↔ `192.168.100.1:54321`, shared by PID 1054 (FD 5) and PID 1056 (FDs 0/1/2/5); one connection. |
| M11 | Persistence/activation | SSH restart during activation | -- | O | -- | S | Plaso `systemd_journal`/`utmp` | TL journal: restart PID 1049 at `20:44:43.453084`, PID 655 `SIGTERM` at `.464985`, PID 1054 listening at `.488536`; `utmp` brackets the `pts/0` session from `20:44:42.856282` to `20:44:43.823745`. |

## Source metric summary

Source rows count the classified targets to which that source contributes; the
union row carries the case-wide partition. `Union gain` is on the union row.

| Source | O | P | N | TF | Found / A | Coverage | U / C / S | X | Union gain | Rejected candidates | TTF | Principal methods |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|
| Filesystem | 3 | 1 | 0 | 0 | 4 / 4 | 100.0% | 1 / 1 / 2 | 0 | -- | 0 | not measured | TSK 4.15.0 (`mmls`,`fsstat`,`fls`,`ifind`,`istat`,`icat`) |
| Timeline | 1 | 1 | 1 | 0 | 2 / 3 | 66.7% | 0 / 1 / 1 | 0 | -- | N/A | not measured | Plaso 20260512 curated `timeline.plaso` (`filestat`,`syslog_traditional`,`systemd_journal`,`utmp`; `bash_history` enabled, 0 events) plus unfiltered control; bounded `psort` filters |
| Memory | 3 | 0 | 1 | 0 | 3 / 4 | 75.0% | 0 / 1 / 2 | 0 | -- | 0 | not measured | Volatility 3 2.28.0 (`proc.Maps`,`pslist`,`pstree`,`psaux`,`sockstat`,`bash`,`timeliner.Timeliner`) |
| Union | 6 | 1 | 0 | 0 | 7 / 7 | 100.0% | 1 / 1 / 5 | 0 | +3 (M09, M10, M11) | 0 case-wide | not measured | TSK + Plaso 20260512 + Volatility 3 |

Category-level union results: staging/build has no applicable target and drops
out of the case entirely; persistence/activation `5 / 5` (100.0%; four observed
plus one partial, M08), runtime `2 / 2` (100.0%).

**What the 100% figures do and do not mean.** Every applicable target was
reached by at least one source, but the applicability set is the seven targets
M05–M11 that the prebuilt-artifact design actually produces. The full coverage
records that the surviving treatment surface is small and well exposed, not that
recovery improved: the four staging/build targets left the denominator because
the events moved to the builder VM, not because a method found them. Coverage is
descriptive inside this declared set and must not be read against the earlier
Father runs or against another source family.

**Robustness readings.** Counting only `O`, the observed-only lower bound is
filesystem `3 / 4` (75.0%), timeline `1 / 3` (33.3%), memory `3 / 4` (75.0%),
union `6 / 7` (85.7%). No accepted `O`/`P` in this run rests on
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
file that survives offline (M07). The Plaso timeline orders install → preload
configuration → SSH restart → new `sshd` within 114 ms using the systemd
journal. The surviving preload inode's MAC time instead postdates its `tee`
command by about 3 s, demonstrating why MAC times alone cannot order this chain.
Memory establishes runtime effect: the same library inode mapped in the
restarted `sshd` (M05), a root child shell (M09), and one established backdoor
connection (M10).

The combination adds information in two distinct ways. For M05 the disk↔memory
inode-`74172` coincidence is corroboration across different artifact classes and
across the one independent acquisition (memory), excluding both single-tool
error and a disk-only artifact with no runtime effect. For M09/M10/M11 the
non-filesystem sources instead *expose* targets no cold source could reach; that
union gain reflects source-exclusive targets rather than a recovery an applicable
source missed. Keeping this distinction explicit is the methodological point of
the case. No materially contradictory accepted observation was recorded (`X` 0).

Declared limitations: this run cannot speak to build staging at all, because the
build happens on a separate builder VM and M01–M04 are not applicable rather
than negative — a design boundary, not a recovery failure, and the reason this
case's coverage is not comparable with the earlier Father runs; command history
preserves text but not per-command times
(M08 partial/negative across sources); static ELF inspection proves capability,
not hook execution; no memory mapping was hashed, so library identity is
disk-derived only; and Plaso shares the disk acquisition with TSK. The cause of
the preload inode's approximately 3 s MAC-time offset is not established.
