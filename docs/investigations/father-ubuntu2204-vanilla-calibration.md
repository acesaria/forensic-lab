# Father calibration — Ubuntu 22.04 vanilla

> **Historical draft:** this older calibration report is not an accepted
> authoritative investigation under the current `../../ai/archive/METHODOLOGY.md` reporting
> contract and is excluded from `COMPARATIVE_RESULTS.md`. Its legacy DR/FP/TTD/
> QoR table must not be used for thesis comparison.

Status: historical draft — retained for provenance, not current comparison.

| Item | Value |
|---|---|
| Run | `ubuntu-22.04_userland_father_ldpreload_20260722-175300` |
| Scenario | `userland_father_ldpreload` (userland `LD_PRELOAD` persistence) |
| Platform | Ubuntu 22.04.5 LTS, kernel `5.15.0-1095-kvm`, vanilla profile, UTC guest |
| Repository revision | `02263bb55e2457f1045a3bff48a73ad72e5652fd` (run); reprocessed at `4d7f21c` |
| Scenario interval | `2026-07-22T15:53:00.766Z` – `2026-07-22T15:53:02.171Z` |

## 1. Case and evidence

This is a calibration experiment: a known controlled compromise is run once,
and the three evidence sources (disk, timeline, memory) are checked for
mutual consistency so that later scenarios can be trusted. Interpretation is
manual throughout; nothing here is automatic detection or scoring.

The scenario stages the *Father* userland rootkit, an `LD_PRELOAD` library
that hooks libc functions to hide files and grant a backdoor shell.
Acquisition produced immutable evidence, all read-only for this analysis:

- **Disk (VM off):** EWF `dumps/disk/evidence_disk.E01/.E02`, logical SHA-256
  `d07e721c…6936` verified by `ewfverify` (exit 0). Root ext4 at byte offset
  `116391936`. TSK bodyfile `analysis/bodyfile`, 72,683 rows.
- **Memory (VM on):** `dumps/memory/mem.raw` (2,147,747,795 B, SHA-256
  `ae716110…0cb5`), via `virsh dump --memory-only`; Volatility 3 2.28.0 with
  ISF `ubuntu_5.15.0-1095-kvm.json`.
- **Timeline:** Plaso 20260512 over the EWF with the repository collection
  filter.

Plaso and Volatility were reprocessed later (2026-07-23) from this unchanged
evidence at repository revision `4d7f21c` — all hashes re-verified first.
The accepted analysis outputs cited below live in
`derived/reprocess-4d7f21c/` in the investigation workspace, with full
provenance; the original run outputs (`analysis/timeline.plaso`,
`timeline.jsonl`, `vol3.json`) are retained untouched. TSK was not rerun.
Analyst working copies never enter the immutable run directory.

## 2. Scenario validation

These facts come from the run's `manifest.json` and `command_log.jsonl`. They
verify that the controlled scenario executed as intended; they are ground
truth, not post-mortem discoveries, and no forensic conclusion rests on them
alone.

| Recorded validation | Result |
|---|---|
| Source upload, extraction, `make father`, install to `/lib/selinux.so.3` | success |
| `/etc/ld.so.preload` activation and SSH restart | success |
| Live file-hiding check | `true` |
| Backdoor identity / trigger | `uid=0 gid=1337`, client port `54321` → `sshd:22` |

## 3. Findings by source

**Filesystem (TSK, read-only).** Discovery followed the standard
preload-persistence path from `/etc/ld.so.preload` outward, without using
ground truth. Key artefacts (bodyfile rows in parentheses):
`/etc/ld.so.preload`, inode 62372 (row 2144), content `/lib/selinux.so.3`;
the `/lib` symlink resolves it to `/usr/lib/selinux.so.3`, inode 62345
(row 18198), a 32,784 B root-owned ELF. The `/tmp` staging tree survives in
full: uploaded archive inode 61596 (row 2295, SHA-256 matching the manifest
source), extracted tree inode 258157, edited `src/config.h` inode 258178
(GID `1337`, `SOURCEPORT 54321`, prefix `__malicious_`), and built `rk.so`
inode 260192. The built and installed copies hash identically (SHA-256
`87fece49…0711`), proving the installed library is the built `rk.so`.
`/home/labuser/.bash_history`, inode 260194 (row 13), preserves the command
strings including `make father` and `touch "$hidden_dir/__malicious_file"`.
The planted `probe/__malicious_file`, inode 260193, is visible offline —
TSK bypasses the live `readdir()` interposition. Static ELF inspection
(exported hook symbols, `AUTHENTICATE:` string) characterises the library
but proves no hook executed.

**Memory (Volatility 3).** The accepted combined output is the reprocessed
`vol3.json`: all eight default plugins completed, including `linux.psaux`,
which the original seven-plugin output lacked (pslist 101, psscan 169,
psaux 101, bash 0, sockstat 309, malfind 2, lsmod 14, proc.Maps 4,386 rows;
the seven previously present plugins match the original counts exactly).
Discovery started from an anomaly, not ground truth: an unusual
`selinux.so.3` mapping in `linux.proc.Maps` led to `sshd` PID 871 and `sh`
PID 873, each mapping five segments of `/usr/lib/selinux.so.3` (inode 62345,
matching the disk artefact). Both PIDs appear in `linux.pslist` and
`linux.psscan`; PID 873 is a root shell (UID/EUID 0, GID/EGID 1337) parented
by PID 871. `linux.psaux` gives their command lines: PID 873 `/bin/sh`;
PID 871 rendered `sshd: /usr/sbin/ss` (truncated, not treated as a full
path). `linux.sockstat` shows one established TCP connection
(`192.168.100.41:22` ↔ `192.168.100.1:54321`, socket object
`152049476416640`); its five FD rows (sshd FD 5, sh FDs 0/1/2/5)
deduplicate to a single connection. Negatives that matter: `linux.bash`
returned no rows (disk history still exists); `linux.malfind` flagged two
RWX regions in unrelated processes; no memory mapping was dumped or hashed,
so the library hash equality is disk-derived only.

**Timeline (Plaso).** The accepted reprocessed store holds **15,995 events**
(9,709 `filestat`, 3,488 syslog, 2,798 journal; the original baseline store
held 15,923). The canonical export (`psort -o json_line`, no filter
arguments) applies psort's default duplicate removal and writes **15,194**
JSONL lines; the 801-line difference is deduplication, never time filtering.
Both the complete store and the canonical JSONL are preserved unrestricted
by scenario ground truth. For triage, one derived analyst view was exported
with an explicit psort date filter around the scenario interval plus a
±120 s buffer (`2026-07-22T15:51:00.766Z`–`15:55:02.171Z`, UTC guest and
store): **3,795 events**, saved beside the store with full provenance. This
view is ground-truth-guided manual triage, not blind detection.

*Bash history, resolved.* The recovered history contains the command strings
but no `#<epoch>` timestamp lines. The installed `text/bash_history` plugin
verifies file format before parsing and requires such a line; a standalone
diagnostic against a copy of the recovered file produced zero events, while
a synthetic timestamped control produced events normally. So the file was
selected, the parser was enabled, and the absence of command events happens
at the parsing (format-verification) stage — not at storage and not at psort
export. The command strings remain a filesystem finding; no individual
execution times can be assigned to them. `text/bash_history` stays enabled.

*Collection-filter gap and correction.* The baseline filter missed shallow
`/usr/lib` shared libraries, so `/usr/lib/selinux.so.3` had no `filestat`
row. A measured candidate rerun of the same EWF (+24 events, ≈0.12 % larger
JSONL, no warnings) recovered it. Audit of that decision found a real
defect: the promoted generic expressions used `[^/]` character classes, but
Plaso splits filter paths on `/` before compiling per-segment regexes, so
those expressions were silently inert — the candidate's `selinux.so.3` rows
had actually come from a Father-specific line that was rightly dropped at
promotion. The generic expressions were corrected to the split-safe
per-segment equivalent (`/usr/(lib|lib64)/.+[.]so([.][0-9]+)*` and the
`/(lib|lib64)/` variant) and validated against a synthetic tree. The
output-only reprocessing then confirmed the fix on the real evidence: the
corrected generic expressions add **+72 filestat events** over the original
baseline — 18 newly selected paths × 4 events, namely 13 shallow shared
libraries (including `/usr/lib/selinux.so.3`, klibc and multipath
libraries) and 5 `/usr/local` directories, all scenario-blind. The
installed library's four `filestat` rows are now a normal finding of the
accepted timeline (canonical lines 14769–14771 and 14786, the last a
`15:53:01.981` access during the SSH restart). No Father-specific path rule
exists in the filter.

## 4. Cross-source reconstruction and coverage

Supported sequence, grouped into phases (times UTC; locators are line
numbers in the reprocessed canonical `timeline.jsonl`; event order is
unchanged from the original baseline, only line numbers shifted):

1. **Staging** (`15:53:00.97`–`01.50`): archive appears in `/tmp` (filestat,
   line 14610), tree extracted (14642), `config.h` modified (14695).
2. **Build and install** (`01.87`–`01.92`): `rk.so` created (14751), library
   installed — filestat (14770) and journal sudo record (14773) — hidden
   file created (14777).
3. **Activation** (`01.97`–`02.09`): `tee` writes `/etc/ld.so.preload`
   (14783), SSH restart requested and completed with new `sshd` PID 871
   (14787–14802), Bash history finalized (14806).
4. **At acquisition** (memory): PID 871 and root `sh` PID 873 live with the
   library mapped and one established port-54321 connection.

Coverage is scored against eleven minimal atomic targets derived from the
scenario's ground-truth records, each mapped only to accepted forensic
locators. This is **manual evidence-recovery coverage** — a descriptive
post-mortem measure of what each source recovered, not automatic detection
accuracy. This first inventory was formalised after the investigation but
derived from ground truth independently of the evidence mapping; later
inventories are frozen before mapping under the metric contract in
`COMPARATIVE_RESULTS.md`. Applicability is fixed by source capability:
filesystem M01–M08, timeline M01–M08 and M11, memory M05/M09/M10.

| Target — expected fact | FS | TL | Mem | Accepted locators / limitation |
|---|---|---|---|---|
| M01 source archive staged | obs | obs | n/a | FS inode 61596; TL 14610 |
| M02 source/build tree extracted | obs | obs | n/a | FS inode 258157; TL 14642 |
| M03 malicious `config.h` applied | obs | partial | n/a | FS inode 258178 (content); TL 14695 times the edit, not its bytes |
| M04 `rk.so` built | obs | obs | n/a | FS inode 260192; TL 14751 (byte-equal to M05) |
| M05 library installed/mapped `/usr/lib/selinux.so.3` | obs | obs | obs | FS inode 62345; TL 14770; `proc.Maps` PID 871/873 (mapping not hashed) |
| M06 `/etc/ld.so.preload` configured | obs | obs | n/a | FS inode 62372; TL 14783 (journal `tee`); the mapping is M05 |
| M07 controlled hidden file created | obs | obs | n/a | FS inode 260193; TL 14777 |
| M08 interactive command activity | partial | not obs | n/a | FS inode 260194 (command strings); TL no `#<epoch>` → 0 `text/bash_history`; memory shell exited pre-capture |
| M09 privileged shell parented by `sshd` | n/a | n/a | obs | `pslist` PID 873 PPID 871, UID/GID 0/1337 |
| M10 established backdoor connection | n/a | n/a | obs | `sockstat` object 152049476416640, `:22`↔`:54321` (5 FDs → 1 conn) |
| M11 SSH service restart during activation | n/a | obs | n/a | TL 14787–14802; a live `sshd` alone would not prove a restart |

`obs` observed; `partial` central occurrence supported with a stated property
missing (still Found); `not obs` applicable but unrecovered; `n/a` source
cannot reasonably observe the target. M08 is Found on disk (command strings
present) but its full sequence and per-command timing were not recovered and
the timeline produced no command events — the sole reason timeline coverage is
below 100%.

| Source                 | Found / Total | Coverage (DR) | FP          | TTD          | QoR    |
|------------------------|:-------------:|:-------------:|:-----------:|:------------:|:------:|
| Filesystem             | 8 / 8         | 100%          | N/A         | not measured | High   |
| Timeline               | 8 / 9         | 88.9%         | N/A         | not measured | Medium |
| Memory                 | 3 / 3         | 100%          | 2           | not measured | High   |
| Union (unique targets) | 11 / 11       | 100%          | 2 case-wide | not measured | —      |

The two memory FP candidates are the unrelated `linux.malfind` RWX rows for
`networkd-dispatcher` (PID 365) and `unattended-upgrades` (PID 438): heuristic
candidates the plugin surfaced, rejected because neither PID carries a Father
mapping or any other Father relationship. FP is a count of rejected candidates,
not a rate. TTD was not measured — no prospective analyst start/first-locator
times were recorded, and TTD cannot be reconstructed from attack, acquisition,
event or tool timestamps. The 100% union coverage is the observed result of
this calibration, not a pass condition; lower coverage in later scenarios is an
equally valid forensic result. Disk supplies content and identity, the timeline
temporal and log context, memory live process and socket state; no source
contradicts another.

## 5. Limitations and conclusion

- Static ELF tools prove presence, not execution; no recovered binary was
  run, and no memory mapping was dumped or hashed.
- Bash-history commands carry no timestamps in this run; only `filestat` and
  journal events provide times, so individual command executions are not
  independently timed.
- `/lib` is a symlink: the installed object exists only under `/usr/lib`,
  and no `/lib/selinux.so.3` row can exist.
- Memory negatives (`linux.bash` empty, unrelated `malfind` hits, ordinary
  `lsmod`) neither confirm nor exclude a userland preload.
- The original baseline Plaso runtime was not recorded, so filter runtime
  overhead is unmeasured; the reprocessed extraction took 17.4 s with no
  warnings. Reprocessed outputs are later analysis of unchanged evidence,
  not new acquisition.

Disk, timeline and memory are mutually consistent. The disk preserves the
full persistence chain from staging archive to installed library
(byte-identical to the build) plus the command strings; the timeline
supports the staging→build→install→activation sequence without timing
individual commands; memory shows the backdoor live. The one collection gap
found was fixed generically, and the audit additionally caught and corrected
a silently inert filter expression, a fix the output-only reprocessing
confirmed on the real evidence — a useful reminder that unexpected negatives
should be explained, not assumed benign.
