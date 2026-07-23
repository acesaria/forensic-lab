# Father calibration — Ubuntu 22.04 vanilla

Status: reviewed — filesystem, memory and timeline sources closed out.

| Item | Value |
|---|---|
| Run | `ubuntu-22.04_userland_father_ldpreload_20260722-175300` |
| Scenario | `userland_father_ldpreload` (userland `LD_PRELOAD` persistence) |
| Platform | Ubuntu 22.04.5 LTS, kernel `5.15.0-1095-kvm`, vanilla profile, UTC guest |
| Repository revision | `02263bb55e2457f1045a3bff48a73ad72e5652fd` |
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
  ISF `ubuntu_5.15.0-1095-kvm.json`, consolidated in `analysis/vol3.json`.
- **Timeline:** Plaso 20260512 over the EWF with the repository collection
  filter; store `analysis/timeline.plaso`, export `analysis/timeline.jsonl`.

Analyst working copies and measurements live in the investigation workspace
(`shared/investigations/<run>/`), never inside the immutable run directory.

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

**Memory (Volatility 3).** Discovery started from an anomaly, not ground
truth: an unusual `selinux.so.3` mapping in `linux.proc.Maps` led to `sshd`
PID 871 and `sh` PID 873, both mapping `/usr/lib/selinux.so.3` (inode 62345,
matching the disk artefact). Both PIDs appear in `linux.pslist` and
`linux.psscan`; PID 873 is a root shell (UID/EUID 0, GID/EGID 1337) parented
by PID 871. `linux.sockstat` shows one established TCP connection
(`192.168.100.41:22` ↔ `192.168.100.1:54321`, socket object
`152049476416640`); its five FD rows deduplicate to a single connection.
Negatives that matter: `linux.bash` returned no rows (disk history still
exists); `linux.malfind` flagged two RWX regions in unrelated processes; no
memory mapping was dumped or hashed, so the library hash equality is
disk-derived only.

**Timeline (Plaso).** The complete store holds **15,923 events** (9,637
`filestat`, 3,488 syslog, 2,798 journal). The canonical export
(`psort -o json_line`, no filter arguments) applies psort's default
duplicate removal and writes 15,122 JSONL lines; the 801-line difference is
deduplication, never time filtering. Both the complete store and the
canonical JSONL are preserved unrestricted by scenario ground truth. For
triage, one derived analyst view was exported with an explicit psort date
filter around the scenario interval plus a ±120 s buffer
(`2026-07-22T15:51:00.766Z`–`15:55:02.171Z`, UTC guest and store): **3,781
events**, saved as `derived/plaso/analyst-view-timeline.jsonl` with full
provenance. This view is ground-truth-guided manual triage, not blind
detection.

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
`/(lib|lib64)/` variant) and validated end-to-end against a synthetic tree:
shallow `.so` files (including `selinux.so.3`) are selected; deep multiarch
paths and non-`.so` files are not. The EWF was not reprocessed; the
candidate benchmark remains the measured estimate. The filter stays fully
scenario-blind.

## 4. Cross-source reconstruction

Supported sequence, grouped into phases (times UTC, canonical JSONL lines as
locators):

1. **Staging** (`15:53:00.97`–`01.50`): archive appears in `/tmp` (filestat,
   line 14547), tree extracted (14579), `config.h` modified (14632).
2. **Build and install** (`01.87`–`01.92`): `rk.so` created (14688), library
   installed — journal sudo record (14707) — hidden file created (14711).
3. **Activation** (`01.97`–`02.09`): `tee` writes `/etc/ld.so.preload`
   (14717), SSH restart requested and completed with new `sshd` PID 871
   (14720–14735), Bash history finalized (14739).
4. **At acquisition** (memory): PID 871 and root `sh` PID 873 live with the
   library mapped and one established port-54321 connection.

| Finding | Filesystem | Timeline | Memory |
|---|---|---|---|
| Preload config | inode 62372, content | journal `tee` (14717) | library in use |
| Installed library | inode 62345 | journal (14707); filestat via corrected filter | Maps, inode 62345 |
| Build ≡ install | SHA-256 equality | filestat creations | mapped copy (not hashed) |
| `__malicious_file` | inode 260193, offline-visible | filestat (14711) | — |
| Bash history | command strings (inode 260194) | filestat only (14739) | `linux.bash` empty |
| Root shell + socket | — | service sequence (14720–14735) | PIDs 871/873, GID 1337, port 54321 |

Disk supplies content and identity, the timeline supplies temporal and log
context, memory supplies live process and socket state. No source
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
- Baseline Plaso runtime was not recorded, so filter runtime overhead is
  unmeasured; candidate outputs are measurements, not primary evidence.

Disk, timeline and memory are mutually consistent. The disk preserves the
full persistence chain from staging archive to installed library
(byte-identical to the build) plus the command strings; the timeline
supports the staging→build→install→activation sequence without timing
individual commands; memory shows the backdoor live. The one collection gap
found was fixed generically, and the audit additionally caught and corrected
a silently inert filter expression — a useful reminder that unexpected
negatives should be explained, not assumed benign.
