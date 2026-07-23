Status: ready for analyst review — Filesystem, Memory and Plaso reviewed.

# Father calibration — Ubuntu 22.04 vanilla

Run identity:

| Item | Value |
|---|---|
| Run | `ubuntu-22.04_userland_father_ldpreload_20260722-175300` |
| Scenario | `userland_father_ldpreload` (userland `LD_PRELOAD` persistence) |
| Workflow / scenario status | `completed` / `completed` |
| Platform | Ubuntu 22.04.5 LTS, kernel `5.15.0-1095-kvm`, vanilla profile, UTC guest |
| Baseline | VM `lab-ubuntu-22.04`, snapshot `baseline` (`2026-07-15T13:28:58Z`) |
| Repository revision | `02263bb55e2457f1045a3bff48a73ad72e5652fd` |
| Scenario interval | `2026-07-22T15:53:00.766Z` – `2026-07-22T15:53:02.171Z` |

This is a calibration report: its purpose is to confirm that the three evidence
sources (disk, memory, timeline) are consistent and readable for a known
scenario, so later scenarios can be trusted. It is not final thesis prose and
contains no automatic detection, scoring or reconstruction.

## 1. Experimental case

The scenario stages the *Father* userland rootkit, an `LD_PRELOAD` library that
hooks libc functions to hide files and grant a backdoor shell. Acquisition
produced immutable disk and memory images plus raw TSK, Plaso and Volatility
exports; all analysis below reads those artefacts read-only.

Acquisition provenance:

- **Disk (VM off):** EWF `dumps/disk/evidence_disk.E01` (+`.E02`), logical size
  `4294967296` bytes, recorded logical SHA-256
  `d07e721c2be1841b74bab01c0b2b7baea935e201f047a974746d83367c264936`. Existing
  `ewfverify -d sha256` completed with exit `0`; the recorded digest was
  accepted rather than recomputed. Root filesystem is ext4 at sector `227328`
  (byte offset `116391936`). TSK bodyfile `analysis/bodyfile` has 72,683 rows,
  SHA-256 `2d7e5268f40620152358d6651865c9a609510a52413dc8ab002b820cee6ecc78`.
- **Memory (VM on):** `dumps/memory/mem.raw`, `2147747795` bytes, SHA-256
  `ae716110c13a38bebdeb968d84fc70edd40ecaaf9033968e98ecb8928abb0cb5`, acquired
  with `virsh dump --memory-only`. Volatility 3 `2.28.0` with ISF
  `ubuntu_5.15.0-1095-kvm.json`; consolidated output `analysis/vol3.json`.
- **Timeline:** Plaso `log2timeline` version `20260512` over the EWF, output
  `analysis/timeline.jsonl` / `analysis/timeline.plaso`.

All acquired images and raw exports remain immutable; nothing in this review
modified them.

## 2. Scenario validation

The facts in this section come from the run's `manifest.json` and
`command_log.jsonl`. **They verify that the controlled scenario executed as
intended; they are experimental ground truth, not post-mortem discoveries.** No
forensic conclusion below rests on them alone.

| Recorded validation | Result |
|---|---|
| Source verification, upload, extraction, `make father` | success |
| `rk.so` installed at `/lib/selinux.so.3` | success |
| `/etc/ld.so.preload` activation and SSH restart | success |
| Live file-hiding validation | `true` |
| Native backdoor identity | `uid=0(root) gid=1337 groups=1337` |
| Trigger/listener | client source port `54321` to `sshd` port `22` |

## 3. Investigation findings

### Filesystem (TSK, read-only)

Discovery followed the standard preload-persistence path: `/etc/ld.so.preload`
→ named library → `/lib` symlink resolution → installed ELF → the `/tmp` staging
tree → build/install hash equality → Bash history → offline probe directory.

| Finding | Inode / locator | Direct observation | Interpretation / limitation |
|---|---|---|---|
| Preload configuration | `/etc/ld.so.preload`, inode 62372 (bodyfile row 2144) | Allocated, 17 B, root-owned, `0644`; content `/lib/selinux.so.3` | Persistence configuration on disk; runtime activation is a validation fact, not a disk observation. |
| Installed library + path resolution | `/lib` symlink inode 1542 → `/usr/lib/selinux.so.3`, inode 62345 (row 18198) | `/lib` points to `usr/lib`; installed file 32,784 B, root-owned, `0644` | The textual `/lib/...` preload path resolves to the `/usr/lib` inode; TSK does not follow the directory symlink automatically. |
| Uploaded archive | `/tmp/father-upstream-4eb2712.tar`, inode 61596 (row 2295) | POSIX tar, 61,440 B, uid/gid 1000, `0664`; SHA-256 `90e440a2…a2c125` | Digest matches the source provenance recorded in the manifest. |
| Extracted source/build tree | `/tmp/forensic-lab/father_ldpreload`, inode 258157 (row 2300) | Allocated `0775` dir, uid/gid 1000; contains source, build dirs, `rk.so` | Full tree enumerated in the immutable bodyfile; only small files were re-extracted as working copies. |
| Modified configuration | `src/config.h`, inode 258178 (row 2320) | Contains GID `1337`, `SOURCEPORT 54321`, prefix `__malicious_`, install path `/lib/selinux.so.3` | Static source context; explains later observables but does not prove execution. |
| Built `rk.so` | inode 260192 (row 2331) | ELF64 x86-64 shared object, 32,784 B, `0775`, not stripped; SHA-256 `87fece49…2f0711` | Static inspection only; the ELF was never loaded. |
| Build ≡ install | inodes 260192 and 62345 | Both 32,784 B, both SHA-256 `87fece49…2f0711` | Independently extracted inodes hash identically: the installed library is the built `rk.so`. |
| Bash history | `/home/labuser/.bash_history`, inode 260194 (row 13) | 613 B, uid/gid 1000, `0600`; records extraction, `config.h` edit, `make father`, install, `touch __malicious_file`, preload write, SSH restart | Command **strings** are present on disk (see §4 for their status). Distinct from the scenario command log. |
| Controlled hidden file | `probe/__malicious_file`, inode 260193 (row 2299) | Allocated zero-byte file, uid/gid 1000, `0664` | Offline TSK enumeration bypasses live userland `readdir()` interposition; proves offline visibility, not the separate live-hiding validation. |

Static ELF characteristics (both copies): ELF64 `DYN`, x86-64, dynamically
linked, not stripped, Build ID `96daef8b…49c7`; exported symbols include
`accept`, `readdir`, `open`, `openat`, `opendir`, `lstat`, `fstat`; strings
include `AUTHENTICATE:`, `Enjoy the shell!`, `__malicious_`, `/lib/selinux.so.3`.
These characterise the library but do not prove any hook executed.

### Memory (Volatility 3)

Discovery ran from an anomaly, not from ground truth: an unusual `selinux.so.3`
mapping in `linux.proc.Maps` led to the two live processes, which were then
confirmed across independent structures. The scenario record supplied neither
PID.

| Finding | Plugin | Observation | Classification |
|---|---|---|---|
| Father library mapped into two processes | `linux.proc.Maps` | Five segments each for `sshd` PID 871 and `sh` PID 873 resolve to `/usr/lib/selinux.so.3`, inode 62345 | Suspicious observable; path/inode matches the disk artefact. A mapping shows presence, not which hook ran. |
| Both processes independently visible | `linux.pslist`, `linux.psscan` | PIDs 871/873 in both; `psscan` marks both `TASK_RUNNING` | Agreement across traversal and scan supports both processes alive at acquisition. |
| Privileged shell + ancestry | `linux.pslist` | PID 873 `sh` is a child of PID 871 `sshd`, UID/EUID 0, GID/EGID 1337 | Root shell parented by `sshd`; GID 1337 is case-specific, not a universal signature. |
| One established connection | `linux.sockstat` | Socket object `152049476416640`, TCP `ESTABLISHED`, guest `192.168.100.41:22` ↔ host `192.168.100.1:54321`; referenced by `sshd` FD 5 and `sh` FDs 0/1/2/5 | Five FD rows are **one** connection after object-level deduplication; port 54321 corroborates validation. |
| Command-line context | `linux.psaux` | PID 873 args `/bin/sh`; PID 871 rendered `sshd: /usr/sbin/ss` (truncated) | Direct observation; the truncated `sshd` string is not treated as a full path. |

Negative memory observations that matter for interpretation:

- `linux.bash` returned `[]`. This means only that this plugin recovered no Bash
  rows; a live `sh` (PID 873) is independently present, and disk history exists.
- `linux.malfind` returned two RWX anonymous rows, in `networkd-dispatcher`
  (PID 365) and `unattended-upgrades` (PID 438). Neither has a Father mapping,
  so neither is labelled malicious.
- `linux.lsmod` listed 14 ordinary modules with empty taint fields. Father is a
  userland preload technique, so an ordinary module list neither confirms nor
  excludes it.
- No mapping was dumped or hashed, and no distinctive Father string was recovered
  from RAM in this bounded pass. The correlated SHA-256 above is the disk copy's,
  not a memory-resident hash.

### Timeline (Plaso)

The baseline timeline holds 15,122 events: 9,069 `filestat`, 3,281
`text/syslog_traditional`, 2,772 `systemd_journal`. Timestamps are UTC
microseconds. For `filestat`, the four `timestamp_desc` values are properties of
one inode, not four actions. The installed `systemd_journal` parser fills
`written_time` from a journal entry's `real_time` but the timeliner labels it
`Content Modification Time`; parser inspection confirms it is the journal entry
time, not a file mtime.

Supported sequence within the scenario window (baseline `timeline.jsonl` lines
are the locators):

| Event | UTC | Meaning | Source | Line |
|---|---|---|---|---|
| Uploaded archive | `15:53:00.965777` | Creation | `filestat` | 14547 |
| Staging tree | `15:53:01.453777` | Creation | `filestat` | 14579 |
| Modified `config.h` | `15:53:01.497777` | Content mod. | `filestat` | 14632 |
| Built `rk.so` | `15:53:01.869777` | Creation | `filestat` | 14688 |
| Installed library | `15:53:01.905777` | Creation | `filestat` (candidate) | 14727 |
| Sudo install record | `15:53:01.908225` | Journal write | `systemd_journal` | 14707 |
| Hidden file | `15:53:01.917777` | Creation | `filestat` | 14711 |
| Preload write (`tee`) | `15:53:01.968362` | Journal write | `systemd_journal` | 14717 |
| SSH restart requested | `15:53:01.988607` | Journal write | `systemd_journal` | 14720 |
| Old ssh deactivates | `15:53:01.995487` | Journal write | `systemd_journal` | 14724 |
| New sshd listens (PID 871) | `15:53:02.012822` | Journal write | `systemd_journal` | 14735 |
| Bash-history file finalized | `15:53:02.085777` | Content mod. | `filestat` | 14739 |

A later `/etc/ld.so.preload` `filestat` mtime at `15:53:04.505777` (line 14979)
is a final inode property in the acquisition/shutdown window and is not
substituted for the earlier journalled `tee` write.

**Bash history and Plaso — the attribution that matters.** The command strings
`cd "$source" && make father` and `touch "$hidden_dir/__malicious_file"` are
present in the recovered `.bash_history` (verified on disk; see §3 filesystem).
Their presence is therefore a **filesystem** finding. Plaso produced **no**
`text/bash_history` command events — not because the parser was absent (it was
enabled) or the file was out of scope (`/home/.+/.bash_history` is in the
collection filter), but because the recovered history contains no
`HISTTIMEFORMAT` epoch-timestamp lines, which is the only form the parser can
turn into timestamped events. Only the four `.bash_history` `filestat` inode
times were produced. Consequently there are no Plaso-assigned execution times for
those commands; the `rk.so` and `__malicious_file` **creation** times above give
indirect temporal support but are not command-execution logs. Likewise, no
journal/syslog record states `make father` or `touch __malicious_file` — `make`
and `touch` do not log there; those actions surface only through `filestat`.

**Filter change and its measured effect.** The baseline collection filter did not
cover shallow versioned shared libraries directly under `/usr/lib`, so
`/usr/lib/selinux.so.3` had no `filestat` row in the baseline timeline. The
accepted change to `orchestrator/forensics/filters/linux_common.yaml` adds three
scenario-blind, segment-based expressions:

```
/usr/local/(bin|sbin|lib|lib64)
/usr/(lib|lib64)/[^/]+[.]so([.][0-9]+)*
/(lib|lib64)/[^/]+[.]so([.][0-9]+)*
```

The `[^/]+` guards keep the `/usr/lib` and `/lib` patterns to immediate
`.so`/versioned-`.so` filenames and do not recurse into multiarch trees. One
candidate extraction of the same immutable EWF (Plaso `20260512`) measured:
`log2timeline` 17.84 s, `psort` 2.63 s, +24 events (15,122 → 15,146, all
`filestat`), +19,276 JSONL bytes (≈0.12%), no warnings or errors, and it
recovered the four `/usr/lib/selinux.so.3` `filestat` rows. The candidate's extra
case-specific line `/usr/lib/selinux[.]so[.]3` was **not** promoted: it is
redundant (the generic versioned-`.so` expression already matches) and would
hard-code a Father path. This is a proportionate, cross-scenario gain, so the
three generic expressions are retained; no parser was added.

## 4. Cross-source reconstruction

Supported sequence (sources named per step): the archive appears in `/tmp`
(disk + Plaso `filestat`), is extracted and `config.h` edited (disk content +
Plaso `filestat`), `rk.so` is built and installed to `/usr/lib/selinux.so.3`
(disk hash equality + Plaso `filestat`/journal install record), `/etc/ld.so.preload`
is written and `ssh.service` restarted (journal), and at acquisition the new
`sshd` (PID 871) and a root `sh` (PID 873) are live with the library mapped and
one established port-54321 socket (memory). Disk supplies content and identity,
Plaso supplies temporal/log context, memory supplies live process and socket
state.

| Finding | Filesystem | Plaso | Memory | Interpretation |
|---|---|---|---|---|
| Preload configuration | inode 62372 | line 14717 (`tee`) | library mapped, not the config file | Disk gives content `/lib/selinux.so.3`; Plaso times the write; memory shows the referenced library in use. |
| Installed library | inode 62345 | candidate line 14727 | proc.Maps inode 62345 | Baseline omitted the path; candidate supplies the `filestat` row; memory confirms it live. |
| Uploaded archive | inode 61596 | line 14547 | not searched | Digest matches manifest source. |
| Extracted tree + `config.h` | inode 258157 / 258178 | lines 14579, 14632 | not searched | Plaso dates objects; disk supplies configured values. |
| Built `rk.so` | inode 260192 | line 14688 | maps installed copy | Build-tree object vs. installed mapping. |
| Build ≡ install identity | inodes 260192 + 62345 | n/a | inode 62345 mapped | SHA-256 equality is disk-derived; no memory mapping was hashed. |
| `__malicious_file` | inode 260193 | line 14711 | not searched | Offline visibility; live hiding stays a validation fact. |
| Bash history | inode 260194 (command strings) | line 14739 (`filestat` only) | `linux.bash` = `[]` | Disk uniquely supplies command content; Plaso gives only file times; memory recovered no rows. |
| SSH restart → new daemon | n/a | lines 14720/14724/14735 | `pslist` PID 871 | Plaso gives the service sequence; memory observes the resulting live daemon (same PID 871). |
| Library in `sshd` + shell | inode 62345 | line 14707 | proc.Maps PIDs 871/873 | Memory uniquely establishes live address-space mappings. |
| Root shell ancestry + GID 1337 | n/a | not observed | `pslist`/`psscan`/`pstree` | Memory uniquely supplies process identity and ancestry. |
| Port-54321 connection | n/a | not observed | `sockstat` object `152049476416640` | Five FD rows are one deduplicated connection. |

## 5. Limitations and conclusion

**Limitations that change interpretation.**

- Static tools (`file`, `readelf`, `strings`) characterise ELFs but prove no
  runtime execution; no recovered binary was loaded.
- Plaso assigns no execution times to Bash-history commands (source lacks
  `HISTTIMEFORMAT` timestamps), and neither `make father` nor
  `touch __malicious_file` is logged; both surface only via `filestat`/disk.
- `/lib` is a symlink to `/usr/lib`; the installed object is reported under
  `/usr/lib`, and a direct `/lib/selinux.so.3` `filestat` row does not exist.
- Memory negatives (`linux.bash` empty, `malfind` unrelated, `lsmod` ordinary)
  do not exclude a userland preload; no memory mapping was dumped or hashed and
  no Father string was recovered from RAM.
- Baseline Plaso runtime was not recorded, so runtime overhead is not computed;
  the baseline was not rerun. The candidate timeline is a measurement output, not
  primary evidence.

**Conclusion.** Disk, timeline and memory are mutually consistent with no
contradiction. The disk preserves the preload configuration, installed library,
uploaded archive, source/build tree, built `rk.so` (byte-identical to the
installed library), Bash history and the controlled hidden file. Plaso supports
the sequence from archive creation through build, install, preload write and
successful SSH restart, but does not time individual commands. Memory shows the
library live in `sshd` and a root `sh`, their ancestry, GID 1337 and one
deduplicated established port-54321 connection. The one collection-filter gap
(shallow `/usr/lib` shared libraries) was fixed with a proportionate,
scenario-blind change; the installed Plaso configuration is otherwise adequate
for this class of scenario.
