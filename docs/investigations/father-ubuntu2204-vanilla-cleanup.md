# Father cleanup — Ubuntu 22.04 vanilla

Status: reviewed — filesystem, deletion recovery, timeline and memory sources closed out.

| Item | Value |
|---|---|
| Run | `ubuntu-22.04_userland_father_ldpreload_cleanup_20260724-162708` |
| Scenario | `userland_father_ldpreload_cleanup` (userland `LD_PRELOAD` persistence + partial cleanup) |
| Platform | Ubuntu 22.04.5 LTS, kernel `5.15.0-1095-kvm`, vanilla profile, UTC guest |
| Repository revision | `011db2291260096ef99c82f5c610f4c698797304` (run) |
| Scenario interval | `2026-07-24T14:27:08.159Z` – `14:27:10.260Z` (host bookkeeping; see §5) |

## 1. Case and evidence

This is the cleanup variant of the Father calibration: the same controlled
`LD_PRELOAD` compromise is deployed and validated, and then a small, naive
staging cleanup removes the uploaded archive and the extracted source/build
tree, clears the interactive Bash history, deletes the history file and
suppresses further history persistence. `/etc/ld.so.preload` and the installed
library deliberately remain. This is partial deployment/history cleanup, not
rootkit removal. The forensic question is what a post-mortem investigation
recovers once the staging evidence has been deleted.

Acquisition produced immutable evidence, all read-only for this analysis:

- **Disk (VM off):** EWF `dumps/disk/evidence_disk.E01`/`.E02`, logical SHA-256
  `aa7d804f…20d4a` verified by `ewfverify -d sha256` (exit 0, SUCCESS). Root
  ext4 `cloudimg-rootfs` at sector 227328 = byte offset `116391936`, block size
  4096, 1,020,155 blocks of which 463,295 free, inodes 1–516,097 of which
  444,541 free. TSK bodyfile `analysis/bodyfile`, 72,649 rows (Sleuth Kit
  4.15.0).
- **Memory (VM on):** `dumps/memory/mem.raw` (2,147,747,795 B, SHA-256
  `789db089…7ec6`) via `virsh dump --memory-only`; Volatility 3 2.28.0 with ISF
  `ubuntu_5.15.0-1095-kvm.json`, eight plugins, all exit 0.
- **Timeline:** Plaso 20260512 over the EWF with the repository collection
  filter; store `analysis/timeline.plaso` holds **15,907 events**, the canonical
  unfiltered export `analysis/timeline.jsonl` holds **15,104 lines** (psort's
  default deduplication accounts for the difference).

Two derived outputs are cited below, both in the investigation workspace with
full provenance and hashes. A triage timeline view was exported with an explicit
psort date filter around the scenario interval plus a ±120 s buffer
(`2026-07-24T14:25:08`–`14:29:10`, UTC guest and UTC store): **3,722 events**.
For deletion recovery, an offset-free root-ext4 working image was derived
read-only from the EWF (`ewfexport -f raw -o 116391936 -B 4178558464`,
4,178,558,464 B, SHA-256 `f54f1716…2cd5`), whose `fsstat` geometry at offset
zero matches the run's recorded values exactly. Both are disclosed
ground-truth-guided manual work, not blind detection; the complete store,
canonical export and acquired images are untouched.

## 2. Scenario validation

These facts come from `manifest.json` and `command_log.jsonl`. They verify that
the controlled scenario executed as intended; they are ground truth, not
post-mortem discoveries, and no forensic conclusion rests on them alone.

| Recorded validation | Result |
|---|---|
| Source verified, uploaded, extracted, `config.h` edited, `make father`, install to `/lib/selinux.so.3` | success |
| `/etc/ld.so.preload` activation and SSH restart | success |
| Live file-hiding check (visible before, hidden after) | `true` |
| Backdoor identity / trigger | `uid=0(root) gid=1337`, client port `54321` → `sshd:22` |
| Cleanup commands (`rm` archive, `rm -rf` tree, `history -c`, `rm` history file, `unset HISTFILE`) | exit 0 each |

The manifest's `scenario_facts.cleanup.*` booleans are assigned unconditionally
in the runner rather than observed in the guest, and the command log records
only that each `rm` returned 0. Neither states that a file was absent
afterwards, and neither is used as an evidence locator anywhere below.

## 3. Findings by source

**Filesystem (TSK, read-only) — surviving evidence.** Discovery followed the
standard preload-persistence path from `/etc/ld.so.preload` outward. The
configuration survives at inode 17436 (bodyfile row 2143), 17 bytes,
root-owned, content exactly `/lib/selinux.so.3` with no trailing newline.
`/lib` is a symlink to `usr/lib` (inode 1542, row 2235), resolving the target to
`/usr/lib/selinux.so.3`, inode 17435 (row 18164), a 32,784 B root-owned ELF
whose extracted copy hashes to SHA-256 `87fece49…0711`. Static inspection
characterises it as a Father build: a not-stripped x86-64 shared object needing
only `libc.so.6`, exporting interposition hooks (`accept`, `access`, `execve`,
`fopen`/`fopen64`, `open`/`open64`/`openat`, `opendir`, `readdir`, the `stat`
family, `unlink`/`unlinkat`, `pam_authenticate`) alongside Father-specific
`backconnect`, `exfil`, `falsify_tcp`, `lpe_drop_shell` and `timebomb`, and
containing `AUTHENTICATE: `, `Enjoy the shell!` and the configured
`__malicious_` prefix. This proves file characteristics, not that any hook
executed. The staging tree is partly intact — `/tmp/forensic-lab` (258150),
`father_ldpreload` (258151), `probe` (258152) and the planted
`probe/__malicious_file` (258185, 0 B), visible offline because TSK bypasses the
live `readdir()` interposition. Cleanup did not target them.

**Filesystem — deleted-entry and inode recovery.** No directory entry —
allocated or deleted — survives for the uploaded archive, the extracted
`Father-4eb2712…` tree, `src/config.h`, `rk.so` or `/home/labuser/.bash_history`.
The negative is trustworthy rather than vacuous: the same bodyfile carries 978
deleted-marked entries elsewhere (658 under `/usr/src`, 206 `/usr/share`, 70
`/usr/lib`, 40 `/usr/include`, four others), all baseline cloud-image artefacts,
so `fls` deleted-entry reporting demonstrably works here. Targeted
`fls -d -r` on the three surviving parents — `/tmp` (1581),
`/tmp/forensic-lab/father_ldpreload` (258151) and `/home/labuser` (258049) —
returned empty output at exit 0. With no attributable inode, no `istat` or
`icat` candidate existed for any deleted target. What remains at the metadata
level is one residual signal: inode 258151 carries mtime/ctime one second later
than the creation of its only surviving child, evidencing a subsequent
directory-entry change without naming what changed.

**Filesystem — journal-based recovery, and why it failed.** One targeted
`ext4magic` 0.3.2 pass over the derived working image, driven by a five-line
target list covering exactly the approved targets, completed at `EXIT_SUCCESS`
and recovered **nothing**. The ext4 journal (inode 8, 64 MiB) holds a
well-formed JBD2 superblock with **`s_start = 0`** and contains zero JBD2 block
magics in its entire body; `fsstat` independently reports a clean unmount.
Those observations are consistent with a checkpointed and reset journal after
graceful shutdown. With no historical journal transactions available, this
bounded journal-driven pass had no historic inode copies to recover. The result
shows why this `ext4magic` method was ineffective here; it does not directly
demonstrate when the journal was cleared or imply that deleted content is gone.

**Filesystem — content recovery from unallocated space.** `blkls` over the
working image yielded a 1,899,761,664 B unallocated stream, searched
exhaustively; stream offsets were mapped back to filesystem blocks with
`blkcalc -u`. **`src/config.h` was recovered complete at recovery level 5.** A
scenario-blind structural predicate (`#ifndef CONFIG`) matched once, at a block
boundary resolving to **filesystem block 589851**; the block holds the whole
header through `#endif` (740 bytes) followed by NUL padding. Identity was then
verified independently: the pristine `src/config.h` extracted from the
repository's vendored archive is 735 bytes, and applying the scenario's exact
`sed 's|^#define STRING .*|#define STRING "__malicious_"|'` produces a 740-byte
file whose SHA-256, `d14ebf96…0ad4`, is byte-identical to the recovered block
content. The recovered header carries `#define GID 1337`,
`#define SOURCEPORT 54321`, the scenario's `#define STRING "__malicious_"`,
`#define SHELL_PASS "lobster"` and
`#define INSTALL_LOCATION "/lib/selinux.so.3" // used for reinstallation`.
Attribution is sound because `SOURCEPORT` and `STRING` are preprocessor macro
names that cannot survive compilation — a control check confirms neither appears
in the allocated library — so those bytes are source text, not a copy of the
binary.

Adjacent to it, filesystem blocks **589852**, **589855**, **589856** and
**589861** hold level-3 attributable fragments: GCC assembler intermediates
from the `make father` compilation,
carrying `.file "accept.c"`, `.file "father.c"`, `.file "readdir.c"` and
x86-64 assembly calling `lpe_drop_shell@PLT` through `o_access@GOTPCREL`.
Attribution rests on Father's own source filenames and interposition symbols in
compiler output, not on generic strings. These fragments support source/build
tree identity and compilation, but not recovery of the final `rk.so`.

**Filesystem — bounded recovery negatives.** The archive, the built `rk.so` and
`.bash_history` remain at recovery level 0: they were **not recovered by the
bounded method**. For `rk.so`, an
exhaustive byte-exact search of the full unallocated stream for the built
object's first 64 bytes — taken from the byte-identical installed library —
returned zero matches, and a scan for *any* 64-bit ELF header returned exactly
one hit, examined and rejected as an unrelated artefact. For the archive, the
distinctive member path `Father-4eb2712…` and the filename
`father-upstream-4eb2712.tar` matched zero times; 18 generic `ustar` candidate
lines (21 raw occurrences) cluster far from the Father blocks, carry no Father
member name, and were all rejected as insufficient attribution. For
`.bash_history`, no command substring from the session (`make father`,
`tar -xf`, `hidden_dir`,
`history -c`, `unset HISTFILE`, `ls -la --`, `mkdir -p`, `__malicious_file`)
matched anywhere. This negative covers targeted `fls` deleted-entry examination,
one `ext4magic` journal pass and exhaustive string and byte-exact header search
over the complete unallocated stream. It does not state that these files never
existed, and it does not state that no evidence exists.

The 18 TAR candidates are the 18 matching binary lines in
`derived/recovery/unallocated.blk`, located as line/byte-offset pairs:
`3452062/204907619`, `3453018/205098662`, `3453112/205114273`,
`3453176/205133417,205133470`, `3453528/205222938`,
`3455006/205630710`, `3455081/205655797`, `3457740/206344460`,
`3457744/206346477`, `3457748/206348509`, `3457753/206351177`,
`3457754/206351702`, `3457755/206352221`, `3457793/206357104`,
`3457892/206372904,206373016`, `3457937/206382382,206382666`,
`3457964/206393590` and `3458734/206587579`. The paired offsets occur
on the same candidate line. Every candidate was rejected for the same explicit
reason: it is generic `ustar` magic in the 204.9–206.6 MB region, outside the
Father recovery cluster, with no Father member path or archive name in the
exhaustive companion searches. The one ELF candidate is at stream offset
7,991,296 and was rejected because its header differs from the installed
library. The four `Makefile` candidates are filesystem blocks 243750 and 256026
(Debian package descriptions listing `Makefile` as a supported language) and
491840 and 491841 (a libgcrypt copyright/changelog record); each is unrelated
to Father.

Scalpel was deliberately not run. A narrow configuration relevant to these
named targets would start from the same generic ELF or `ustar` signatures
already enumerated above, without improving attribution. Given the bounded
recovery scope, another signature-carving pass had no demonstrated incremental
value. This is a scope decision, not a claim that Scalpel could recover no
additional bytes.

**Timeline (Plaso).** `filestat` covers the surviving artefacts with four rows
each: `/etc/ld.so.preload`, `/usr/lib/selinux.so.3`, `/tmp/forensic-lab`,
`…/father_ldpreload`, `…/probe` and `…/probe/__malicious_file`. There is no
`filestat` row for any deleted target, and `bash_history` matches zero lines
across the complete canonical export — expected, because a path-based collection
filter selects only files present at collection time. Plaso records no literal
deletion event for any cleanup target.

Its decisive contribution is the journal. `sudo` records preserve the deleted
source tree's full identity as the working directory of three privileged
commands: at 14:27:09.894247 `PWD=/tmp/forensic-lab/father_ldpreload/Father-4eb2712caf612a7dc55fd4f34ff5c72b74c7c332 ;
COMMAND=/usr/bin/install -m 0644 …`, at 14:27:09.951565
`COMMAND=/usr/bin/tee /etc/ld.so.preload`, and at 14:27:09.970722
`COMMAND=/usr/bin/systemctl restart ssh.service`, each with `TTY=pts/0`. The
restart is then visible directly: `sshd[458] Received signal 15; terminating` at
14:27:09.974971 and `sshd[754] Server listening on 0.0.0.0 port 22` at
14:27:09.997618. From 14:27:10.440 the journal fills with `ERROR: ld.so: object
'/lib/selinux.so.3' from /etc/ld.so.preload cannot be preloaded` emitted by
snap-confined `lxd.activate` processes — a mount-namespace resolution failure,
not evidence of an absent library, and a strikingly loud side effect of the
technique that names both Father paths in the clear.

**Memory (Volatility 3).** Discovery began from an anomaly rather than ground
truth: aggregating every shallow `/usr/lib` or `/lib` shared-object mapping in
`linux.proc.Maps` yields only three distinct libraries, of which
`/usr/lib/selinux.so.3` alone has no packaging provenance. It is mapped by
`sshd` PID 754 and `sh` PID 756, five segments each, carrying **inode 17435** —
the same inode as the disk artefact, and the same PID 754 the journal recorded
starting at 14:27:09.997618. `linux.pslist` shows PID 756 as a direct child of
PID 754 with UID/EUID 0 and **GID/EGID 1337**; `linux.psaux` gives PID 756
`/bin/sh` and PID 754 `sshd: /usr/sbin/ss` (truncated by the plugin, not treated
as a path). `linux.sockstat` shows one ESTABLISHED TCP connection,
`192.168.100.41:22` ↔ `192.168.100.1:54321`, socket object `156763311287232`;
its five FD rows (sshd FD 5, sh FDs 0/1/2/5) deduplicate to a single connection.

Negatives that matter: `linux.bash` returned **0 rows** — the interactive
`labuser` shell had exited before capture, so this says nothing about disk
state; `linux.lsmod` lists 14 baseline modules and none belonging to Father,
the correct negative for a userland technique the plugin cannot observe; and
`linux.malfind` flagged two RWX regions, in `networkd-dispat` PID 368 and
`unattended-upgr` PID 446, both rejected — neither maps the library, neither is
parented by `sshd`, and Father is file-backed rather than injected.

## 4. Cross-source reconstruction and coverage

Supported sequence, grouped into phases. Times are UTC and come from guest-side
journal and inode evidence, never from host bookkeeping. No deletion time is
asserted, because no source observed one:

1. **Session and staging** (`14:27:07`–`09.4`): `sshd` accepts publickey logins
   for `labuser`; the staging tree is created under `/tmp/forensic-lab`.
2. **Build** (`≈09.4`–`09.89`): Father's sources are compiled; the surviving
   assembler intermediates at blocks 589852–589861 and the recovered
   `config.h` at block 589851 are the residue of this phase.
3. **Install** (`09.89`–`09.90`): `sudo install` places the library at its
   Father default path (inode 17435, crtime 14:27:09.890920012); the hidden file
   follows (inode 258185, 14:27:09.898920012).
4. **Activation** (`09.95`–`09.99`): `sudo tee /etc/ld.so.preload`, then
   `systemctl restart ssh.service`; the old `sshd` takes SIGTERM and PID 754
   begins listening.
5. **Cleanup (scenario validation only; not timed):** the archive, the source
   tree and the history file are removed. No forensic source observed the
   removals themselves.
6. **At acquisition** (memory): PID 754 and root `sh` PID 756 live with the
   library mapped and one established port-54321 connection.

Coverage is scored against the inventory frozen **before** any evidence mapping
(2026-07-24T15:26:11Z): the eleven calibration targets M01–M11, unchanged, plus
three cleanup targets C01–C03. Applicability was fixed from source capability,
not tool success. This is **manual evidence-recovery coverage** — a descriptive
post-mortem measure of what manual analysis recovered, not detection accuracy.

| Target | FS | TL | MEM | Accepted locators (current run / workspace) | Limitation |
|---|---|---|---|---|---|
| M01 source archive staged | not obs | not obs | n/a | — | no entry, inode or content survives |
| M02 source/build tree extracted | obs | obs | n/a | FS block 589851 (recovered `config.h`), blocks 589852/589856/589861; TL journal `PWD=…/Father-4eb2712…` 14:27:09.894247 | tree's own dirent/inode gone |
| M03 modified `config.h` applied | obs | not obs | n/a | FS block 589851, `recovered-config.h` SHA-256 `d14ebf96…0ad4` | inode and timestamps unrecoverable |
| M04 `rk.so` built | partial | not obs | n/a | FS inode 17435 (Father ELF) + blocks 589855/589856 (GCC intermediates calling `lpe_drop_shell@PLT`) | compilation/output supported; deleted `rk.so` not recovered |
| M05 library installed/mapped | obs | obs | obs | FS inode 17435 row 18164; TL `filestat` ×4 + journal `install` 14:27:09.894247; `proc.Maps` PID 754/756 inode 17435 | mapping not hashed in memory |
| M06 `/etc/ld.so.preload` configured | obs | obs | n/a | FS inode 17436 row 2143; TL journal `tee` 14:27:09.951565 | inode timestamps do not date the activation (§5) |
| M07 controlled hidden file created | obs | obs | n/a | FS inode 258185 row 2297; TL `filestat` ×4 | — |
| M08 interactive command activity | not obs | partial | n/a | TL journal three `sudo` records with `TTY=pts/0`, `PWD`, full `COMMAND` | only privileged commands; no history file; no times for the rest |
| M09 privileged shell parented by `sshd` | n/a | n/a | obs | `pslist` PID 756 PPID 754, UID/EUID 0, GID/EGID 1337 | — |
| M10 established backdoor connection | n/a | n/a | obs | `sockstat` socket `156763311287232`, `:22`↔`:54321` | 5 FDs → 1 connection |
| M11 SSH restart during activation | n/a | obs | n/a | TL journal 14:27:09.974971 / 14:27:09.997618 | — |
| C01 archive cleanup | not obs | not obs | n/a | — | not recovered by the bounded method |
| C02 source/build-tree cleanup | obs | partial | n/a | FS inode 258151 mtime/ctime vs child crtime, plus deallocated content at blocks 589851–589861; TL `filestat` on inode 258151 | metadata times an entry change; no source proves a deletion event |
| C03 Bash-history cleanup | not obs | not obs | n/a | — | not recovered by the bounded method |

| Source | Found / Total | Coverage (DR) | FP | TTD | QoR |
|---|---|---|---|---|---|
| Filesystem | 7 / 11 | 63.6% | 23 | 0 s (1 s resolution) | High |
| Timeline | 7 / 12 | 58.3% | N/A | 12 s | Medium |
| Memory | 3 / 3 | 100% | 2 | 1 min 16 s | High |
| Union | 11 / 14 | 78.6% | 25 case-wide | 0 s (1 s resolution) | N/A |

Filesystem FP counts the 23 candidates surfaced by candidate-generating
unallocated signature/string searches and rejected above: 18 `ustar` output
lines, one ELF header and four `Makefile` matches. Timeline FP is `N/A` because
only targeted lookups were used, which generate no candidates. Memory FP is the
two rejected `malfind` rows: PID 368 and PID 446 neither maps the Father library
nor is parented by `sshd`, and Father is file-backed rather than an injected RWX
region. The case-wide FP is 25: the disjoint 23 filesystem and two memory
candidates, counted once each; targeted lookups are excluded. TTD was recorded
prospectively from each source start to its first accepted locator. Union
coverage counts unique targets found in at least one source over unique targets
expected in at least one source; per-source rates are never averaged, and no
aggregate union QoR is assigned.

## 5. Limitations and conclusion

Four limitations shape everything above.

*Host bookkeeping is not execution time.* The 19 `command_log.jsonl` entries are
spaced roughly 20 ms apart, including across `make father`, whose transcript
shows ten `gcc` invocations. Those timestamps, and the manifest's scenario
interval derived from the same clock, order what ran but cannot date it. Every
time in §4 is guest-side.

*The preload file differs from the scenario's explicit write; the cause is
inferred.* The activation command emits 18 bytes including a newline; inode
17436 holds 17 bytes without one, and its crtime is 14:27:12.834920012 UTC —
about 2.9 s after the journal timed the `tee`. The acquired file was therefore
created or rewritten after that explicit write. The recovered `config.h`
defines `INSTALL_LOCATION "/lib/selinux.so.3" // used for reinstallation` and
`PRELOAD "ld.so.preload" // used for hiding`, and the installed library exports
file-operation hooks. Those facts make Father's internal reinstallation path a
plausible mechanism, but they do not demonstrate that the path executed, which
process invoked it, or that shutdown caused it. The causal mechanism remains
analyst inference requiring dynamic analysis. The practical consequence is
unchanged: inode 17436's timestamps do not date M06.

*The acquisition metadata does not demonstrate memory/shutdown overlap.* At the
run revision, the orchestrator awaited `acquire_memory()`, then ran the
pre-shutdown callback, and only then requested guest shutdown. The
`dumps/acquisition.json` timestamp was recorded after hashing, while
`acquisition_seconds` measured the preceding dump command; subtracting one from
the other does not reconstruct the dump start. The guest's 14:27:12.483947
power-off record therefore cannot establish overlap or justify calling the
snapshot a teardown snapshot. The memory findings remain valid because the
affected processes, mapping and connection are present. Separate engineering
follow-up: future runs should record explicit dump-command start and completion
timestamps.

*Graceful power-off limits journal recovery.* The clean-unmount finding and
empty journal are consistent with checkpoint/reset during graceful shutdown.
They explain why the bounded `ext4magic` journal pass had no historical
transactions to use, but do not prove that the acquisition policy alone caused
the negative. Recovery succeeded because attributable block content remained
unallocated and intact.

The cleanup treatment achieved its narrow purpose against directory-entry
evidence and against two of the three content targets: no deleted entry survived
for any of the five staging objects, and neither the uploaded archive nor the
built `rk.so` nor `.bash_history` was recovered by the bounded method. It failed
against everything else. The deleted, edited `src/config.h` was recovered
complete and verified byte-for-byte, exposing the rootkit's magic GID, trigger
port, password, hidden-file prefix and reinstallation path; the build residue
still names Father's own source files; and the system's own record-keeping was
never touched, so the journal preserved the deleted tree's exact path, the
privileged commands that built and installed the library, and the service
restart that activated it, while memory preserved the running consequence.
Naive `rm` on a quiet filesystem removes names far more reliably than it removes
content — and it removes neither the logs nor the running process.
