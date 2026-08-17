---
cwd: ../../../..
shell: bash
---

# Father disk investigation

__Run:__ `ubuntu-22.04_userland_father_ldpreload_20260813-224442`

Read-only filesystem examination of the accepted disk image with The Sleuth
Kit, following the `LD_PRELOAD` persistence path from `/etc/ld.so.preload`
outward without using scenario ground truth for selection. Every TSK command
addresses the volume by its sector offset (`-o`) on the accepted EWF evidence,
so nothing is mounted and no partition copy sits between the tool and the
source. Derived output is written under the ignored analyst workspace
`shared/investigations/<run_id>/derived/disk/` and only the bounded portion
useful to the educational point is shown here.

## Case paths

```bash
RUN_ID="ubuntu-22.04_userland_father_ldpreload_20260813-224442"
export RUN_ID="$RUN_ID"
RUN_DIR="shared/experiments/$RUN_ID"
export RUN_DIR="$RUN_DIR"
INV_DIR="shared/investigations/$RUN_ID/derived/disk"
export INV_DIR="$INV_DIR"
DISK="$RUN_DIR/dumps/disk/evidence_disk.E01"
export DISK="$DISK"
ls "$RUN_DIR/dumps/disk"
```

**Output**

The accepted EWF segments (`evidence_disk.E01/.E02`) and the acquisition status
files are present. `ewfverify` passed at acquisition time; the analysis never
writes to these files.

## Partition layout: what `mmls` can and cannot tell us

```bash
# mmls reads the partition table only.
mmls "$DISK" | tee "$INV_DIR/d-00-mmls.txt"
```

**Output**

```text {"ignore":"true"}
GUID Partition Table (EFI)
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Safety Table
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  Meta      0000000001   0000000001   0000000001   GPT Header
003:  Meta      0000000002   0000000033   0000000032   Partition Table
004:  013       0000002048   0000010239   0000008192
005:  014       0000010240   0000227327   0000217088
006:  000       0000227328   0020971486   0020744159
007:  -------   0020971487   0020971519   0000000033   Unallocated
```

The `Description` column is **blank** for all three real partitions (slots 013,
014, 000). That is not a tool failure. For a GPT disk `mmls` fills that column
from each entry's optional free-text partition-name field, and this cloud image
leaves it empty; the entry's type GUID is not rendered in this view. So the
table gives layout — where each partition starts and how long it is — and
nothing about content. The only clue is size: slot 000 holds 20,744,159 sectors
(~9.9 GiB) against 8,192 and 217,088 for the other two, which makes it the
candidate root volume, not a proven one.

## Filesystem identity: what `fsstat` adds

```bash
# The largest partition starts at sector 227328; reuse it for every later
# TSK command instead of extracting the partition to a separate file.
OFFSET="227328"
export OFFSET="$OFFSET"
fsstat -o "$OFFSET" "$DISK" | tee "$INV_DIR/d-00-fsstat.txt" | head -12
```

**Output**

```text {"ignore":"true"}
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: Ext4
Volume Name: cloudimg-rootfs
Volume ID: 63cfa1aafe94fe86d74a94f237ba9d70

Last Written at: 2026-05-15 12:56:47 (CEST)
Last Checked at: 2026-05-15 12:55:26 (CEST)

Last Mounted at: 2026-08-13 22:44:34 (CEST)
Unmounted properly
Last mounted on: /
```

This is the pedagogical point: `mmls` reads the **partition table**, which
describes layout only, while `fsstat` reads the **filesystem superblock** at the
partition's own offset, which describes content — here `Ext4`, volume
`cloudimg-rootfs`, last mounted on `/`. Naming the filesystem requires reading
inside the partition, not the table that locates it.

From here on every TSK command addresses the volume through `-o "$OFFSET"` on
the accepted EWF evidence directly. The earlier `d-06-rk.so.recovered` and the
extracted `root-partition.ext4` in the workspace are retained as the derived
views they already are; they are simply no longer the read path.

## Preload configuration, the technique-led entry point

```bash
# /etc/ld.so.preload is the first thing an LD_PRELOAD case should read.
ffind -o "$OFFSET" "$DISK" 74210
icat -o "$OFFSET" "$DISK" 74210 | tee "$INV_DIR/d-01-ld.so.preload"; echo
```

**Output**

```text {"ignore":"true"}
/etc/ld.so.preload
/lib/selinux.so.3
```

`/etc/ld.so.preload` (inode `74210`) contains the single entry
`/lib/selinux.so.3`, a mimic of a system library. On Ubuntu `/lib` is a symlink
to `/usr/lib`, so it resolves to `/usr/lib/selinux.so.3`.

## Installed library identity by hash

```bash
# Read the installed library straight out of the volume and hash it against
# the manifest input; no intermediate extracted copy is needed.
icat -o "$OFFSET" "$DISK" 74172 | sha256sum
grep -o '"sha256": "[0-9a-f]*"' "$RUN_DIR/manifest.json" | head -1
```

**Output**

```text {"ignore":"true"}
87fece49fc15a48372a1ba76cf424755f9cfab6cce7e8073002757f7db2f0711  -
"sha256": "87fece49fc15a48372a1ba76cf424755f9cfab6cce7e8073002757f7db2f0711"
```

The recovered `/usr/lib/selinux.so.3` (inode `74172`, 32,784 B, root-owned) has
SHA-256 `87fece49…0711`, byte-for-byte equal to the manifest's prebuilt `rk.so`
input. The installed library is exactly the object built by the builder. Static
ELF inspection (`d-06-rk.so.extent`) exposes Father hook symbols (`o_accept`,
`o_readdir`, `o_open`, `o_execve`, `o_lxstat`, `o_unlink`), the backdoor routine
(`backconnect`, `lpe_drop_shell`, `falsify_tcp`) and strings (`AUTHENTICATE:`,
`ld.so.preload`, `/bin/sh`). This characterises capability; it does not prove a
hook executed.

## Concealable file visible offline

```bash
# TSK reads ext4 directly and ignores the userland readdir hook.
fls -o "$OFFSET" -r -p "$DISK" | grep -E 'tmp/__malicious_file|usr/lib/selinux.so.3|etc/ld.so.preload'
```

**Output**

```text {"ignore":"true"}
r/r 74210:	etc/ld.so.preload
r/r 74173:	tmp/__malicious_file
r/r 74172:	usr/lib/selinux.so.3
```

`/tmp/__malicious_file` (inode `74173`) is fully visible in the dead image even
though the `readdir` interposition would hide it on the live system. The
filename matches the disclosed `__malicious_` prefix; that is a posterior
validation.

No build staging tree is present under `/tmp`, and none is expected: this
scenario compiles `rk.so` on a **separate builder VM** and uploads only the
finished object to the victim, which the runner then deletes. So the absence of
a source archive, extracted tree, or `config.h` here is a property of the
treatment, not a bounded negative — the case summary records those targets
(M01–M04) as not applicable rather than not observed. What the victim did briefly
hold is the uploaded `/tmp/rk.so`, deleted after a `sync`; recovering that
deleted staging object from unallocated space or the journal was not pursued
within this bounded examination.

## Log context (auth.log)

```bash
# Principal logs are examined here per the guidelines; broad temporal
# correlation is otherwise the timeline notebook's job (Plaso not run here).
# ifind resolves the path to an inode, icat reads it, without mounting.
AUTH_INODE=$(ifind -o "$OFFSET" -n /var/log/auth.log "$DISK")
icat -o "$OFFSET" "$DISK" "$AUTH_INODE" | tee "$INV_DIR/d-08-auth.log" \
  | grep -E 'Aug 13 20:44:4.*(COMMAND=|Received signal 15|listening on 0\.0\.0\.0)'
```

**Output**

```text {"ignore":"true"}
Aug 13 20:44:43 lab-ubuntu-22 sudo:  labuser : TTY=pts/0 ; PWD=/home/labuser ; USER=root ; COMMAND=/usr/bin/install -m 0644 /tmp/rk.so /lib/selinux.so.3
Aug 13 20:44:43 lab-ubuntu-22 sudo:  labuser : TTY=pts/0 ; PWD=/home/labuser ; USER=root ; COMMAND=/usr/bin/tee /etc/ld.so.preload
Aug 13 20:44:43 lab-ubuntu-22 sudo:  labuser : TTY=pts/0 ; PWD=/home/labuser ; USER=root ; COMMAND=/usr/bin/systemctl restart ssh.service
Aug 13 20:44:43 lab-ubuntu-22 sshd[655]: Received signal 15; terminating.
Aug 13 20:44:43 lab-ubuntu-22 sshd[1054]: Server listening on 0.0.0.0 port 22.
Aug 13 20:44:46 lab-ubuntu-22 sshd[1054]: Received signal 15; terminating.
```

`auth.log` dates the activation: at `20:44:43 UTC` `labuser` installs the
library, writes the preload configuration, and runs
`sudo systemctl restart ssh.service`; the old `sshd` (PID 655) receives
`SIGTERM` and a new `sshd` (PID 1054) starts listening on port 22. PID 1054 is
the process that loads the preload library and is later seen in memory. The
three `sudo` records share one `20:44:43` second, so this file orders the chain
only to the second — the sub-second ordering is the timeline notebook's
contribution. The recovered `.bash_history` preserves command text/order only,
with no `#<epoch>` lines, so no per-command execution time can be assigned.
