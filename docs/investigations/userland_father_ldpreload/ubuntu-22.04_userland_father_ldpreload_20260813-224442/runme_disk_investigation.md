---
cwd: ../../../..
shell: bash
---

# Father disk investigation

__Run:__ `ubuntu-22.04_userland_father_ldpreload_20260813-224442`

Read-only filesystem examination of the accepted disk image with The Sleuth
Kit, following the `LD_PRELOAD` persistence path from `/etc/ld.so.preload`
outward and then recovering the deleted staging object `/tmp/rk.so` from the
ext4 journal. Every evidence read addresses the volume by its sector offset
(`-o`) on the accepted EWF, so nothing is mounted and no partition copy sits
between the tool and the source. A few utilities used only to *characterise a
failure* (`extundelete`, `debugfs`) cannot read EWF; they run against the
read-only extracted partition `derived/disk/root-partition.ext4` (same volume
ID, disclosed at the point of use), never as the evidentiary read path. Derived
output is written under the ignored analyst workspace
`shared/investigations/<run_id>/derived/disk/`; only the bounded portion useful
to the educational point is shown here.

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
mkdir -p "$INV_DIR"
ls "$RUN_DIR/dumps/disk"
```

**Output**

The accepted EWF segments (`evidence_disk.E01/.E02`) and the acquisition status
files are present. `dumps/acquisition.json` records `ewfverify 20240506` exit 0
over SHA-256 `f12d21e3…159ad` at acquisition time; the analysis never writes to
these files.

## Partition layout: what `mmls` can and cannot tell us

```bash
mmls "$DISK" | tee "$INV_DIR/d-00-mmls.txt"
```

**Output**

```text {"ignore":"true"}
GUID Partition Table (EFI)
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
006:  000       0000227328   0020971486   0020744159
```

The `Description` column is **blank** for all three real partitions. That is not
a tool failure: for a GPT disk `mmls` fills that column from each entry's
optional free-text partition-name field, which this cloud image leaves empty,
and the type GUID is not rendered here. The table gives layout only. The single
clue is size — slot 000 holds 20,744,159 sectors (~9.9 GiB) against 8,192 and
217,088 — which makes it the *candidate* root volume, not a proven one.

## Filesystem identity: what `fsstat` adds

```bash
OFFSET="227328"
export OFFSET="$OFFSET"
fsstat -o "$OFFSET" "$DISK" | tee "$INV_DIR/d-00-fsstat.txt" | head -14
```

**Output**

```text {"ignore":"true"}
File System Type: Ext4
Volume Name: cloudimg-rootfs
Volume ID: 63cfa1aafe94fe86d74a94f237ba9d70
Last Mounted at: 2026-08-13 22:44:34 (CEST)
Unmounted properly
Last mounted on: /
```

`mmls` reads the **partition table**, which describes layout; `fsstat` reads the
**filesystem superblock** at the partition's own offset, which describes content
— `Ext4`, volume `cloudimg-rootfs`, last mounted on `/`, and `Unmounted
properly`. Naming the filesystem requires reading inside the partition, not the
table that locates it. The clean-unmount flag also matters for recovery below:
the image was acquired after a controlled power-off, so cached writes reached
stable storage before acquisition. From here every TSK command addresses the
volume through `-o "$OFFSET"` on the accepted EWF directly.

## Preload configuration: the technique-led entry point

```bash
# /etc/ld.so.preload is the first thing an LD_PRELOAD case should read.
PRELOAD_INODE=$(ifind -o "$OFFSET" -n /etc/ld.so.preload "$DISK")
export PRELOAD_INODE="$PRELOAD_INODE"
echo "ld.so.preload = inode $PRELOAD_INODE"
icat -o "$OFFSET" "$DISK" "$PRELOAD_INODE" | tee "$INV_DIR/d-01-ld.so.preload"; echo
```

**Output**

```text {"ignore":"true"}
ld.so.preload = inode 74210
/lib/selinux.so.3
```

`/etc/ld.so.preload` (inode `74210`) contains the single entry
`/lib/selinux.so.3`, a mimic of a system library. On Ubuntu `/lib` is a symlink
to `/usr/lib`, so it resolves to `/usr/lib/selinux.so.3`.

## Installed library identity by hash

```bash
LIB_INODE=$(ifind -o "$OFFSET" -n /usr/lib/selinux.so.3 "$DISK")
export LIB_INODE="$LIB_INODE"
icat -o "$OFFSET" "$DISK" "$LIB_INODE" | sha256sum
grep -o '"sha256": "[0-9a-f]*"' "$RUN_DIR/manifest.json" | head -1
```

**Output**

```text {"ignore":"true"}
87fece49fc15a48372a1ba76cf424755f9cfab6cce7e8073002757f7db2f0711  -
"sha256": "87fece49fc15a48372a1ba76cf424755f9cfab6cce7e8073002757f7db2f0711"
```

The installed `/usr/lib/selinux.so.3` (inode `74172`, 32,784 B, root-owned) has
SHA-256 `87fece49…0711`, byte-for-byte equal to the manifest's prebuilt `rk.so`
input. Static ELF inspection of the object (`icat … | strings`) exposes Father
hook symbols (`o_accept`, `o_readdir`, `o_open`, `o_execve`, `o_lxstat`,
`o_unlink`), the backdoor routines (`backconnect`, `lpe_drop_shell`,
`falsify_tcp`) and strings (`AUTHENTICATE:`, `ld.so.preload`, `/bin/sh`,
`Enjoy the shell!`, `__malicious_`). This characterises **capability** — the
concealment and backdoor are statically present — but it does not prove a hook
executed; that is the memory notebook's contribution.

## Concealable file visible offline

```bash
fls -o "$OFFSET" -r -p "$DISK" | grep -E 'tmp/__malicious_file|usr/lib/selinux.so.3|etc/ld.so.preload'
CONCEAL_INODE=$(ifind -o "$OFFSET" -n /tmp/__malicious_file "$DISK")
istat -o "$OFFSET" "$DISK" "$CONCEAL_INODE" | grep -E 'size|uid'
```

**Output**

```text {"ignore":"true"}
r/r 74210:	etc/ld.so.preload
r/r 74173:	tmp/__malicious_file
r/r 74172:	usr/lib/selinux.so.3
size: 0
uid / gid: 1000 / 1000
```

`/tmp/__malicious_file` (inode `74173`) is fully visible in the dead image even
though the `readdir` interposition hides it on the live system. It is an empty
file (`size: 0`, an `owner` `touch`), so no content hash is available; identity
here is metadata-only. The filename matches the disclosed `__malicious_` prefix
— a posterior validation of a file first found by technique, not a selector.

## Anti-forensic IOC: the self-healed preload file

```bash
# The survivor's own metadata, read straight from the volume.
istat -o "$OFFSET" "$DISK" "$PRELOAD_INODE" | sed -n '/size/p;/Inode Times/,/Created/p'
echo -n "survivor bytes: "; icat -o "$OFFSET" "$DISK" "$PRELOAD_INODE" | wc -c
echo -n "final byte: "; icat -o "$OFFSET" "$DISK" "$PRELOAD_INODE" | tail -c1 | xxd | cut -d' ' -f2
```

**Output**

```text {"ignore":"true"}
size: 17
Accessed:	2026-08-13 22:44:46.476 (CEST)
File Modified:	2026-08-13 22:44:46.472 (CEST)
Inode Modified:	2026-08-13 22:44:46.472 (CEST)
File Created:	2026-08-13 22:44:46.472 (CEST)
survivor bytes: 17
final byte: 33
```

The surviving `/etc/ld.so.preload` is **17 bytes** ending in `0x33` (`3`) — the
string `/lib/selinux.so.3` with **no trailing newline** — and all four MAC times
fall on the single second `20:44:46`. The scenario operator wrote the file with
`printf '%s\n' /lib/selinux.so.3 | tee` (auth.log, next section, `20:44:43`),
which emits **18 bytes** (17 + `\n`). The survivor therefore is *not* the
operator's write: it is 1 byte shorter, newline-free, and stamped ~3 s later at
the power-off second (auth.log `Powering Off` at `20:44:46`, below). A 17-byte,
newline-free rewrite at shutdown is exactly the output of Father's own
`src/exec.c` regeneration path (`fprintf(f, INSTALL_LOCATION)`, no newline). The
most-parsimonious reading is that the rootkit regenerated its own preload entry;
the exact trigger is not proven from disk alone. This sharpens the timeline
notebook's observation that the preload MAC time mis-orders the activation chain
— the offset is not clock skew but a second writer.

## Anti-forensic cleanup, from disk

```bash
# Principal logs are examined here per the guidelines; broad temporal
# correlation is the timeline notebook's job (Plaso not run here).
AUTH_INODE=$(ifind -o "$OFFSET" -n /var/log/auth.log "$DISK")
icat -o "$OFFSET" "$DISK" "$AUTH_INODE" | tee "$INV_DIR/d-08-auth.log" \
  | grep -E 'rk\.so|Powering Off' | grep '20:44:4'
```

**Output**

```text {"ignore":"true"}
Aug 13 20:44:43 lab-ubuntu-22 sudo:  labuser : ... COMMAND=/usr/bin/install -m 0644 /tmp/rk.so /lib/selinux.so.3
Aug 13 20:44:46 lab-ubuntu-22 systemd-logind[616]: Powering Off...
```

`auth.log` proves `/tmp/rk.so` **existed**: the sudo'd `install … /tmp/rk.so …`
is recorded, but the later `rm /tmp/rk.so` is not, because it was not privileged.
Command history was wiped by the cleanup (`history -c`; `rm` of the history
file), so no `.bash_history` survives for the operator account:

```bash
ifind -o "$OFFSET" -n /home/labuser/.bash_history "$DISK"
```

**Output**

```text {"ignore":"true"}
File not found
```

`/home/labuser/.bash_history` resolves to no live inode (a bounded negative: the
wipe succeeded). The command *text* is still recoverable from the home-directory
journal but carries no `#<epoch>` lines, so it fixes order, not per-command time;
that is discussed under M08 in the case summary. What the victim briefly
held and then deleted was the uploaded `/tmp/rk.so`; recovering it is the rest of
this notebook.

## Deleted-file recovery — identifying the target

```bash
# fls reports no live or deleted directory entry for rk.so anywhere.
fls -o "$OFFSET" -rd "$DISK" 2>/dev/null | grep 'rk\.so' || echo "(no live or deleted rk.so entry)"
# The ext4 journal (jbd2, inode 8) still holds committed copies of the /tmp
# directory block. Extract it once, then locate the copy that names rk.so.
icat -o "$OFFSET" "$DISK" 8 > "$INV_DIR/d-03-journal.bin"
grep -abo 'rk.so' "$INV_DIR/d-03-journal.bin" | awk -F: '{print "journal block " int($1/4096)}'
```

**Output**

```text {"ignore":"true"}
(no live or deleted rk.so entry)
journal block 832
```

The live filesystem retains **no** trace of `rk.so`: `fls -rd` finds neither a
live nor an orphaned directory entry. The journal does. Journal block `832` is a
committed image of the `/tmp` directory block (fs block `16758`) that still names
`rk.so`. Reading two successive committed copies gives the deletion *event*:

```bash
# jcat reads a journal block by number, straight from the EWF.
echo "--- committed copy at journal block 832 (rk.so present) ---"
jcat -o "$OFFSET" "$DISK" 832 | strings -a | grep -E 'rk\.so|__malicious_file'
echo "--- next committed copy at journal block 863 (rk.so gone) ---"
jcat -o "$OFFSET" "$DISK" 863 | strings -a | grep -E 'rk\.so|__malicious_file'
```

**Output**

```text {"ignore":"true"}
--- committed copy at journal block 832 (rk.so present) ---
rk.so
__malicious_file
--- next committed copy at journal block 863 (rk.so gone) ---
__malicious_file
```

Decoding the directory entry in the earlier copy gives `rk.so`'s inode:

```bash
jcat -o "$OFFSET" "$DISK" 832 > "$INV_DIR/d-04-tmpdir-with-rk.bin"
# 8-byte ext4 dirent header (inode, rec_len, name_len, file_type); find rk.so.
python3 - "$INV_DIR/d-04-tmpdir-with-rk.bin" <<'PY'
import struct,sys
b=open(sys.argv[1],'rb').read(); o=0
while o < len(b)-8:
    ino,rlen,nl,ft = struct.unpack('<IHBB', b[o:o+8])
    if rlen < 8: break
    if b[o+8:o+8+nl] in (b'rk.so', b'__malicious_file'):
        print(f"{b[o+8:o+8+nl].decode():16s} inode {ino}")
    o += rlen
PY
```

**Output**

```text {"ignore":"true"}
rk.so            inode 74171
__malicious_file inode 74173
```

`/tmp/rk.so` was **inode 74171**, staged next to the implant (`74172`) and the
concealable file (`74173`). The journal thus fixes both the deletion **event**
(present in one committed directory image, absent in the next) and the deleted
object's **identity** — before any content is recovered.

## Why metadata undelete fails here

```bash
# Point the standard tools at inode 74171 as it exists now.
istat -o "$OFFSET" "$DISK" 74171 | grep -E 'Allocated|size'
ffind -o "$OFFSET" "$DISK" 74171
```

**Output**

```text {"ignore":"true"}
Allocated
size: 31720832
/var/cache/apt/pkgcache.bin
```

Inode `74171` is **allocated to a different, live file** — the ~30 MB
`/var/cache/apt/pkgcache.bin`, which `apt` regenerated during the seconds between
the `rm` and power-off and which claimed the just-freed inode number. On unlink
ext4 zeroes the extent header of the freed inode; the number is then quickly
recycled. So any *metadata/inode-keyed* undelete recovers the wrong object:

```bash
# extundelete cannot read EWF; run it on the read-only extracted partition.
RAW="$INV_DIR/root-partition.ext4"
( cd "$INV_DIR" && rm -rf eu && mkdir eu && cd eu \
  && extundelete "../root-partition.ext4" --restore-file tmp/rk.so ) 2>&1 | tail -3
ls "$INV_DIR/eu/RECOVERED_FILES/" 2>&1
```

**Output**

```text {"ignore":"true"}
Loading journal descriptors ... 5415 descriptors loaded.
double free or corruption (!prev)          # glibc heap abort (message varies)
ls: cannot access '.../RECOVERED_FILES/': No such file or directory
```

`extundelete` aborts with a glibc heap error (the exact message varies between
runs) on the recycled inode's inconsistent metadata and recovers nothing for
`rk.so`; no `RECOVERED_FILES` directory is produced. `ext4magic` metadata mode
likewise keys on the reused inode. This is the documented, expected ext4
limitation: **inode-based undelete does not survive inode reuse**. The recovery
has to come from the data the journal preserved, not from the current inode.

## Journal recovery — the deleted content

The journal kept `rk.so`'s inode-table block (fs block `4924`, holding inode
`74171`) as it stood *before* the unlink. Two standard tools misreport it, which
is itself worth recording: TSK `jls` maps these committed blocks as `FS Block
Unknown`, and `debugfs -R "logdump -i <74171>"` computes the inode's location as
block `4622` where `imap` gives `4924`, so it finds nothing. The committed copy
is located by scanning the extracted journal for the pre-delete image of inode
`74171` (a 32,784-byte regular file), then read back from the EWF with `jcat`:

```bash
# Locate the journal block whose inode-74171 slot is a 32,784-byte regular file.
python3 - "$INV_DIR/d-03-journal.bin" <<'PY'
import struct,sys
b=open(sys.argv[1],'rb').read(); BS=4096
for jb in range(len(b)//BS):
    o=jb*BS+2560                      # inode 74171 slot within fs block 4924
    mode,=struct.unpack('<H',b[o:o+2]); size,=struct.unpack('<I',b[o+4:o+8])
    magic,=struct.unpack('<H',b[o+40:o+42])
    if mode==0x81b4 and size==32784 and magic==0xf30a:
        eblk,elen,shi,slo=struct.unpack('<IHHI',b[o+52:o+64])
        print(f"journal block {jb}: rk.so inode intact -> {elen} blocks at phys {(shi<<32)|slo}")
        break
PY
```

**Output**

```text {"ignore":"true"}
journal block 827: rk.so inode intact -> 9 blocks at phys 1015842
```

The journaled inode still carries `rk.so`'s original single extent: **9 blocks
starting at physical block 1015842**. Those blocks were freed by the unlink but
not overwritten, and — unlike the inode number — not reused:

```bash
blkstat -o "$OFFSET" "$DISK" 1015842 | grep -iE 'Allocated'
blkcat -o "$OFFSET" "$DISK" 1015842 1 | head -c4 | xxd            # ELF magic?
blkcat -o "$OFFSET" "$DISK" 1015842 9 | head -c 32784 | tee "$INV_DIR/d-06-rk.so.recovered" | sha256sum
```

**Output**

```text {"ignore":"true"}
Not Allocated
00000000: 7f45 4c46                                .ELF
1015842..1015850 → 32,784 bytes → 87fece49fc15a48372a1ba76cf424755f9cfab6cce7e8073002757f7db2f0711
```

`blkstat` confirms the data blocks are **unallocated** (free but intact);
`blkcat` reads a valid ELF and the recovered 32,784 bytes hash to
`87fece49…0711`. That is byte-for-byte the installed implant (inode `74172`) and
the manifest input. **The deleted staging object `/tmp/rk.so` is the Father
implant**, recovered from its own residual data using the block pointer the
journal preserved — no live inode or ground-truth path was used to reach it.

Carving is a viable but weaker alternative here: because the blocks survive in
unallocated space, `blkls -A` plus a magic carver would find the ELF *header*,
but ELF has no reliable trailer, so a magic-only carve cannot bound the file's
length. The journal supplies the exact start block and size, which is why it —
not carving — is the reliable recovery on this image.

## Recovery affordance (disclosed)

This content recovery depends on `rk.so`'s data and metadata having reached
stable storage *before* the unlink. The runner performs an explicit `sync`
immediately before deleting the file (`command_log.jsonl`: `sync` at
`20:44:43.702`, `rm` at `20:44:43.723`) precisely to make the residual evidence
deterministic. Without that flush the sub-second staging window is shorter than
the ext4 commit interval, and dirty pages of a file unlinked before writeback may
never be written at all, so both the journaled inode and the residual data would
be racy. This is a disclosed laboratory affordance, not a property a real `rm`
guarantees. The *techniques* shown — journal directory-entry history, journal
inode recovery, and residual-block hashing — are standard and transfer to any
case where the deleted data reached disk (as it also does here through the clean
pre-acquisition power-off, `fsstat: Unmounted properly`).
