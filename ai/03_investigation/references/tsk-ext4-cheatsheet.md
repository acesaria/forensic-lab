> **ICM reference — imported, authoritative.** Compact TSK/ext4 command
> reference extracted from an authoritative manual (Sleuth Kit wiki; Carrier,
> *File System Forensic Analysis*, Addison-Wesley 2005). Kept verbatim as a
> reusable operator/agent runbook; no run-specific findings belong here.
>
> **Repo adaptation note.** This project's disk phase examines **EWF (`.E01`)
> images, not raw `disk.dd`**. TSK reads EWF containers directly via libewf,
> so in this repo: (a) omit the explicit `-f linux-ext4` where the notebook
> already relies on autodetection, and (b) pass the E01 path where this sheet
> writes `disk.dd`, with `-o <START_SECTOR>` discovered from `mmls`. Verify
> exact flag spellings (`fls -rd`, `ils -e`, `blkls -e/-s`, `tsk_recover -e`,
> `blkcalc -u`) against the installed TSK version before relying on them.
> See `investigations/father/disk_investigation.ipynb` for the E01-based
> workflow this sheet backs.

# TSK — ext4 Operational Cheatsheet (Linux Only)

**Purpose:** Compact, copy-pasteable reference for low-level ext4 forensics with The Sleuth Kit (TSK).  
**Assumptions:** Linux host, raw image `disk.dd` or block device `/dev/sdX`, ext4 filesystem.  
**Use case:** Embed in ICM config / runbook for AI agents and operators.

---

## 1. Golden Rules

1. **Work on a forensic image, never on the original disk.**  
   ```bash
   dd if=/dev/sdX of=disk.dd bs=4M conv=noerror,sync
   sha256sum disk.dd > disk.dd.sha256
   ```
2. **Identify before you analyze.** Always run `mmls` → `fsstat` → FS tools.  
3. **Never guess offsets.** Every offset comes from `mmls`; every inode from `fls`/`ils`; every block from `istat`/`blkls`.  
4. **Cross-reference:** name (`fls`) ↔ metadata (`istat`) ↔ content (`icat`).  
5. **Log everything.** Redirect all outputs to a case directory.

---

## 2. Core Commands (ext4)

### 2.1 Partition and Filesystem Discovery

```bash
# Partition table → starting sector (offset)
mmls disk.dd

# Filesystem details → block size, journal inode, ranges
fsstat -f linux-ext4 -o <START_SECTOR> disk.dd
```

### 2.2 File Name Layer

```bash
# List all files (recursive, full paths)
fls -f linux-ext4 -o <START_SECTOR> -r -p disk.dd

# List deleted files only (recursive, full paths)
fls -f linux-ext4 -o <START_SECTOR> -r -d -p disk.dd

# Reverse lookup: name from inode
ffind -f linux-ext4 -o <START_SECTOR> disk.dd <INODE>
```

### 2.3 Metadata Layer

```bash
# Inode metadata (times, size, block pointers)
istat -f linux-ext4 -o <START_SECTOR> disk.dd <INODE>

# List all inodes (including deleted/orphaned)
ils -f linux-ext4 -o <START_SECTOR> -e disk.dd

# Find inode owning a specific block
ifind -f linux-ext4 -o <START_SECTOR> -d <BLOCK_NUM> disk.dd
```

### 2.4 Content Extraction

```bash
# Extract file content by inode
icat -f linux-ext4 -o <START_SECTOR> disk.dd <INODE> > recovered_file.ext

# Batch recover all files (allocated + deleted)
tsk_recover -e -f linux-ext4 -o <START_SECTOR> disk.dd ./recovered/
```

### 2.5 Data Unit Layer (Blocks)

```bash
# Dump a single block
blkcat -f linux-ext4 -o <START_SECTOR> disk.dd <BLOCK_NUM>

# Extract all unallocated blocks
blkls -f linux-ext4 -o <START_SECTOR> disk.dd > unalloc.img

# Extract file slack only
blkls -f linux-ext4 -o <START_SECTOR> -s disk.dd > slack.img

# Check block allocation status
blkstat -f linux-ext4 -o <START_SECTOR> disk.dd <BLOCK_NUM>

# Translate block address: blkls stream → original image
blkcalc -f linux-ext4 -o <START_SECTOR> -u <STREAM_BLOCK> disk.dd
```

### 2.6 String Search in Unallocated Space

```bash
# Extract unallocated space
blkls -f linux-ext4 -o <START_SECTOR> disk.dd > unalloc.img

# Search for keyword (strings with decimal byte offset)
strings -t d unalloc.img | grep -i "KEYWORD"
# Example output: 10485760:password=hunter2

# Convert byte offset to block number
# BLOCK_IN_STREAM = BYTE_OFFSET / BLOCK_SIZE (from fsstat)

# Translate to real image block
blkcalc -f linux-ext4 -o <START_SECTOR> -u <BLOCK_IN_STREAM> disk.dd

# View the block
blkcat -f linux-ext4 -o <START_SECTOR> disk.dd <REAL_BLOCK> | less

# Find inode owning the block (if any)
ifind -f linux-ext4 -o <START_SECTOR> -d <REAL_BLOCK> disk.dd
```

### 2.7 Journal Analysis (ext4)

```bash
# Get journal inode from fsstat output
fsstat -f linux-ext4 -o <START_SECTOR> disk.dd | grep -i "journal inode"

# Extract journal
icat -f linux-ext4 -o <START_SECTOR> disk.dd <JOURNAL_INODE> > journal.jbd2

# List journal entries
jls -f linux-ext4 -o <START_SECTOR> disk.dd

# Extract specific journal block
jcat -f linux-ext4 -o <START_SECTOR> disk.dd <JOURNAL_BLOCK> > jblock.raw
```

### 2.8 Timeline Generation

```bash
# Body file from file names
fls -f linux-ext4 -o <START_SECTOR> -r -m / disk.dd > body.fls

# Body file from all inodes (catches orphans)
ils -f linux-ext4 -o <START_SECTOR> -e -m disk.dd > body.ils

# Combine and generate timeline
cat body.fls body.ils > body
mactime -b body -d -y > timeline.csv
```

### 2.9 Signature and Hash Lookups

```bash
# Search for filesystem signatures
sigfind -f linux-ext4 disk.dd

# List supported signature types
sigfind -t list

# Hash lookup (e.g., NSRL)
hfind <HASHSET> <FILE>
```

---

## 3. Worked Example: Recover Deleted File from Unallocated Space

**Scenario:** Keyword `"secret"` found in unallocated space at byte offset `101345`.

```bash
# 1. Get block size from fsstat
fsstat -f linux-ext4 -o 2048 disk.dd | grep "Block Size"
# Output: Block Size: 4096

# 2. Calculate block number in stream
# BLOCK = 101345 / 4096 = 24 (integer division)

# 3. Extract unallocated space
blkls -f linux-ext4 -o 2048 disk.dd > unalloc.img

# 4. Search for keyword
strings -t d unalloc.img | grep -i "secret"
# Output: 98304:secret_data_found

# 5. Convert to block in stream
# 98304 / 4096 = 24

# 6. Translate to real image block
blkcalc -f linux-ext4 -o 2048 -u 24 disk.dd
# Output: 45066

# 7. View the block
blkcat -f linux-ext4 -o 2048 disk.dd 45066 | less

# 8. Find inode owning the block
ifind -f linux-ext4 -o 2048 -d 45066 disk.dd
# Output: 1311

# 9. Get inode metadata
istat -f linux-ext4 -o 2048 disk.dd 1311

# 10. Get filename (if any)
ffind -f linux-ext4 -o 2048 disk.dd 1311
# Output: /home/user/secret.txt

# 11. Recover file
icat -f linux-ext4 -o 2048 disk.dd 1311 > secret.txt
```

---

## 4. ext4-Specific Caveats

1. **Deleted files lose block pointers.** On ext4, deletion zeroes the inode's extent tree. `istat` shows size/times, but `icat` on the deleted inode usually returns nothing.  
   **Escalation:** journal → carving (`blkls` + `photorec`/`foremost`) → `ext4magic`/`extundelete`.

2. **Journal is critical.** Pre-deletion inode copies (with intact block pointers) often exist in the journal. Always check `jls`/`jcat` before declaring a file unrecoverable.

3. **Slack space matters.** The tail of the last block of a file (`blkls -s`) often contains fragments of previously deleted data.

4. **Timestamps.** ext4 `istat` shows `crtime` (created), `mtime` (content modified), `ctime` (inode changed), `atime` (accessed). Record timezone with `mactime -z <TZ>`.

---

## 5. Quick Reference Table

| Goal | Command |
|------|---------|
| Partition layout | `mmls disk.dd` |
| Filesystem info | `fsstat -f linux-ext4 -o <OFFSET> disk.dd` |
| List files (all) | `fls -f linux-ext4 -o <OFFSET> -r -p disk.dd` |
| List deleted files | `fls -f linux-ext4 -o <OFFSET> -r -d -p disk.dd` |
| Inode metadata | `istat -f linux-ext4 -o <OFFSET> disk.dd <INODE>` |
| Filename from inode | `ffind -f linux-ext4 -o <OFFSET> disk.dd <INODE>` |
| Extract file content | `icat -f linux-ext4 -o <OFFSET> disk.dd <INODE> > file.ext` |
| Batch recover | `tsk_recover -e -f linux-ext4 -o <OFFSET> disk.dd ./outdir/` |
| Unallocated blocks | `blkls -f linux-ext4 -o <OFFSET> disk.dd > unalloc.img` |
| Slack space | `blkls -f linux-ext4 -o <OFFSET> -s disk.dd > slack.img` |
| Block to inode | `ifind -f linux-ext4 -o <OFFSET> -d <BLOCK> disk.dd` |
| Address translation | `blkcalc -f linux-ext4 -o <OFFSET> -u <STREAM_BLOCK> disk.dd` |
| Timeline | `fls -m` + `ils -m` → `mactime -b body -d -y > timeline.csv` |
| Journal extraction | `icat` journal inode → `jls`/`jcat` |

---

## 6. References

- Sleuth Kit Wiki — FS Analysis: http://wiki.sleuthkit.org/index.php?title=FS_Analysis  
- TSK Tool Overview: http://wiki.sleuthkit.org/index.php?title=TSK_Tool_Overview  
- Carrier, Brian. *File System Forensic Analysis*. Addison-Wesley, 2005.
