---
cwd: ../../../..
shell: bash
---

# Father memory investigation

__Run:__ `ubuntu-22.04_userland_father_ldpreload_20260813-224442`

Read-only memory examination of the accepted image with Volatility 3 (2.28.0),
ISF for kernel `5.15.0-179-generic`. Discovery starts from a mapping anomaly,
not scenario ground truth. Broad plugin output is saved under
`shared/investigations/<run_id>/derived/memory/`; only the bounded portion is
shown here.

## Case paths and integrity

```bash
RUN_ID="ubuntu-22.04_userland_father_ldpreload_20260813-224442"
export RUN_ID="$RUN_ID"
RUN_DIR="shared/experiments/$RUN_ID"
export RUN_DIR="$RUN_DIR"
INV_DIR="shared/investigations/$RUN_ID/derived/memory"
export INV_DIR="$INV_DIR"
MEM="$RUN_DIR/dumps/memory/mem.raw"
export MEM="$MEM"
# Re-verify the memory hash against the acquisition sidecar before analysis.
sha256sum "$MEM" | cut -d' ' -f1
grep -o '"sha256": "[0-9a-f]*"' "$RUN_DIR/dumps/acquisition.json" | head -1
```

**Output**

The memory image hashes to `4d370432…dab04`, matching the acquisition sidecar.
Analysis is read-only.

## Anomalous library mapping (technique-led entry point)

```bash
grep 'selinux.so.3' "$INV_DIR/m-03-maps-all.txt"
```

**Output**

`linux.proc.Maps` exposes `/usr/lib/selinux.so.3` with **inode 74172** — the
same inode as the on-disk artefact — mapped in two processes, `sshd` PID 1054
and `sh` PID 1056, each with five segments. The disk↔memory inode coincidence
ties the in-RAM mapping to the installed library.

## Process relationship and privileged shell

```bash
grep -E '\b1054\b|\b1056\b' "$INV_DIR/m-02-pslist.txt"
grep -E '1054|1056' "$INV_DIR/m-02-psaux.txt"
```

**Output**

`pslist`/`pstree` place PID 1056 as a child of PID 1054; `psaux` gives the
command lines (PID 1056 `/bin/sh`; PID 1054 rendered `sshd: /usr/sbin/ss`,
truncated and not treated as a full path). PID 1056 is a root shell: UID/EUID 0,
GID/EGID 1337.

## Established backdoor connection

```bash
grep '0x8b3849b03480' "$INV_DIR/m-04-sockstat-all.txt"
```

**Output**

`linux.sockstat` shows one established TCP connection
`192.168.100.32:22` ↔ `192.168.100.1:54321` (socket object `0x8b3849b03480`)
shared by PID 1054 (FD 5) and PID 1056 (FDs 0/1/2/5); the FD rows deduplicate to
a single connection. The client port 54321 matches the scenario facts,
confirming identity after technique-led discovery.

## Negatives that are results

```bash
wc -l "$INV_DIR/m-06-bash.txt"
```

**Output**

`linux.bash` returns no command rows, while the disk retains history text: the
absence is of the memory source within its bound, not of the system. No memory
mapping was extracted and hashed, so the library-identity hash equality remains
a disk finding, not a memory one.
