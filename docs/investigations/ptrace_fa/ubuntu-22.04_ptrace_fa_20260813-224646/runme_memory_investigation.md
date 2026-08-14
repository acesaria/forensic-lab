---
cwd: ../../../..
shell: bash
---

# ptrace foreign-allocation memory investigation

__Run:__ `ubuntu-22.04_ptrace_fa_20260813-224646`

Memory-led examination of the accepted image with Volatility 3 (2.28.0), ISF for
kernel `5.15.0-179-generic`. The technique — `ptrace` foreign-allocation
shellcode injection into a live process — is memory-resident, so memory is the
dominant source. Discovery starts from `malfind`, not scenario ground truth.

## Case paths and integrity

```bash
RUN_ID="ubuntu-22.04_ptrace_fa_20260813-224646"
export RUN_ID="$RUN_ID"
RUN_DIR="shared/experiments/$RUN_ID"
export RUN_DIR="$RUN_DIR"
INV_DIR="shared/investigations/$RUN_ID/derived/memory"
export INV_DIR="$INV_DIR"
MEM="$RUN_DIR/dumps/memory/mem.raw"
export MEM="$MEM"
sha256sum "$MEM" | cut -d' ' -f1
grep -o '"sha256": "[0-9a-f]*"' "$RUN_DIR/dumps/acquisition.json" | head -1
```

**Output**

The memory image hashes to `9f8852bf…8231`, matching the acquisition sidecar.
Analysis is read-only.

## Injected executable region (technique-led entry point)

```bash
vol3 -q -f "$MEM" -s shared/isf linux.malfind > "$INV_DIR/p-malfind.txt"
grep -E '^[0-9]+' "$INV_DIR/p-malfind.txt" | awk '{print $1,$2,$5,$6,$7}'
vol3 -q -f "$MEM" -s shared/isf linux.proc.Maps --pid 1044 > "$INV_DIR/p-maps-1044.txt"
grep 'Anonymous' "$INV_DIR/p-maps-1044.txt" | grep 'r-x'
```

**Output**

`malfind` flags an anonymous executable page in process `victim` (PID 1044).
`proc.Maps` locates it at `0x7f5864d1d000–0x7f5864d1e000` (one page, `r-x`,
Anonymous Mapping). A normal process's executable code is file-backed; an
anonymous executable page is the expected artefact of a `ptrace`-injected foreign
allocation. `malfind` also flags `rwx` anonymous regions in unrelated system
daemons `networkd-dispat` (611) and `unattended-upgr` (659); see rejection below.

## Target process, child shell, reverse shell

```bash
vol3 -q -f "$MEM" -s shared/isf linux.pslist > "$INV_DIR/p-01-pslist.txt"
vol3 -q -f "$MEM" -s shared/isf linux.pstree > "$INV_DIR/p-pstree.txt"
vol3 -q -f "$MEM" -s shared/isf linux.sockstat > "$INV_DIR/p-sockstat.txt"
grep -E '\b1044\b|\b1046\b' "$INV_DIR/p-01-pslist.txt"
grep '0x8d050965abc0' "$INV_DIR/p-sockstat.txt" | head -1
```

**Output**

PID 1044 (`./victim`, UID 1000) is still present — the target **survived** the
injection. `pstree` shows a child PID 1046 `sh` (UID 1000) created ~22 ms later.
`sockstat` shows PID 1046 holding an established TCP connection
`192.168.100.32:54032` → `192.168.100.1:4444` (socket `0x8d050965abc0`) on FDs
0/1/2/3 — stdin/stdout/stderr redirected to the socket, the reverse-shell
signature. Listener port 4444 and UID 1000 (`labuser`) match the scenario facts,
confirming identity after technique-led discovery.

## Rejected candidates and bounded scope

**Output**

The `rwx` regions in PID 611 and 659 are selected candidates then rejected: they
hold no reverse-shell socket, have no child shell, and belong to long-running
system daemons whose `rwx` regions are a common `malfind` false positive
(2 rejected candidates). Cold sources are bounded context: the injection is
memory-resident and establishes no persistence, so no durable filesystem
equivalent of the chain exists; disk/timeline were not examined in depth for this
memory-dominant run. This is a declared scope decision, not hidden absence.
