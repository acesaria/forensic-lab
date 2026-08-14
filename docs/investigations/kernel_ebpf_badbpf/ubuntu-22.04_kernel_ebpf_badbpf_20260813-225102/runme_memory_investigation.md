---
cwd: ../../../..
shell: bash
---

# Bad-BPF (eBPF) memory investigation

__Run:__ `ubuntu-22.04_kernel_ebpf_badbpf_20260813-225102`

Kernel/memory examination with Volatility 3 (2.28.0), ISF for kernel
`5.15.0-179-generic`. Discovery starts from the process list and eBPF program
enumeration, not from planted names.

## Case paths and integrity

```bash
RUN_ID="ubuntu-22.04_kernel_ebpf_badbpf_20260813-225102"
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

The memory image hashes to `e2bc1d74…0abaa`, matching the acquisition sidecar.

## Hidden worker visible in kernel memory

```bash
vol3 -q -f "$MEM" -s shared/isf linux.pslist > "$INV_DIR/bb-pslist.txt"
vol3 -q -f "$MEM" -s shared/isf linux.psaux  > "$INV_DIR/bb-psaux.txt"
grep -E '\b1053\b|\b1058\b|\b1060\b' "$INV_DIR/bb-pslist.txt"
grep -E '\b1058\b|\b1060\b' "$INV_DIR/bb-psaux.txt"
```

**Output**

`pslist` shows PID 1053 `comm=kworker/u8:2` (Volatility walks the kernel task
list, so the pidhide `/proc` filter does not hide it). `psaux` shows the loader
chain `sudo -n nohup stdbuf … /tmp/.xcrypto/pidhide --pid-to-hide 1053`
(PID 1058/1059/1060): the mechanism discloses the target PID. The hidden PID is
found from the kernel structure; the planted value only confirms it afterward.

## Identity incoherence

```bash
vol3 -q -f "$MEM" -s shared/isf linux.proc.Maps --pid 1053 > "$INV_DIR/bb-maps-1053.txt"
awk '$5 ~ /x/ && $9 !~ /Anonymous/ {print $1,$5,$9; exit}' "$INV_DIR/bb-maps-1053.txt"
```

**Output**

PID 1053 presents as a kernel thread (`comm kworker/u8:2`) but three memory-read
attributes contradict that: PPID 1 (real kthreads have PPID 2), UID 1000 (kthreads
are UID 0), and it has a user address space — `comm` says `kworker/u8:2`, argv
says `/usr/bin/uptime`, and the executable mapping is `/a` (inode 74173). Real
kernel threads have neither argv nor a file-backed executable. The three identity
views are mutually incoherent; that incoherence is the artefact.

## eBPF mechanism and pool connection

```bash
vol3 -q -f "$MEM" -s shared/isf linux.ebpf > "$INV_DIR/bb-ebpf.txt"
grep 'handle_getdents' "$INV_DIR/bb-ebpf.txt"
vol3 -q -f "$MEM" -s shared/isf linux.sockstat > "$INV_DIR/bb-sockstat.txt"
grep '0x8ddac379c600' "$INV_DIR/bb-sockstat.txt"
```

**Output**

`linux.ebpf` enumerates three `handle_getdents` programs of type
`BPF_PROG_TYPE_TRACEPOINT` (`0xcefa40756000`, `0xcefa40763000`, `0xcefa40754000`)
— an eBPF program hooked on the `getdents` tracepoint is exactly the pidhide
directory-filter mechanism, so memory exposes the tool, not only the effect
(contrast Diamorphine, where the hook was not provable). `sockstat` shows PID 1053
holding an established TCP connection `192.168.100.32:38018` →
`192.168.100.1:3333` (socket `0x8ddac379c600`) to the simulated pool — another
attribute a real `kworker` would not have. Limitation: the eBPF bytecode was not
disassembled, so that these programs filter specifically PID 1053 is consistent
with the chain but not proven by decoding the program.
