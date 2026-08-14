---
cwd: ../../../..
shell: bash
---

# Diamorphine (LKM) memory investigation

__Run:__ `ubuntu-22.04_kernel_diamorphine_20260813-224854`

Kernel-memory examination with Volatility 3 (2.28.0), ISF for kernel
`5.15.0-179-generic`. The case distinguishes two claims: that the module is
loaded and hidden, and that an active hook is demonstrable. Discovery starts from
the module list, not scenario ground truth.

## Case paths and integrity

```bash
RUN_ID="ubuntu-22.04_kernel_diamorphine_20260813-224854"
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

The memory image hashes to `75edc2d3…0446`, matching the acquisition sidecar.

## Module hiding: discrepancy between views

```bash
vol3 -q -f "$MEM" -s shared/isf linux.lsmod > "$INV_DIR/dk-lsmod.txt"
grep -c '' "$INV_DIR/dk-lsmod.txt"; grep -i diamorphine "$INV_DIR/dk-lsmod.txt" || echo 'not in lsmod'
vol3 -q -f "$MEM" -s shared/isf linux.check_modules > "$INV_DIR/dk-check_modules.txt"
vol3 -q -f "$MEM" -s shared/isf linux.hidden_modules > "$INV_DIR/dk-hidden_modules.txt"
vol3 -q -f "$MEM" -s shared/isf linux.modxview > "$INV_DIR/dk-modxview.txt"
grep -i diamorphine "$INV_DIR/dk-modxview.txt"
```

**Output**

`lsmod` enumerates 57 modules and does not include Diamorphine. `check_modules`
and `hidden_modules` both find a `diamorphine` module resident at offset
`0xffffc0b620c0` (code size `0x4000`, taints `OOT_MODULE,UNSIGNED_MODULE`).
`modxview` shows `diamorphine` with *In procfs* `False`, *In sysfs* `True`,
*In scan* `True` — unlinked from the module list but present in sysfs and
findable by scanning. It is the only hidden module. This proves an unsigned
out-of-tree module is loaded and deliberately hidden from ordinary enumeration.

## Limit: the active hook is not demonstrated

```bash
vol3 -q -f "$MEM" -s shared/isf linux.check_syscall > "$INV_DIR/dk-check_syscall.txt"
grep -E 'getdents|sys_kill' "$INV_DIR/dk-check_syscall.txt"
vol3 -q -f "$MEM" -s shared/isf linux.tracing.ftrace.CheckFtrace > "$INV_DIR/dk-ftrace.txt"
grep -c '' "$INV_DIR/dk-ftrace.txt"
```

**Output**

The syscall-table entries for `getdents` (78), `getdents64` (217) and `kill` (62)
point to the normal kernel symbols (`__x64_sys_getdents64` at `0xffff8cdbc1c0`,
`__x64_sys_kill` at `0xffff8cadc920`), not into the module range `0xffffc0b6…`:
no entry is redirected. `CheckFtrace` reports no installed `ftrace_ops`. Within
the available methods, memory does not expose the active hook mechanism behind
the scenario-validated file hiding and signal-64 escalation. Module hiding is
proven; the active hook is not. This is recorded as a bounded negative rather
than inferred from scenario success.
