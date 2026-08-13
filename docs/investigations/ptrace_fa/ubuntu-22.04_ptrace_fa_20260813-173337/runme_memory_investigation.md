---
cwd: ../../../..
shell: bash
---

# ptrace_fa memory investigation — Runme notebook

__Run:__ `ubuntu-22.04_ptrace_fa_20260813-173337`

**Scope:** RAM-led manual examination of P02 and P05-P08 using process,
mapping, socket, injection-candidate, and active-ptrace views. Full outputs are
retained beneath this run's `shared/investigations/.../derived/memory/` tree.

## M-00 - Case boundary and integrity

```bash {"name":"M-00-Case-Boundary","promptEnv":"never"}
set -euo pipefail

RUN_ID='ubuntu-22.04_ptrace_fa_20260813-173337'
RUN_DIR="shared/experiments/$RUN_ID"
INV_DIR="shared/investigations/$RUN_ID"
MANIFEST="$RUN_DIR/manifest.json"
ACQUISITION="$RUN_DIR/dumps/acquisition.json"
MEMORY_IMAGE="$RUN_DIR/dumps/memory/mem.raw"
ISF='shared/isf/ubuntu_5.15.0-179-generic.json'
VOL="$(command -v vol3)"
EXAM_DIR="$INV_DIR/derived/memory/examination"

jq -e --arg run "$RUN_ID" '
  .run_id == $run and .scenario_id == "ptrace_fa"
  and .status == "completed" and .scenario_status == "completed"
  and .repository.commit == "aef7d0015bbcd1a87f051e16f4fe722f73507993-dirty"
' "$MANIFEST" >/dev/null
jq -e --arg run "$RUN_ID" '
  .run_id == $run and .memory_image.commands[0].status == "completed"
  and .disk_preparation == "powered_off"
  and .disk_image.verification.status == "completed"
' "$ACQUISITION" >/dev/null
[[ "$(stat -c '%s' "$MEMORY_IMAGE")" == "$(jq -er '.memory_image.size_bytes' "$ACQUISITION")" ]]
[[ "$(sha256sum "$MEMORY_IMAGE" | cut -d' ' -f1)" == "$(jq -er '.memory_image.sha256' "$ACQUISITION")" ]]
[[ "$(sha256sum "$ISF" | cut -d' ' -f1)" == '0b573a2095f6a6f18f4262bcbd537a6d49d28653150bafe20408827f24ba91cc' ]]

mkdir -p "$EXAM_DIR"
export MEMORY_IMAGE ISF VOL EXAM_DIR
printf 'run=%s\nrevision=%s\nmemory_size=%s\nmemory_sha256=%s\nisf_sha256=%s\n' \
  "$RUN_ID" "$(jq -r '.repository.commit' "$MANIFEST")" \
  "$(stat -c '%s' "$MEMORY_IMAGE")" "$(jq -r '.memory_image.sha256' "$ACQUISITION")" \
  "$(sha256sum "$ISF" | cut -d' ' -f1)"
```

**Output**

```text {"ignore":"true"}
run=ubuntu-22.04_ptrace_fa_20260813-173337
revision=aef7d0015bbcd1a87f051e16f4fe722f73507993-dirty
memory_size=2147747795
memory_sha256=7ea955ff92217f5eb9331f4cd8c98eaeb0d2f505b14a81b7d22ff47687c3ca76
isf_sha256=0b573a2095f6a6f18f4262bcbd537a6d49d28653150bafe20408827f24ba91cc
```

The memory size/hash and target-kernel ISF hash matched. The dirty revision is
the disclosed human-approved deadline exception, not a clean-provenance claim.

## M-01 - Process structure: pstree, pslist, psscan

The initial selection asks which live shell has structurally unusual parentage;
it does not search for the planted scenario PID.

```bash {"name":"M-01-Process-Structure","promptEnv":"never"}
set -euo pipefail

PSTREE="$EXAM_DIR/m-01-pstree.txt"
PSLIST="$EXAM_DIR/m-01-pslist.txt"
PSSCAN="$EXAM_DIR/m-01-psscan.txt"
[[ -s "$PSTREE" ]] || "$VOL" -q -f "$MEMORY_IMAGE" -s "$(dirname "$ISF")" linux.pstree.PsTree >"$PSTREE"
[[ -s "$PSLIST" ]] || "$VOL" -q -f "$MEMORY_IMAGE" -s "$(dirname "$ISF")" linux.pslist.PsList >"$PSLIST"
[[ -s "$PSSCAN" ]] || "$VOL" -q -f "$MEMORY_IMAGE" -s "$(dirname "$ISF")" linux.psscan.PsScan >"$PSSCAN"

grep -B1 -A1 -E $'\t(1042|1044)\t' "$PSTREE"
grep -E $'\t(1042|1044)\t' "$PSLIST"
grep -E $'\t(1042|1043|1044)\t' "$PSSCAN"
```

**Output**

```text {"ignore":"true"}
* 0x8b7cca15a000  1042  1042  1     victim
** 0x8b7cca158000 1044  1044  1042  sh
0x8b7cca15a000 1042 1042 1    victim 1000 1000 1000 1000 2026-08-13 15:33:37.521134 UTC Disabled
0x8b7cca158000 1044 1044 1042 sh     1000 1000 1000 1000 2026-08-13 15:33:37.542701 UTC Disabled
0xa15a000 1042 1042 1    victim           TASK_RUNNING
0xa15c000 1043 1043 1028 shellcode_injec EXIT_DEAD
0xa158000 1044 1044 1042 sh               TASK_RUNNING
```

**P05 observed.** PID 1044 `sh` is parented by PID 1042 `victim`; both use
UID/GID 1000 and were created about 22 ms apart. `psscan` also retains the
exited injector PID 1043, but execution outcome is established by the live
child/mapping/socket chain rather than that name.

## M-02 - Command lines

```bash {"name":"M-02-Command-Lines","promptEnv":"never"}
set -euo pipefail

PSAUX="$EXAM_DIR/m-02-psaux.txt"
[[ -s "$PSAUX" ]] || "$VOL" -q -f "$MEMORY_IMAGE" -s "$(dirname "$ISF")" linux.psaux.PsAux --pid 1042 1044 >"$PSAUX"
cat "$PSAUX"
```

**Output**

```text {"ignore":"true"}
PID  PPID  COMM    ARGS
1042 1     victim  ./victim
1044 1042  sh
```

The victim argument is recovered; the shell ARGS field is empty. That limits
invocation detail but does not negate the process relationship.

## M-03 - Socket state

```bash {"name":"M-03-Sockets","promptEnv":"never"}
set -euo pipefail

SOCKSTAT="$EXAM_DIR/m-03-sockstat.txt"
[[ -s "$SOCKSTAT" ]] || "$VOL" -q -f "$MEMORY_IMAGE" -s "$(dirname "$ISF")" linux.sockstat.Sockstat --pids 1042 1044 >"$SOCKSTAT"
cat "$SOCKSTAT"
```

**Output**

```text {"ignore":"true"}
NetNS      Process Name PID  TID  FD Sock Offset    Family  Type   Proto Source Addr    Source Port Destination Addr Destination Port State       Filter
4026531840 sh           1044 1044 0  0x8b7cc444d780 AF_INET STREAM TCP   192.168.100.32 38876       192.168.100.1   4444             ESTABLISHED -
4026531840 sh           1044 1044 1  0x8b7cc444d780 AF_INET STREAM TCP   192.168.100.32 38876       192.168.100.1   4444             ESTABLISHED -
4026531840 sh           1044 1044 2  0x8b7cc444d780 AF_INET STREAM TCP   192.168.100.32 38876       192.168.100.1   4444             ESTABLISHED -
4026531840 sh           1044 1044 3  0x8b7cc444d780 AF_INET STREAM TCP   192.168.100.32 38876       192.168.100.1   4444             ESTABLISHED -
```

**P08 observed.** FDs 0-3 share one socket object and therefore one
established connection, not four connections. PID 1042 has no socket row.

## M-04 - Process mappings

```bash {"name":"M-04-Process-Maps","promptEnv":"never"}
set -euo pipefail

MAPS="$EXAM_DIR/m-04-maps.txt"
[[ -s "$MAPS" ]] || "$VOL" -q -f "$MEMORY_IMAGE" -s "$(dirname "$ISF")" linux.proc.Maps --pid 1042 >"$MAPS"
grep -F '/tmp/forensic-lab/ptrace_fa/victim' "$MAPS"
grep -F 'Anonymous Mapping' "$MAPS" | grep -F $'r-x\t'
```

**Output**

```text {"ignore":"true"}
1042 victim 0x558359916000 0x558359917000 r-- 0x0    252 1 258131 /tmp/forensic-lab/ptrace_fa/victim Disabled
1042 victim 0x558359917000 0x558359918000 r-x 0x1000 252 1 258131 /tmp/forensic-lab/ptrace_fa/victim Disabled
1042 victim 0x558359918000 0x558359919000 r-- 0x2000 252 1 258131 /tmp/forensic-lab/ptrace_fa/victim Disabled
1042 victim 0x558359919000 0x55835991a000 r-- 0x2000 252 1 258131 /tmp/forensic-lab/ptrace_fa/victim Disabled
1042 victim 0x55835991a000 0x55835991b000 rw- 0x3000 252 1 258131 /tmp/forensic-lab/ptrace_fa/victim Disabled
1042 victim 0x7f3f67547000 0x7f3f67548000 r-x 0x0 0 0 0 Anonymous Mapping Disabled
```

The live process maps the same path/inode identified by disk D-02. One
anonymous executable mapping is present at `0x7f3f67547000`.

## M-05 - malfind candidates and injected bytes

```bash {"name":"M-05-Malfind","promptEnv":"never"}
set -euo pipefail

MALFIND="$EXAM_DIR/m-05-malfind.txt"
[[ -s "$MALFIND" ]] || "$VOL" -q -f "$MEMORY_IMAGE" -s "$(dirname "$ISF")" linux.malfind.Malfind >"$MALFIND" 2>"$EXAM_DIR/m-05-malfind.stderr"
grep -E $'^[0-9]+\t' "$MALFIND" | grep -E 'Anonymous Mapping|/[a-z]' | cut -f1-6
awk '/^1042\tvictim\t0x7f3f67547000/{p=1} p{print; if (/^0x7f3f6754703c/) exit}' "$MALFIND"
```

**Output**

```text {"ignore":"true"}
611  networkd-dispat 0x7f8166114000 0x7f8166115000 Anonymous Mapping                    rwx
665  unattended-upgr 0x7f230ec15000 0x7f230ec16000 Anonymous Mapping                    rwx
1042 victim           0x7f3f67308000 0x7f3f6749d000 /usr/lib/x86_64-linux-gnu/libc.so.6 r-x
1042 victim           0x7f3f67547000 0x7f3f67548000 Anonymous Mapping                    r-x
1042 victim 0x7f3f67547000 0x7f3f67548000 Anonymous Mapping r-x
90 90 b8 39 00 00 00 0f 05 48 83 f8 00 74 02 cd
03 48 31 f6 48 f7 e6 48 ff c6 6a 02 5f 04 29 0f
05 48 93 52 68 c0 a8 64 01 66 68 11 5c 66 6a 02
48 89 df 48 89 e6 6a 10 5a 6a 2a 58 0f 05 48 31
0x7f3f67547002: mov eax, 0x39
0x7f3f67547007: syscall
0x7f3f6754701d: add al, 0x29
0x7f3f6754701f: syscall
0x7f3f6754703b: pop rax
0x7f3f6754703c: syscall
```

Four candidates were reviewed. The two unrelated loader-adjacent RWX pages
and the named libc mapping are rejected as distinct injected-region
candidates; the libc dirty-page warning remains contextual. The PID 1042
anonymous `r-x` region is accepted because it belongs to the already-selected
chain and agrees with `Maps`. **P06 observed.** These plugins read correlated
VMA state and are not fully independent.

The code bytes show fork (`0x39`), socket (`0x29`), and connect (`0x2a`)
syscall construction. Literal bytes `c0 a8 64 01` and big-endian `11 5c`
decode to `192.168.100.1:4444`, independently matching M-03. **P07 observed.**

## M-06 - Active ptrace relationship

```bash {"name":"M-06-Ptrace","promptEnv":"never"}
set -euo pipefail

PTRACE_OUT="$EXAM_DIR/m-06-ptrace.txt"
[[ -e "$PTRACE_OUT" ]] || "$VOL" -q -f "$MEMORY_IMAGE" -s "$(dirname "$ISF")" linux.ptrace.Ptrace >"$PTRACE_OUT" || true
cat "$PTRACE_OUT"
printf 'rows=%s\n' "$(awk 'NR>3 && NF>0' "$PTRACE_OUT" | wc -l)"
```

**Output**

```text {"ignore":"true"}
Process PID TID Tracer TID Tracee TID Flags
rows=0
```

This is a valid bounded negative: the injector detaches after successful
execution, so zero active relationships does not contradict P05-P08.

## M-07 - Synthesis, limitations, and scenario validation

Memory observes P02 and P05-P08. `psscan` retains the exited injector but no
extra command remnants parented by the shell. `psaux` cannot recover the
shell's arguments. `sockstat` has no victim row. The image is a single
point-in-time snapshot. `malfind` emitted a deprecation warning and a libc
dirty-page warning but completed with valid output; no plugin failed.

Only after selection, manifest facts validate PID 1042, listener
`192.168.100.1:4444`, `labuser`, victim survival, and the still-open reverse
shell. Those are controlled-treatment facts, not forensic discoveries.

**Conclusion:** RAM supports a live victim-to-shell chain, an anonymous
executable code region, an endpoint decoded from those bytes, and a matching
established connection. The empty active-ptrace result is expected after
detach.
