---
cwd: ../../../..
shell: bash
---

# Father cleanup memory investigation — Runme notebook

__Run:__ `ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919`

**Scope:** manual post-mortem examination of the acquired RAM image.

> [!IMPORTANT]
> Run cells in order from the repository root and in one Runme terminal. The
> RAM image, ISF, raw `vol3.json`, acquisition record and raw-extraction record
> are immutable. New output belongs only beneath this case's
> `shared/investigations/.../derived/memory/` directory.

Forensic observation, analyst interpretation and disclosed scenario validation
remain separate. Complete broad outputs are retained as derived files; the
notebook displays the process inventory, native-filtered results and small
bounded views.

## M-00 - Case boundary and integrity verification

**Question:** Is the authoritative RAM image sufficiently identified and
verified for examination?

This is a read-only analyst check, not a new acquisition. The acquisition
authority records `memory_image.verification=null`, so the hash comparison below
does not retroactively claim acquisition-time verification.

```bash {"name":"M-00-Case-Boundary-and-Integrity","promptEnv":"never"}
set -euo pipefail

RUN_ID='ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919'
RUN_DIR="shared/experiments/$RUN_ID"
INV_DIR="shared/investigations/$RUN_ID"
MANIFEST="$RUN_DIR/manifest.json"
ACQUISITION="$RUN_DIR/$(jq -er '.artifacts.acquisition_manifest' "$MANIFEST")"
RAW_STATUS="$RUN_DIR/$(jq -er '.artifacts.raw_extraction_status' "$MANIFEST")"

jq -e --arg run "$RUN_ID" '
  .run_id == $run
  and .scenario_id == "userland_father_ldpreload_cleanup"
  and .status == "completed"
' "$MANIFEST" >/dev/null
jq -e --arg run "$RUN_ID" '
  .run_id == $run
  and .memory_image.commands[0].status == "completed"
  and .memory_image.verification == null
' "$ACQUISITION" >/dev/null
jq -e --arg run "$RUN_ID" '
  .run_id == $run
  and .volatility.status == "completed"
  and (.volatility.invocations | all(.[]; .status == "completed"))
' "$RAW_STATUS" >/dev/null

MEMORY_IMAGE="$(jq -er '.memory_image.path' "$ACQUISITION")"
ISF="$(jq -er '.volatility.isf.path' "$RAW_STATUS")"
VOL="$(command -v vol3)"
VOLATILITY_OUTPUT="$(jq -er '.volatility.output.path' "$RAW_STATUS")"
EXAM_DIR="$INV_DIR/derived/memory/examination"

[[ "$(stat -c '%s' "$MEMORY_IMAGE")" == "$(jq -er '.memory_image.size_bytes' "$ACQUISITION")" ]]
[[ "$(sha256sum "$MEMORY_IMAGE" | cut -d' ' -f1)" == "$(jq -er '.memory_image.sha256' "$ACQUISITION")" ]]
[[ "$(sha256sum "$ISF" | cut -d' ' -f1)" == "$(jq -er '.volatility.isf.sha256' "$RAW_STATUS")" ]]
[[ "$(sha256sum "$VOLATILITY_OUTPUT" | cut -d' ' -f1)" == "$(jq -er '.volatility.output.sha256' "$RAW_STATUS")" ]]

mkdir -p "$EXAM_DIR"
export MEMORY_IMAGE="$MEMORY_IMAGE"
export ISF="$ISF"
export VOL="$VOL"
export EXAM_DIR="$EXAM_DIR"

printf 'run=%s\n' "$RUN_ID"
printf 'manifest=%s\nacquisition_authority=%s\nraw_extraction_authority=%s\n' \
  "$MANIFEST" "$ACQUISITION" "$RAW_STATUS"
printf 'memory=%s\nmemory_size=%s\nmemory_sha256=%s\n' \
  "$MEMORY_IMAGE" "$(stat -c '%s' "$MEMORY_IMAGE")" \
  "$(jq -r '.memory_image.sha256' "$ACQUISITION")"
printf 'memory_image.verification=null\n'
printf 'isf=%s\nisf_sha256=%s\n' "$ISF" "$(jq -r '.volatility.isf.sha256' "$RAW_STATUS")"
printf 'volatility_output=%s\nvolatility_output_sha256=%s\n' \
  "$VOLATILITY_OUTPUT" "$(jq -r '.volatility.output.sha256' "$RAW_STATUS")"
printf 'volatility=%s %s; all recorded invocations completed\n' \
  "$(jq -r '.volatility.tool' "$RAW_STATUS")" "$(jq -r '.volatility.version' "$RAW_STATUS")"
printf 'examination_directory=%s\n' "$EXAM_DIR"
```

**Output**

```text {"ignore":"true"}
run=ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919
manifest=shared/experiments/ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919/manifest.json
acquisition_authority=shared/experiments/ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919/dumps/acquisition.json
raw_extraction_authority=shared/experiments/ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919/analysis/raw_extraction_status.json
memory=/home/anto/linux-multisource-dfir-lab/shared/experiments/ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919/dumps/memory/mem.raw
memory_size=2147747795
memory_sha256=55384f72f923c38c77a1994feb87c019a155999f9a161ae4afac4a917ea2b5ad
memory_image.verification=null
isf=/home/anto/linux-multisource-dfir-lab/shared/isf/ubuntu_5.15.0-1095-kvm.json
isf_sha256=e083c9c6c9dc8c951f90811c060751ae25c07bba700d9ed4ff846fc69b19e4de
volatility_output=/home/anto/linux-multisource-dfir-lab/shared/experiments/ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919/analysis/vol3.json
volatility_output_sha256=89382f4a098dfd9bad37b6969c12542a73fb224d2092f6c9fd108e60449175cc
volatility=volatility3 2.28.0; all recorded invocations completed
examination_directory=shared/investigations/ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919/derived/memory/examination
```

**Assessment:** The manifest, acquisition sidecar and raw-extraction sidecar
agree on the run. RAM size and SHA-256, ISF SHA-256 and raw Volatility-output
SHA-256 matched their recorded values. M-00 establishes the case boundary only;
it makes no claim about Father activity.

## M-01 - Process inventory with pslist, psscan and pstree

**Question:** What process structures are visible, and which process chain
warrants bounded follow-up?

`pslist` walks active linked tasks and supplies credentials and creation times.
`psscan` has different scan semantics and also exposes exited remnants. `pstree`
presents the PPID hierarchy, making a parent-child relationship easier to read;
because it derives that hierarchy from process parent data, it is not wholly
independent corroboration of `pslist` parentage.

```bash {"name":"M-01-Process-Inventory","promptEnv":"never"}
set -euo pipefail

PSLIST="$EXAM_DIR/m-01-pslist.txt"
PSSCAN="$EXAM_DIR/m-01-psscan.txt"
PSTREE="$EXAM_DIR/m-01-pstree.txt"

[[ -s "$PSLIST" ]] || "$VOL" -q -f "$MEMORY_IMAGE" -s "$(dirname "$ISF")" linux.pslist >"$PSLIST"
[[ -s "$PSSCAN" ]] || "$VOL" -q -f "$MEMORY_IMAGE" -s "$(dirname "$ISF")" linux.psscan >"$PSSCAN"
[[ -s "$PSTREE" ]] || "$VOL" -q -f "$MEMORY_IMAGE" -s "$(dirname "$ISF")" linux.pstree.PsTree >"$PSTREE"

cat "$PSTREE"
```

**Output**

```text {"ignore":"true"}
Volatility 3 Framework 2.28.0

OFFSET (V)	PID	TID	PPID	COMM

0x8daf80891700	1	1	0	systemd
* 0x8daf819ddc00	112	112	1	systemd-journal
* 0x8daf81af0000	132	132	1	systemd-fsckd
* 0x8daf819c8000	167	167	1	multipathd
* 0x8daf819cc500	171	171	1	systemd-udevd
* 0x8daf84528000	273	273	1	systemd-timesyn
* 0x8daf81af9700	324	324	1	systemd-network
* 0x8daf8452ae00	326	326	1	systemd-resolve
* 0x8daf81afc500	358	358	1	cron
* 0x8daf86ad5c00	359	359	1	dbus-daemon
* 0x8daf8689dc00	366	366	1	irqbalance
* 0x8daf80a09700	367	367	1	networkd-dispat
* 0x8daf846dae00	369	369	1	rsyslogd
* 0x8daf846ddc00	372	372	1	snapd
* 0x8daf846d9700	373	373	1	systemd-logind
* 0x8daf846e0000	384	384	1	agetty
* 0x8daf8b9cc500	405	405	1	systemd-hostnam
* 0x8daf8b9cdc00	413	413	1	unattended-upgr
* 0x8daf844bc500	423	423	1	polkitd
* 0x8daf846f1700	570	570	1	systemd-timedat
* 0x8daf80a24500	619	619	1	systemd
** 0x8daf8d449700	620	620	619	(sd-pam)
* 0x8daf846d8000	708	708	1	sshd
** 0x8daf8d718000	759	759	708	sshd
* 0x8daf8179dc00	711	711	1	sshd
** 0x8daf8d71ae00	806	806	711	sshd
* 0x8daf8d71dc00	877	877	1	sshd
** 0x8daf9b925c00	879	879	877	sh
0x8daf80894500	2	2	0	kthreadd
* 0x8daf80892e00	3	3	2	rcu_gp
* 0x8daf80895c00	4	4	2	rcu_par_gp
* 0x8daf80890000	5	5	2	slub_flushwq
* 0x8daf808dc500	6	6	2	netns
* 0x8daf808dae00	7	7	2	kworker/0:0
* 0x8daf808ddc00	8	8	2	kworker/0:0H
* 0x8daf808d8000	9	9	2	kworker/u4:0
* 0x8daf808d9700	10	10	2	mm_percpu_wq
* 0x8daf808e2e00	11	11	2	rcu_tasks_trace
* 0x8daf808e5c00	12	12	2	ksoftirqd/0
* 0x8daf808e0000	13	13	2	rcu_sched
* 0x8daf808e1700	14	14	2	migration/0
* 0x8daf808e9700	15	15	2	cpuhp/0
* 0x8daf808ec500	16	16	2	cpuhp/1
* 0x8daf808eae00	17	17	2	migration/1
* 0x8daf808edc00	18	18	2	ksoftirqd/1
* 0x8daf808e8000	19	19	2	kworker/1:0
* 0x8daf808f9700	20	20	2	kworker/1:0H
* 0x8daf808fc500	21	21	2	kdevtmpfs
* 0x8daf808fae00	22	22	2	inet_frag_wq
* 0x8daf808fdc00	23	23	2	kauditd
* 0x8daf808f8000	24	24	2	kworker/0:1
* 0x8daf80a0ae00	25	25	2	oom_reaper
* 0x8daf80a0dc00	26	26	2	writeback
* 0x8daf80a10000	31	31	2	kworker/1:1
* 0x8daf80a2dc00	49	49	2	kblockd
* 0x8daf80a3c500	50	50	2	blkcg_punt_bio
* 0x8daf80a3ae00	51	51	2	tpm_dev_wq
* 0x8daf80a3dc00	52	52	2	ata_sff
* 0x8daf80a38000	53	53	2	kworker/u4:1
* 0x8daf80a39700	54	54	2	kworker/0:1H
* 0x8daf80a18000	55	55	2	kswapd0
* 0x8daf80a1ae00	57	57	2	kthrotld
* 0x8daf80a1c500	58	58	2	nfit
* 0x8daf80a19700	59	59	2	hwrng
* 0x8daf80a1dc00	60	60	2	khvcd
* 0x8daf80a12e00	61	61	2	iscsi_eh
* 0x8daf80a14500	62	62	2	iscsi_conn_clea
* 0x8daf80a11700	63	63	2	mld
* 0x8daf80a15c00	64	64	2	ipv6_addrconf
* 0x8daf80a0c500	65	65	2	kstrp
* 0x8daf81798000	68	68	2	kworker/u5:0
* 0x8daf81799700	69	69	2	jbd2/vda1-8
* 0x8daf8179c500	70	70	2	ext4-rsv-conver
* 0x8daf8179ae00	71	71	2	kworker/0:2
* 0x8daf819cae00	96	96	2	kworker/1:1H
* 0x8daf81afdc00	124	124	2	kworker/1:2
* 0x8daf80a21700	127	127	2	kworker/u4:2
* 0x8daf80a20000	136	136	2	kworker/0:3
* 0x8daf819c9700	165	165	2	kmpathd
* 0x8daf819cdc00	166	166	2	kmpath_handlerd
* 0x8daf80a29700	170	170	2	kworker/u4:3
* 0x8daf81af4500	197	197	2	scsi_eh_0
* 0x8daf81af5c00	199	199	2	scsi_tmf_0
* 0x8daf81af1700	200	200	2	scsi_eh_1
* 0x8daf8689ae00	202	202	2	scsi_tmf_1
* 0x8daf86898000	205	205	2	scsi_eh_2
* 0x8daf86899700	206	206	2	scsi_tmf_2
* 0x8daf8689c500	207	207	2	scsi_eh_3
* 0x8daf868b9700	208	208	2	scsi_tmf_3
* 0x8daf868bc500	209	209	2	scsi_eh_4
* 0x8daf868bae00	210	210	2	scsi_tmf_4
* 0x8daf868bdc00	212	212	2	scsi_eh_5
* 0x8daf868b8000	213	213	2	scsi_tmf_5
* 0x8daf86ad0000	214	214	2	kworker/u4:4
* 0x8daf86ad1700	215	215	2	kworker/u4:5
* 0x8daf86ad4500	216	216	2	kworker/u4:6
* 0x8daf86ad2e00	217	217	2	kworker/u4:7
* 0x8daf81af2e00	226	226	2	kworker/u4:8
* 0x8daf8452dc00	230	230	2	kworker/u4:9
* 0x8daf846e5c00	233	233	2	kworker/u4:10
* 0x8daf844b9700	254	254	2	kworker/u4:11
* 0x8daf8d455c00	591	591	2	kworker/1:3
```

`pslist` records PID 877 `sshd` at `2026-08-05 12:49:20.356698 UTC`
and child PID 879 `sh` at `2026-08-05 12:49:20.398332 UTC`, approximately 42 ms
apart. PID 879 has UID/EUID `0` and GID/EGID `1337`. The short interval is an
observation, not proof that timing alone establishes causality. `psscan` also
contains exited remnants; an exited or scan-only task is not automatically
hidden or malicious.

**Selection:** PID 877 and PID 879 form an unusual root service-to-shell chain
that warrants command-line, socket and library examination without using
scenario facts to select it.

## M-02 - Command-line examination with psaux

**Question:** What command-line arguments remain for the selected processes?

`psaux` adds command-line arguments. It does not replace the task, credential,
scan or hierarchy semantics of `pslist`, `psscan` and `pstree`.

```bash {"name":"M-02-Command-Lines","promptEnv":"never"}
set -euo pipefail

PSAUX="$EXAM_DIR/m-02-psaux.txt"
[[ -s "$PSAUX" ]] || "$VOL" -q -f "$MEMORY_IMAGE" -s "$(dirname "$ISF")" \
  linux.psaux.PsAux --pid 877 879 >"$PSAUX"
cat "$PSAUX"
```

**Output**

```text {"ignore":"true"}
Volatility 3 Framework 2.28.0

PID	PPID	COMM	ARGS

877	1	sshd	sshd: /usr/sbin/ss
879	877	sh	/bin/sh
```

PID 877's command line is visibly truncated and must not be reconstructed from
assumption. The output supports the observed `sshd` → `sh` relationship but
does not explain how the shell was created.

## M-03 - Socket examination with sockstat

**Question:** Which sockets belong to the selected process chain?

```bash {"name":"M-03-Sockets","promptEnv":"never"}
set -euo pipefail

SOCKSTAT="$EXAM_DIR/m-03-sockstat.txt"
[[ -s "$SOCKSTAT" ]] || "$VOL" -q -f "$MEMORY_IMAGE" -s "$(dirname "$ISF")" \
  linux.sockstat.Sockstat --pids 877 879 >"$SOCKSTAT"
cat "$SOCKSTAT"
```

**Output**

```text {"ignore":"true"}
Volatility 3 Framework 2.28.0

NetNS	Process Name	PID	TID	FD	Sock Offset	Family	Type	Proto	Source Addr	Source Port	Destination Addr	Destination Port	State	Filter

4026531840	sshd	877	877	1	0x8daf8d40d540	AF_UNIX	STREAM	-	-	11339	/run/systemd/journal/stdout	10370	ESTABLISHED	-
4026531840	sshd	877	877	2	0x8daf8d40d540	AF_UNIX	STREAM	-	-	11339	/run/systemd/journal/stdout	10370	ESTABLISHED	-
4026531840	sshd	877	877	3	0x8daf86b11a40	AF_INET	STREAM	TCP	0.0.0.0	22	0.0.0.0	0	LISTEN	-
4026531840	sshd	877	877	4	0x8daf8d6ddc80	AF_INET6	STREAM	TCP	::	22	::	0	LISTEN	-
4026531840	sshd	877	877	5	0x8daf8d42bd40	AF_INET	STREAM	TCP	192.168.100.41	22	192.168.100.1	54321	ESTABLISHED	-
4026531840	sh	879	879	0	0x8daf8d42bd40	AF_INET	STREAM	TCP	192.168.100.41	22	192.168.100.1	54321	ESTABLISHED	-
4026531840	sh	879	879	1	0x8daf8d42bd40	AF_INET	STREAM	TCP	192.168.100.41	22	192.168.100.1	54321	ESTABLISHED	-
4026531840	sh	879	879	2	0x8daf8d42bd40	AF_INET	STREAM	TCP	192.168.100.41	22	192.168.100.1	54321	ESTABLISHED	-
4026531840	sh	879	879	5	0x8daf8d42bd40	AF_INET	STREAM	TCP	192.168.100.41	22	192.168.100.1	54321	ESTABLISHED	-
```

PID 877 and PID 879 reference the same socket object `0x8daf8d42bd40` and
the same established tuple, `192.168.100.41:22` →
`192.168.100.1:54321`. Repeated file-descriptor rows for that object are not
separate connections. A shared connection is a point-in-time observation, not
by itself proof of malicious activity or actor identity.

## M-04 - Library enumeration and bounded cached-library recovery

**Question:** Which libraries are associated with the selected chain, and can
the unusual candidate be recovered through the standard page-cache method?

`LibraryList` uses loader/link-map information. `Elfs` enumerates mapped ELF
headers. Similar results are useful correlation but do not make the plugins
identical evidence, and no `Elfs --dump` reconstruction is used.

```bash {"name":"M-04-Library-Enumeration","promptEnv":"never"}
set -euo pipefail

LIBRARIES="$EXAM_DIR/m-04-library-list.txt"
ELFS="$EXAM_DIR/m-04-elfs.txt"

[[ -s "$LIBRARIES" ]] || "$VOL" -q -f "$MEMORY_IMAGE" -s "$(dirname "$ISF")" \
  linux.library_list.LibraryList --pids 877 879 >"$LIBRARIES"
[[ -s "$ELFS" ]] || "$VOL" -q -f "$MEMORY_IMAGE" -s "$(dirname "$ISF")" \
  linux.elfs.Elfs --pid 877 879 >"$ELFS"

cat "$LIBRARIES"
cat "$ELFS"
```

**Output**

```text {"ignore":"true"}
Volatility 3 Framework 2.28.0

Name	Pid	LoadAddress	Path

sshd	877	0x7f8ec197c000	/lib/x86_64-linux-gnu/libresolv.so.2
sshd	877	0x7f8ec194e000	/lib/x86_64-linux-gnu/libtirpc.so.3
sshd	877	0x7f8ec1928000	/lib/x86_64-linux-gnu/libgpg-error.so.0
sshd	877	0x7f8ec1999000	/lib/x86_64-linux-gnu/libkrb5support.so.0
sshd	877	0x7f8ec1990000	/lib/x86_64-linux-gnu/libkeyutils.so.1
sshd	877	0x7f8ec19a7000	/lib/x86_64-linux-gnu/libk5crypto.so.3
sshd	877	0x7f8ec19d6000	/lib/x86_64-linux-gnu/libpcre2-8.so.0
sshd	877	0x7f8ec1bb6000	/lib/x86_64-linux-gnu/liblz4.so.1
sshd	877	0x7f8ec1bab000	/lib/x86_64-linux-gnu/libcap.so.2
sshd	877	0x7f8ec1a6d000	/lib/x86_64-linux-gnu/libgcrypt.so.20
sshd	877	0x7f8ec262f000	/lib64/ld-linux-x86-64.so.2
sshd	877	0x7f8ec1ca7000	/lib/x86_64-linux-gnu/liblzma.so.5
sshd	877	0x7f8ec1bd8000	/lib/x86_64-linux-gnu/libzstd.so.1
sshd	877	0x7f8ec1cd2000	/lib/x86_64-linux-gnu/libcap-ng.so.0
sshd	877	0x7f8ec1cda000	/lib/x86_64-linux-gnu/libnsl.so.2
sshd	877	0x7f8ec1cf4000	/lib/x86_64-linux-gnu/libc.so.6
sshd	877	0x7f8ec1f25000	/lib/x86_64-linux-gnu/libkrb5.so.3
sshd	877	0x7f8ec1f1d000	/lib/x86_64-linux-gnu/libcom_err.so.2
sshd	877	0x7f8ec1ff0000	/lib/x86_64-linux-gnu/libgssapi_krb5.so.2
sshd	877	0x7f8ec20aa000	/lib/x86_64-linux-gnu/libz.so.1
sshd	877	0x7f8ec2070000	/lib/x86_64-linux-gnu/libcrypt.so.1
sshd	877	0x7f8ec2044000	/lib/x86_64-linux-gnu/libselinux.so.1
sshd	877	0x7f8ec2613000	/lib/x86_64-linux-gnu/libwrap.so.0
sshd	877	0x7f8ec25e5000	/lib/x86_64-linux-gnu/libaudit.so.1
sshd	877	0x7f8ec25d3000	/lib/x86_64-linux-gnu/libpam.so.0
sshd	877	0x7f8ec250c000	/lib/x86_64-linux-gnu/libsystemd.so.0
sshd	877	0x7f8ec20c6000	/lib/x86_64-linux-gnu/libcrypto.so.3
sshd	877	0x7f8ec2625000	/lib/selinux.so.3
sh	879	0x7fcc18ba2000	/lib/x86_64-linux-gnu/libc.so.6
sh	879	0x7fcc18ddb000	/lib64/ld-linux-x86-64.so.2
sh	879	0x7fcc18dd1000	/lib/selinux.so.3

Volatility 3 Framework 2.28.0

PID	Process	Start	End	File Path	File Output

877	sshd	0x557086e85000	0x557086e90000	/usr/sbin/sshd	Disabled
877	sshd	0x7f8ec1928000	0x7f8ec192c000	/usr/lib/x86_64-linux-gnu/libgpg-error.so.0.32.1	Disabled
877	sshd	0x7f8ec194e000	0x7f8ec1955000	/usr/lib/x86_64-linux-gnu/libtirpc.so.3.0.0	Disabled
877	sshd	0x7f8ec197c000	0x7f8ec197f000	/usr/lib/x86_64-linux-gnu/libresolv.so.2	Disabled
877	sshd	0x7f8ec1990000	0x7f8ec1992000	/usr/lib/x86_64-linux-gnu/libkeyutils.so.1.9	Disabled
877	sshd	0x7f8ec1999000	0x7f8ec199c000	/usr/lib/x86_64-linux-gnu/libkrb5support.so.0.1	Disabled
877	sshd	0x7f8ec19a7000	0x7f8ec19ab000	/usr/lib/x86_64-linux-gnu/libk5crypto.so.3.1	Disabled
877	sshd	0x7f8ec19d6000	0x7f8ec19d8000	/usr/lib/x86_64-linux-gnu/libpcre2-8.so.0.10.4	Disabled
877	sshd	0x7f8ec1a6d000	0x7f8ec1a7c000	/usr/lib/x86_64-linux-gnu/libgcrypt.so.20.3.4	Disabled
877	sshd	0x7f8ec1bab000	0x7f8ec1bae000	/usr/lib/x86_64-linux-gnu/libcap.so.2.44	Disabled
877	sshd	0x7f8ec1bb6000	0x7f8ec1bb8000	/usr/lib/x86_64-linux-gnu/liblz4.so.1.9.3	Disabled
877	sshd	0x7f8ec1bd8000	0x7f8ec1be2000	/usr/lib/x86_64-linux-gnu/libzstd.so.1.4.8	Disabled
877	sshd	0x7f8ec1ca7000	0x7f8ec1caa000	/usr/lib/x86_64-linux-gnu/liblzma.so.5.2.5	Disabled
877	sshd	0x7f8ec1cd2000	0x7f8ec1cd4000	/usr/lib/x86_64-linux-gnu/libcap-ng.so.0.0.0	Disabled
877	sshd	0x7f8ec1cda000	0x7f8ec1cde000	/usr/lib/x86_64-linux-gnu/libnsl.so.2.0.1	Disabled
877	sshd	0x7f8ec1cf4000	0x7f8ec1d1c000	/usr/lib/x86_64-linux-gnu/libc.so.6	Disabled
877	sshd	0x7f8ec1f1d000	0x7f8ec1f1f000	/usr/lib/x86_64-linux-gnu/libcom_err.so.2.1	Disabled
877	sshd	0x7f8ec1f25000	0x7f8ec1f46000	/usr/lib/x86_64-linux-gnu/libkrb5.so.3.3	Disabled
877	sshd	0x7f8ec1ff0000	0x7f8ec1ffb000	/usr/lib/x86_64-linux-gnu/libgssapi_krb5.so.2.2	Disabled
877	sshd	0x7f8ec2044000	0x7f8ec204a000	/usr/lib/x86_64-linux-gnu/libselinux.so.1	Disabled
877	sshd	0x7f8ec2070000	0x7f8ec2072000	/usr/lib/x86_64-linux-gnu/libcrypt.so.1.1.0	Disabled
877	sshd	0x7f8ec20aa000	0x7f8ec20ac000	/usr/lib/x86_64-linux-gnu/libz.so.1.2.11	Disabled
877	sshd	0x7f8ec20c6000	0x7f8ec2178000	/usr/lib/x86_64-linux-gnu/libcrypto.so.3	Disabled
877	sshd	0x7f8ec250c000	0x7f8ec251f000	/usr/lib/x86_64-linux-gnu/libsystemd.so.0.32.0	Disabled
877	sshd	0x7f8ec25d3000	0x7f8ec25d6000	/usr/lib/x86_64-linux-gnu/libpam.so.0.85.1	Disabled
877	sshd	0x7f8ec25e5000	0x7f8ec25e8000	/usr/lib/x86_64-linux-gnu/libaudit.so.1.0.0	Disabled
877	sshd	0x7f8ec2613000	0x7f8ec2616000	/usr/lib/x86_64-linux-gnu/libwrap.so.0.7.6	Disabled
877	sshd	0x7f8ec2625000	0x7f8ec2627000	/usr/lib/selinux.so.3	Disabled
877	sshd	0x7f8ec262f000	0x7f8ec2631000	/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2	Disabled
877	sshd	0x7f8ec265b000	0x7f8ec2666000	/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2	Disabled
877	sshd	0x7ffd16bd7000	0x7ffd16bd9000	[vdso]	Disabled
879	sh	0x559f57057000	0x559f5705b000	/usr/bin/dash	Disabled
879	sh	0x7fcc18ba2000	0x7fcc18bca000	/usr/lib/x86_64-linux-gnu/libc.so.6	Disabled
879	sh	0x7fcc18dd1000	0x7fcc18dd3000	/usr/lib/selinux.so.3	Disabled
879	sh	0x7fcc18ddb000	0x7fcc18ddd000	/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2	Disabled
879	sh	0x7fcc18e07000	0x7fcc18e12000	/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2	Disabled
879	sh	0x7fff9e7bb000	0x7fff9e7bd000	[vdso]	Disabled
```

The conventional `libselinux.so.1` and unusual `selinux.so.3` are both visible.
LibraryList renders the unusual path as `/lib/selinux.so.3`; Elfs renders it as
`/usr/lib/selinux.so.3` at the same selected-process load addresses. The path
rendering difference is recorded rather than silently normalized.

After selecting that unusual object, the next cell asks `pagecache.Files` for
the exact cached path, then uses only `InodePages` for bounded recovery.

```bash {"name":"M-04-Cached-Library-Recovery","promptEnv":"never"}
set -euo pipefail

M04_DIR="$EXAM_DIR/m-04-library-recovery"
CACHED_PATH='/usr/lib/selinux.so.3'
FILES_RESULT="$M04_DIR/pagecache-files-selinux.txt"
PAGES_RESULT="$M04_DIR/inode-pages.txt"
RECOVERED="$M04_DIR/inode_0x8daf96febcd0.dmp"

mkdir -p "$M04_DIR"
[[ -s "$FILES_RESULT" ]] || "$VOL" -q -f "$MEMORY_IMAGE" -s "$(dirname "$ISF")" \
  linux.pagecache.Files --find "$CACHED_PATH" >"$FILES_RESULT"
cat "$FILES_RESULT"

[[ "$(grep -F $'\tREG\t' "$FILES_RESULT" | grep -F $'\t/usr/lib/selinux.so.3\t' | wc -l)" -eq 1 ]]
[[ -s "$PAGES_RESULT" && -s "$RECOVERED" ]] || "$VOL" -q -o "$M04_DIR" \
  -f "$MEMORY_IMAGE" -s "$(dirname "$ISF")" \
  linux.pagecache.InodePages --find "$CACHED_PATH" --dump >"$PAGES_RESULT"
cat "$PAGES_RESULT"

[[ -s "$M04_DIR/file.txt" ]] || file "$RECOVERED" >"$M04_DIR/file.txt"
[[ -s "$M04_DIR/sha256.txt" ]] || sha256sum "$RECOVERED" >"$M04_DIR/sha256.txt"
[[ -s "$M04_DIR/strings.txt" ]] || strings -a "$RECOVERED" >"$M04_DIR/strings.txt"

sed "s|$M04_DIR/||" "$M04_DIR/file.txt"
printf 'Size: %s bytes\n' "$(stat -c '%s' "$RECOVERED")"
sed "s|$M04_DIR/||" "$M04_DIR/sha256.txt"

printf '\n[disclosed-ground-truth validation strings, after candidate selection]\n'
grep -F -e '/lib/selinux.so.3' -e '__malicious_' -e 'father.c' "$M04_DIR/strings.txt"
```

**Output**

```text {"ignore":"true"}
Volatility 3 Framework 2.28.0

SuperblockAddr	MountPoint	Device	InodeNum	InodeAddr	FileType	InodePages	CachedPages	FileMode	AccessTime	ModificationTime	ChangeTime	FilePath	InodeSize

0x8daf81782800	/	254:1	62345	0x8daf96febcd0	REG	9	9	-rw-r--r--	2026-08-05 12:49:20.557540 UTC	2026-08-05 12:49:20.473540 UTC	2026-08-05 12:49:20.473540 UTC	/usr/lib/selinux.so.3	32784

Volatility 3 Framework 2.28.0

PageVAddr	PagePAddr	MappingAddr	Index	DumpSafe	Flags	Output File

0xe75d40822800	0x208a0000	0x8daf96febe48	0	True	active,dirty,lru,private,referenced,reported,savepinned,slob_free,uptodate	inode_0x8daf96febcd0.dmp
0xe75d40822840	0x208a1000	0x8daf96febe48	1	True	active,dirty,lru,private,referenced,reported,savepinned,slob_free,uptodate	inode_0x8daf96febcd0.dmp
0xe75d40822880	0x208a2000	0x8daf96febe48	2	True	active,dirty,lru,private,referenced,reported,savepinned,slob_free,uptodate	inode_0x8daf96febcd0.dmp
0xe75d408228c0	0x208a3000	0x8daf96febe48	3	True	active,dirty,lru,private,referenced,reported,savepinned,slob_free,uptodate	inode_0x8daf96febcd0.dmp
0xe75d40822900	0x208a4000	0x8daf96febe48	4	True	active,dirty,lru,private,referenced,reported,savepinned,slob_free,uptodate	inode_0x8daf96febcd0.dmp
0xe75d40822940	0x208a5000	0x8daf96febe48	5	True	active,dirty,lru,private,referenced,reported,savepinned,slob_free,uptodate	inode_0x8daf96febcd0.dmp
0xe75d40822980	0x208a6000	0x8daf96febe48	6	True	dirty,lru,private,reported,savepinned,slob_free,uptodate	inode_0x8daf96febcd0.dmp
0xe75d408229c0	0x208a7000	0x8daf96febe48	7	True	dirty,lru,private,reported,savepinned,slob_free,uptodate	inode_0x8daf96febcd0.dmp
0xe75d40822a00	0x208a8000	0x8daf96febe48	8	True	dirty,lru,private,reported,savepinned,slob_free,uptodate	inode_0x8daf96febcd0.dmp

inode_0x8daf96febcd0.dmp: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=96daef8bb7ab389abcb5aa9458436759949849c7, not stripped
Size: 32784 bytes
87fece49fc15a48372a1ba76cf424755f9cfab6cce7e8073002757f7db2f0711  inode_0x8daf96febcd0.dmp

[disclosed-ground-truth validation strings, after candidate selection]
/lib/selinux.so.3
__malicious_
__malicious_
father.c
```

**Recovery assessment:** `pagecache.Files` returned exactly one suitable regular
file with 9 expected and 9 cached pages. `InodePages` returned indexes 0–8,
all dump-safe, and the dump size equals the reported 32,784-byte inode size.
This supports complete page coverage for the cached file at capture time. It
does not prove byte identity with an original file because no authoritative
original-file comparison was performed. `file`, the SHA-256 and strings
characterize the candidate; they do not independently prove maliciousness. The
Father-specific strings are disclosed scenario validation only.

## M-05 - malfind review

**Question:** What anonymous executable/writable regions does standard
`malfind` select, and how do their mappings relate to the selected chain?

```bash {"name":"M-05-Malfind-Review","promptEnv":"never"}
set -euo pipefail

MALFIND="$EXAM_DIR/m-05-malfind.txt"
MAPS="$EXAM_DIR/m-05-maps.txt"

[[ -s "$MALFIND" ]] || "$VOL" -q -f "$MEMORY_IMAGE" -s "$(dirname "$ISF")" \
  linux.malware.malfind.Malfind >"$MALFIND"
[[ -s "$MAPS" ]] || "$VOL" -q -f "$MEMORY_IMAGE" -s "$(dirname "$ISF")" \
  linux.proc.Maps --pid 367 413 >"$MAPS"

cat "$MALFIND"
head -n 4 "$MAPS"
grep -B 3 -A 2 -F '0x7fd30345f000' "$MAPS"
grep -B 3 -A 2 -F '0x7f88fc27b000' "$MAPS"
```

**Output**

```text {"ignore":"true"}
Volatility 3 Framework 2.28.0

PID	Process	Start	End	Path	Protection	Hexdump	Disasm

367	networkd-dispat	0x7fd30345f000	0x7fd303460000	Anonymous Mapping	rwx
00 00 00 00 00 00 00 00 53 00 00 00 00 00 00 00 ........S.......
f3 0f 1e fa 4c 8d 15 f5 ff ff ff ff 25 07 00 00 ....L.......%...
00 0f 1f 80 00 00 00 00 04 70 5a 02 d3 7f 00 00 .........pZ.....
a8 f9 05 8c 30 56 00 00 00 e2 76 02 d3 7f 00 00 ....0V....v.....
0x7fd30345f000:	add	byte ptr [rax], al
0x7fd30345f002:	add	byte ptr [rax], al
0x7fd30345f004:	add	byte ptr [rax], al
0x7fd30345f006:	add	byte ptr [rax], al
0x7fd30345f008:	push	rbx
0x7fd30345f009:	add	byte ptr [rax], al
0x7fd30345f00b:	add	byte ptr [rax], al
0x7fd30345f00d:	add	byte ptr [rax], al
0x7fd30345f00f:	add	bl, dh
413	unattended-upgr	0x7f88fc27b000	0x7f88fc27c000	Anonymous Mapping	rwx
00 00 00 00 00 00 00 00 53 00 00 00 00 00 00 00 ........S.......
f3 0f 1e fa 4c 8d 15 f5 ff ff ff ff 25 07 00 00 ....L.......%...
00 0f 1f 80 00 00 00 00 04 10 92 fb 88 7f 00 00 ................
38 37 be 94 06 56 00 00 00 e2 11 fb 88 7f 00 00 87...V..........
0x7f88fc27b000:	add	byte ptr [rax], al
0x7f88fc27b002:	add	byte ptr [rax], al
0x7f88fc27b004:	add	byte ptr [rax], al
0x7f88fc27b006:	add	byte ptr [rax], al
0x7f88fc27b008:	push	rbx
0x7f88fc27b009:	add	byte ptr [rax], al
0x7f88fc27b00b:	add	byte ptr [rax], al
0x7f88fc27b00d:	add	byte ptr [rax], al
0x7f88fc27b00f:	add	bl, dh

Volatility 3 Framework 2.28.0

PID	Process	Start	End	Flags	PgOff	Major	Minor	Inode	File Path	File output

367	networkd-dispat	0x7fd303426000	0x7fd303428000	rw-	0x0	0	0	0	Anonymous Mapping	Disabled
367	networkd-dispat	0x7fd303428000	0x7fd30342a000	r--	0x0	254	1	5086	/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2	Disabled
367	networkd-dispat	0x7fd30342a000	0x7fd303454000	r-x	0x2000	254	1	5086	/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2	Disabled
367	networkd-dispat	0x7fd303454000	0x7fd30345f000	r--	0x2c000	254	1	5086	/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2	Disabled
367	networkd-dispat	0x7fd30345f000	0x7fd303460000	rwx	0x0	0	0	0	Anonymous Mapping	Disabled
367	networkd-dispat	0x7fd303460000	0x7fd303462000	r--	0x37000	254	1	5086	/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2	Disabled
367	networkd-dispat	0x7fd303462000	0x7fd303464000	rw-	0x39000	254	1	5086	/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2	Disabled
413	unattended-upgr	0x7f88fc242000	0x7f88fc244000	rw-	0x0	0	0	0	Anonymous Mapping	Disabled
413	unattended-upgr	0x7f88fc244000	0x7f88fc246000	r--	0x0	254	1	5086	/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2	Disabled
413	unattended-upgr	0x7f88fc246000	0x7f88fc270000	r-x	0x2000	254	1	5086	/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2	Disabled
413	unattended-upgr	0x7f88fc270000	0x7f88fc27b000	r--	0x2c000	254	1	5086	/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2	Disabled
413	unattended-upgr	0x7f88fc27b000	0x7f88fc27c000	rwx	0x0	0	0	0	Anonymous Mapping	Disabled
413	unattended-upgr	0x7f88fc27c000	0x7f88fc27e000	r--	0x37000	254	1	5086	/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2	Disabled
413	unattended-upgr	0x7f88fc27e000	0x7f88fc280000	rw-	0x39000	254	1	5086	/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2	Disabled
```

The complete 421-line PID-filtered mapping output is retained in
`m-05-maps.txt`. The two literal address lookups show each anonymous RWX region
immediately adjacent to `ld-linux-x86-64.so.2` mappings.

**Assessment:** `malfind` selected two anonymous RWX regions; it did not flag
malicious processes or ELF files. The regions have strongly similar structure,
both are loader-adjacent, and neither correlates with PID 877, PID 879, their
socket, or `selinux.so.3`. They are likely loader-related false-positive
candidates, not proven benign. No static ELF analysis or internet reputation
claim is used.

## M-06 - Page-cache examination of /tmp

**Question:** What regular-file and directory paths beneath `/tmp` are exposed
by cached inode/dentry information without using scenario keywords to select
them?

```bash {"name":"M-06-Tmp-Page-Cache","promptEnv":"never"}
set -euo pipefail

PAGECACHE="$EXAM_DIR/m-06-pagecache-files.txt"
TMP_VIEW="$EXAM_DIR/m-06-tmp.txt"

[[ -s "$PAGECACHE" ]] || "$VOL" -q -f "$MEMORY_IMAGE" -s "$(dirname "$ISF")" \
  linux.pagecache.Files --type REG DIR >"$PAGECACHE"
[[ -s "$TMP_VIEW" ]] || grep -F $'\t/tmp/' "$PAGECACHE" >"$TMP_VIEW"

head -n 4 "$PAGECACHE"
cat "$TMP_VIEW"
```

**Output**

```text {"ignore":"true"}
Volatility 3 Framework 2.28.0

SuperblockAddr	MountPoint	Device	InodeNum	InodeAddr	FileType	InodePages	CachedPages	FileMode	AccessTime	ModificationTime	ChangeTime	FilePath	InodeSize

0x8daf81782800	/	254:1	258154	0x8daf96fcc600	DIR	1	0	drwxrwxr-x	2026-08-05 12:49:19.869540 UTC	2026-08-05 12:49:19.869540 UTC	2026-08-05 12:49:19.869540 UTC	/tmp/forensic-lab	4096
0x8daf81782800	/	254:1	258155	0x8daf96fcef58	DIR	1	0	drwxrwxr-x	2026-08-05 12:49:19.869540 UTC	2026-08-05 12:49:20.685540 UTC	2026-08-05 12:49:20.685540 UTC	/tmp/forensic-lab/father_ldpreload	4096
0x8daf81782800	/	254:1	258156	0x8daf96fce190	DIR	1	0	drwxrwxr-x	2026-08-05 12:49:20.517540 UTC	2026-08-05 12:49:20.497540 UTC	2026-08-05 12:49:20.497540 UTC	/tmp/forensic-lab/father_ldpreload/probe	4096
0x8daf81782800	/	254:1	260193	0x8daf96feeac0	REG	0	0	-rw-rw-r--	2026-08-05 12:49:20.497540 UTC	2026-08-05 12:49:20.497540 UTC	2026-08-05 12:49:20.497540 UTC	/tmp/forensic-lab/father_ldpreload/probe/__malicious_file	0
0x8daf81782800	/	254:1	258150	0x8daf96d2c600	DIR	1	0	drwx------	2026-08-05 12:49:16.421540 UTC	2026-08-05 12:49:16.421540 UTC	2026-08-05 12:49:16.421540 UTC	/tmp/systemd-private-5e44445e26dd4fdab0dca729027961d5-systemd-timedated.service-XX2J9j	4096
0x8daf81782800	/	254:1	258151	0x8daf96d29810	DIR	1	0	drwxrwxrwt	2026-08-05 12:49:16.421540 UTC	2026-08-05 12:49:16.421540 UTC	2026-08-05 12:49:16.421540 UTC	/tmp/systemd-private-5e44445e26dd4fdab0dca729027961d5-systemd-timedated.service-XX2J9j/tmp	4096
0x8daf81782800	/	254:1	258108	0x8daf89663838	DIR	1	0	drwx------	2026-08-05 12:49:12.737540 UTC	2026-08-05 12:49:12.737540 UTC	2026-08-05 12:49:12.737540 UTC	/tmp/systemd-private-5e44445e26dd4fdab0dca729027961d5-systemd-hostnamed.service-9w5KNB	4096
0x8daf81782800	/	254:1	258110	0x8daf896605b0	DIR	1	0	drwxrwxrwt	2026-08-05 12:49:12.737540 UTC	2026-08-05 12:49:12.737540 UTC	2026-08-05 12:49:12.737540 UTC	/tmp/systemd-private-5e44445e26dd4fdab0dca729027961d5-systemd-hostnamed.service-9w5KNB/tmp	4096
0x8daf81782800	/	254:1	258115	0x8daf89657888	DIR	1	0	drwx------	2026-08-05 12:49:12.565540 UTC	2026-08-05 12:49:12.565540 UTC	2026-08-05 12:49:12.565540 UTC	/tmp/systemd-private-5e44445e26dd4fdab0dca729027961d5-systemd-logind.service-eylUpm	4096
0x8daf81782800	/	254:1	258145	0x8daf896525d8	DIR	1	0	drwxrwxrwt	2026-08-05 12:49:12.565540 UTC	2026-08-05 12:49:12.565540 UTC	2026-08-05 12:49:12.565540 UTC	/tmp/systemd-private-5e44445e26dd4fdab0dca729027961d5-systemd-logind.service-eylUpm/tmp	4096
0x8daf81782800	/	254:1	258102	0x8daf83bf25d8	DIR	1	0	drwx------	2026-08-05 12:49:07.117540 UTC	2026-08-05 12:49:07.117540 UTC	2026-08-05 12:49:07.117540 UTC	/tmp/systemd-private-5e44445e26dd4fdab0dca729027961d5-systemd-resolved.service-s77FKv	4096
0x8daf81782800	/	254:1	258103	0x8daf83bf53c8	DIR	1	0	drwxrwxrwt	2026-08-05 12:49:07.117540 UTC	2026-08-05 12:49:07.117540 UTC	2026-08-05 12:49:07.117540 UTC	/tmp/systemd-private-5e44445e26dd4fdab0dca729027961d5-systemd-resolved.service-s77FKv/tmp	4096
0x8daf81782800	/	254:1	258079	0x8daf83af2a70	DIR	1	0	drwx------	2026-08-05 12:49:05.917540 UTC	2026-08-05 12:49:05.917540 UTC	2026-08-05 12:49:05.917540 UTC	/tmp/systemd-private-5e44445e26dd4fdab0dca729027961d5-systemd-timesyncd.service-WOkCVH	4096
0x8daf81782800	/	254:1	258084	0x8daf83af3838	DIR	1	0	drwxrwxrwt	2026-08-05 12:49:05.917540 UTC	2026-08-05 12:49:05.917540 UTC	2026-08-05 12:49:05.917540 UTC	/tmp/systemd-private-5e44445e26dd4fdab0dca729027961d5-systemd-timesyncd.service-WOkCVH/tmp	4096
0x8daf81782800	/	254:1	258072	0x8daf83b72a70	DIR	1	0	drwxrwxrwt	2026-08-05 12:49:05.917540 UTC	2026-08-05 12:49:05.917540 UTC	2026-08-05 12:49:05.917540 UTC	/tmp/.ICE-unix	4096
0x8daf81782800	/	254:1	258078	0x8daf83b72140	DIR	1	0	drwxrwxrwt	2026-08-05 12:49:05.917540 UTC	2026-08-05 12:49:05.917540 UTC	2026-08-05 12:49:05.917540 UTC	/tmp/.Test-unix	4096
0x8daf81782800	/	254:1	258071	0x8daf83b74f30	DIR	1	0	drwxrwxrwt	2026-08-05 12:49:05.917540 UTC	2026-08-05 12:49:05.917540 UTC	2026-08-05 12:49:05.917540 UTC	/tmp/.X11-unix	4096
0x8daf81782800	/	254:1	258073	0x8daf83b73838	DIR	1	0	drwxrwxrwt	2026-08-05 12:49:05.917540 UTC	2026-08-05 12:49:05.917540 UTC	2026-08-05 12:49:05.917540 UTC	/tmp/.XIM-unix	4096
0x8daf81782800	/	254:1	258077	0x8daf83b705b0	DIR	1	0	drwxrwxrwt	2026-08-05 12:49:05.917540 UTC	2026-08-05 12:49:05.917540 UTC	2026-08-05 12:49:05.917540 UTC	/tmp/.font-unix	4096
0x8daf81782800	/	254:1	258070	0x8daf83b76ac0	DIR	1	0	drwx------	2026-08-05 12:49:05.913540 UTC	2026-08-05 12:49:15.129540 UTC	2026-08-05 12:49:15.129540 UTC	/tmp/snap-private-tmp	4096
0x8daf81782800	/	254:1	258148	0x8daf897eb3a0	DIR	1	0	drwx------	2026-08-05 12:49:15.129540 UTC	2026-08-05 12:49:15.129540 UTC	2026-08-05 12:49:15.129540 UTC	/tmp/snap-private-tmp/snap.lxd	4096
0x8daf81782800	/	254:1	258149	0x8daf897ee190	DIR	1	0	drwxrwxrwt	2026-08-05 12:49:15.129540 UTC	2026-08-05 12:49:15.129540 UTC	2026-08-05 12:49:15.129540 UTC	/tmp/snap-private-tmp/snap.lxd/tmp	4096
```

`pagecache.Files` exposes cached inode/dentry information from RAM. A returned
path is a memory observation, not automatic proof that the path remained
allocated on disk. Its AccessTime, ModificationTime and ChangeTime values are
recovered inode fields, not proof of when an object entered RAM.

Only after the generic `/tmp/` view was produced were the four Father-related
rows identified. Disclosed scenario facts state that
`/tmp/forensic-lab/father_ldpreload/probe/__malicious_file` was not removed by
cleanup, so this is not deleted-file recovery. The view exposes the path and a
zero-byte regular-file inode; it does not recover file content. No other cleaned
staging path appears in this bounded `/tmp/` view. Broad `RecoverFs` was not run.

## M-07 - Negative results and limitations

| Status | Result or limitation |
| --- | --- |
| Successful zero result | The authoritative raw-extraction record reports `linux.bash` completed with 0 rows. This does not prove that no commands ran. |
| Bounded negative | Neither PID 877 nor PID 879 appears in the two-row `malfind` result. |
| Bounded negative | The generic 22-row `/tmp/` view does not show the cleaned archive or source-tree paths. This is not proof they never existed. |
| Incomplete field | PID 877's `psaux` command line is visibly truncated. |
| Recovery limit | All nine cached pages were dumped, but no authoritative original-file comparison established byte identity. |
| Mapping limit | Library enumeration and cached-path observations do not by themselves prove a hook executed. |
| Timestamp limit | Process creation and cached-inode timestamps are recovered fields, not a complete causal timeline. |
| Snapshot limit | The RAM image is one point-in-time acquisition; prior and later state may be absent. |
| Candidate limit | The two loader-adjacent `malfind` regions are likely false-positive candidates, not proven benign. |
| Tool failures | None. Every bounded replay command exited 0; `linux.bash` is a successful zero result, not a failure. |

No YARA, online reputation, broad page-cache recovery, manual page
concatenation, `Elfs --dump`, or unsupported original-file reconstruction was
used.

## M-08 - RAM synthesis and disclosed scenario validation

### Forensic observations and analyst interpretation

| Observation | RAM support | Interpretation and limit |
| --- | --- | --- |
| Service-to-shell hierarchy | `pslist` and `pstree` show PID 877 `sshd` → PID 879 `sh`. | The hierarchy is captured state; the approximately 42 ms creation-time separation does not alone prove causality. |
| Unusual credentials | `pslist` gives the shell UID/EUID `0` and GID/EGID `1337`. | Credentials support an unusual root shell but do not identify an actor or full history. |
| Shared established socket | PID 877 and PID 879 reference socket `0x8daf8d42bd40`, `192.168.100.41:22` → `192.168.100.1:54321`. | Repeated descriptors are one connection; the tuple alone is not proof of maliciousness. |
| Unusual library | LibraryList and Elfs show `selinux.so.3` in both selected processes alongside conventional `libselinux.so.1` in `sshd`. | Loader and mapped-ELF views correlate but are not identical evidence. |
| Bounded library recovery | Files returns one 32,784-byte regular file with 9/9 cached pages; InodePages dumps indexes 0–8, all dump-safe. | Page coverage supports a complete cached-file dump, not proven identity with an original file. |
| `/tmp` page cache | The generic view exposes Father directories and the retained zero-byte probe file. | These are memory-resident path/inode observations, not automatic disk-allocation or deleted-content claims. |
| `malfind` | Two strongly similar anonymous RWX regions are loader-adjacent in unrelated processes. | Likely loader-related false-positive candidates; not proven benign and not linked to the selected chain. |
| Bash | The raw authority records `linux.bash` completed with zero rows. | Valid tool-scoped zero result; no general claim that commands did not run. |

### Disclosed scenario validation

Only after candidate selection, the authoritative manifest, command log and
scenario facts validate the controlled treatment:

- repository revision `3619046e2625211e9e20c45cbffe86145e7f222b`;
- successful installation of `/lib/selinux.so.3`, preload configuration and SSH
   restart;
- listener service `sshd`, port `22`, trigger source port `54321`, and a
   connection open at scenario completion;
- validated identity `uid=0(root) gid=1337 groups=1337`;
- successful source/archive/history cleanup commands; the bounded disk methods
  did not recover those targets, while the installed library and preload config
  remained; and
- the probe path intentionally retained while file hiding was validated.

These facts attribute the selected observations to the controlled Father
treatment. They are validation data, not forensic discoveries or reusable
detection logic.

**RAM conclusion:** The authoritative snapshot supports a coherent
service-to-root-shell, shared-socket and unusual-library chain. Standard page
cache examination recovered all expected cached pages of the selected library
candidate. Generic `/tmp` examination adds path/inode observations, while the
two `malfind` candidates, `linux.bash` zero result and point-in-time acquisition
remain explicitly bounded.

FATHER-CLEANUP RAM PHASE READY FOR REVIEW
