---
cwd: ../../../..
shell: bash
---

# Father disk investigation

__Run:__ `ubuntu-22.04_userland_father_ldpreload_20260813-224442`

Read-only filesystem examination of the accepted disk image with The Sleuth
Kit, following the `LD_PRELOAD` persistence path from `/etc/ld.so.preload`
outward without using scenario ground truth for selection. Derived output is
written under the ignored analyst workspace
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

## Filesystem identity and preload configuration

```bash
# Root ext4 offset from mmls, then fsstat and the preload config.
mmls "$DISK" | tee "$INV_DIR/d-00-mmls.txt"
# The preload file content is the technique-led entry point.
cat "$INV_DIR/d-01-ld.so.preload"; echo
```

**Output**

`fsstat` (saved as `d-00-fsstat.txt`) identifies the root ext4 volume
`cloudimg-rootfs`. `/etc/ld.so.preload` (inode `74210`) contains the single
line `/lib/selinux.so.3`, a mimic of a system library. On Ubuntu `/lib` is a
symlink to `/usr/lib`, so it resolves to `/usr/lib/selinux.so.3`.

## Installed library identity by hash

```bash
# Recover the installed library and hash it against the manifest input.
sha256sum "$INV_DIR/d-06-rk.so.recovered"
grep -o '"sha256": "[0-9a-f]*"' "$RUN_DIR/manifest.json" | head -1
```

**Output**

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
fls -r -p "$INV_DIR/root-partition.ext4" | grep -E 'tmp/__malicious_file|usr/lib/selinux.so.3|etc/ld.so.preload'
```

**Output**

`/tmp/__malicious_file` (inode `74173`) is fully visible in the dead image even
though the `readdir` interposition would hide it on the live system. The
filename matches the disclosed `__malicious_` prefix; that is a posterior
validation. The build staging tree is **not** present under `/tmp` (the scenario
applies a small staging cleanup); its recovery from unallocated space/journal
was not pursued within this bounded examination — a scoped negative, not an
absence of compromise.

## Log context (auth.log)

```bash
# Principal logs are examined here per the guidelines; broad temporal
# correlation is otherwise the timeline notebook's job (Plaso not run here).
tail -8 "$INV_DIR/d-08-auth.log"
```

**Output**

`auth.log` dates the activation: at `20:44:43 UTC` `labuser` runs
`sudo systemctl restart ssh.service`; the old `sshd` (PID 655) receives
`SIGTERM` and a new `sshd` (PID 1054) starts listening on port 22. PID 1054 is
the process that loads the preload library and is later seen in memory. The
recovered `.bash_history` preserves command text/order only, with no `#<epoch>`
lines, so no per-command execution time can be assigned.
