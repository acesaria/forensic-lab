# Experiment summary — userland_father_ldpreload

## Parameters

- scenario: `userland_father_ldpreload`
- distro/profile: `ubuntu-22.04` / `vanilla`
- VM: `lab-ubuntu-22.04` (target IP `192.168.100.32`)
- final evidence run: yes
- repository commit: `fc381d5a4dd8eeaee109c37ef45f7e3ab512c496-dirty` (working tree had uncommitted changes at run time)

## Exact command

```
.venv/bin/python cli.py run --distro ubuntu-22.04 --scenario userland_father_ldpreload
```

## Run identity

- run_id: `father-u22-20260818-01`
- run directory: `shared/experiments/father-u22-20260818-01/`

## Timeline

- scenario started: 2026-08-18T15:00:13.062Z
- scenario ended: 2026-08-18T15:01:44.330Z
- run ended (post-acquisition): 2026-08-18T15:02:22.406Z

## Status

- scenario_status: `completed`
- overall run status: `completed`
- acquisition: `completed` (memory + offline disk)
- final VM state: off

## Execution narrative (as observed)

1. VM reverted to `baseline` snapshot; SSH became ready on 192.168.100.32.
2. Reconnaissance stage ran (`id`, `uname -a`, `cat /etc/os-release` teed to console + `/tmp/__malicious_recon`; `cat /etc/passwd` appended to the stage file only, no console echo) — matches the Phase B recon-quieting change described in `ai/01_refactor/output/father-rootkit-integration.md`.
3. `rk.so` staged to `/tmp/rk.so` on the guest, then installed as `/lib/selinux.so.3` with timestomping (`touch -r` against `libc.so.6`).
4. Credentials harvested (`/etc/shadow` copied to `/tmp/__malicious_harvest`, mode 0600).
5. Persistence configured via `/etc/ld.so.preload`; activated with `systemctl restart ssh.service`.
6. Post-activation `/tmp` listing shows `__malicious_recon` and `__malicious_harvest` no longer visible (hidden by the hooked `readdir`), while `rk.so` (not covered by the hook's name-hiding logic) remains visible — expected implant behavior.
7. Host-side backdoor validation succeeded: connection from Father's trigger port 54321 returned a root shell ("Enjoy the shell!", `uid=0(root) gid=1337`).
8. Cleanup ran: `/tmp/rk.so` removed, shell history cleared/unset. No log truncation was executed, consistent with the evidence-preserving default `CLEANUP_COMMANDS` documented in the Phase B integration note.
9. Memory acquired (virsh dump, memory-only), VM shut down, offline disk acquisition performed (qemu-img → ewfacquire → ewfverify), acquisition manifest written.

## Suitability for downstream stages

- Suitable as input to stage `03_docs` (factual scenario behavior confirmed end-to-end) and stage `04_thesis` (validated final evidence run with acquisition artifacts and hashes).
- No source files were modified during this stage.
