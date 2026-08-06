# Comparative results

Cross-run manual evidence-recovery coverage. These are descriptive post-mortem
metrics, not automatic detection accuracy: no precision, recall, F1, weighting,
or average of per-source rates is used.

## Metric contract

- Each scenario variant uses a fixed atomic target inventory established before
  the run being measured. The Father-cleanup M01–M11/C01–C03 inventory below
  was already documented in repository history before the 2026-08-05 run and
  is reused unchanged.
- `Observed` and `Partial` count as found when an accepted forensic locator
  supports the target's central identity or occurrence; the limitation behind
  every partial result remains explicit. `Not observed` is source- and
  method-scoped. `N/A` means the source was not considered capable of answering
  that target in the fixed inventory.
- Coverage is `Found / applicable targets`, calculated separately per source.
  Union coverage counts each target once when any applicable source found it.
- `Rejected candidates` counts candidates selected as suspicious and then
  rejected as unrelated. `0` means candidate generation produced no rejected
  candidate; `N/A` means no candidate-generating method was used.
- `TTD` is reported only when measured prospectively from examination start to
  the first supported locator. It is never reconstructed afterward.

## Summary

| Run | Scenario | Source | Found / applicable | Coverage | Rejected candidates | TTD | Principal tools | Notes |
|---|---|---|---:|---:|---:|---|---|---|
| ubuntu-22.04_userland_father_ldpreload_20260722-175300 | userland_father_ldpreload (vanilla) | Filesystem | 8 / 8 | 100% | N/A | not measured | TSK (`fls`/`istat`/`icat`) | Full persistence chain; M08 command strings partial, without timing. |
| ubuntu-22.04_userland_father_ldpreload_20260722-175300 | userland_father_ldpreload (vanilla) | Timeline | 8 / 9 | 88.9% | N/A | not measured | Plaso 20260512 | M08 not observed: no `#<epoch>` history and zero `text/bash_history`; M03 partial. |
| ubuntu-22.04_userland_father_ldpreload_20260722-175300 | userland_father_ldpreload (vanilla) | Memory | 3 / 3 | 100% | 2 | not measured | Volatility 3 2.28.0 | Two `malfind` candidates rejected as unrelated to the Father chain. |
| ubuntu-22.04_userland_father_ldpreload_20260722-175300 | userland_father_ldpreload (vanilla) | Union | 11 / 11 | 100% | 2 case-wide | not measured | TSK + Plaso + Volatility 3 | Observed calibration result, not an acceptance condition. |
| ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919 | userland_father_ldpreload_cleanup (vanilla) | Filesystem | 5 / 11 | 45.5% | 0 | not measured | TSK, ext4magic 0.3.2, PhotoRec | M02 is partial; the archive, built `rk.so`, history, and cleanup events were not recovered by the bounded methods. |
| ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919 | userland_father_ldpreload_cleanup (vanilla) | Timeline | 6 / 12 | 50.0% | N/A | not measured | Plaso 20260512 | M08 is partial; privileged invocations and restart are logged, but no cleanup event or backdoor connection is independently observed. |
| ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919 | userland_father_ldpreload_cleanup (vanilla) | Memory | 3 / 3 | 100% | 2 | not measured | Volatility 3 2.28.0 | The two `malfind` candidates are unrelated to the selected Father chain, not proven benign. |
| ubuntu-22.04_userland_father_ldpreload_cleanup_20260805-144919 | userland_father_ldpreload_cleanup (vanilla) | Union | 9 / 14 | 64.3% | 2 case-wide | not measured | TSK + Plaso + Volatility 3 | No forensic source directly observed C01–C03 cleanup; scenario records validate only that the cleanup commands completed. |

## Father cleanup target audit — 20260805-144919

This table makes the summary denominator auditable. The locators refer to the
three notebooks under the exact run directory. Additional supporting evidence
does not create another target or change the fixed applicability set.

| Target | Filesystem | Timeline | Memory | Accepted locator or limitation |
|---|---|---|---|---|
| M01 source archive staged | Not observed | Not observed | N/A | Disk D-02/D-05 and timeline T-05 did not recover or expose it within their bounds. |
| M02 source/build tree extracted | Partial | Observed | N/A | Disk D-04 recovers the `config.h` content candidate at unallocated block `589864` without pathname/inode; timeline T-04 preserves the `Father-4eb2712...` working directory. |
| M03 modified `config.h` applied | Observed | Not observed | N/A | Disk D-04 recovers the complete 740-byte boundary-delimited candidate, SHA-256 `d14ebf96...120ad4`; this is ground-truth-guided recovery. |
| M04 `rk.so` built | Not observed | Not observed | N/A | The installed library survives, but the bounded methods do not independently recover or time the build output. |
| M05 library installed/mapped | Observed | Observed | Observed | Disk D-01 inode `62345`; timeline T-03/T-04 `fs:stat` plus sudo install record; memory M-04 mappings and cached-file recovery for the same inode. |
| M06 `/etc/ld.so.preload` configured | Observed | Observed | N/A | Disk D-01 inode `61596`; timeline T-03/T-04 `fs:stat` plus sudo `tee` record. The later inode timestamp does not date the explicit invocation. |
| M07 controlled hidden file created | Observed | Observed | N/A | Disk D-01 and timeline T-03 identify probe inode `260193`; memory M-06 supplies additional path/inode context outside the fixed denominator. |
| M08 interactive command activity | Not observed | Partial | N/A | Timeline T-04 records only the three privileged sudo invocations; Bash-history parsing produced no event data type. |
| M09 privileged shell parented by `sshd` | N/A | N/A | Observed | Memory M-01/M-02: PID `877` `sshd` → PID `879` root `sh`, GID/EGID `1337`. |
| M10 established backdoor connection | N/A | N/A | Observed | Memory M-03: one established `192.168.100.41:22` → `192.168.100.1:54321` socket shared by the selected processes. |
| M11 SSH restart during activation | N/A | Observed | N/A | Timeline T-04 records the `ssh.service` stop/start lifecycle. |
| C01 archive cleanup | Not observed | Not observed | N/A | Cleanup command success is scenario validation; no forensic locator proves the cleanup event. |
| C02 source/build-tree cleanup | Not observed | Not observed | N/A | Unallocated content and parent-directory change are compatible with cleanup but do not prove a deletion event. |
| C03 Bash-history cleanup | Not observed | Not observed | N/A | Cleanup command success is scenario validation; bounded disk and timeline methods did not recover history evidence. |
