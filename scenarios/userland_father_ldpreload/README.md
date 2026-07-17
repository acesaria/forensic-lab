# userland_father_ldpreload

`userland_father_ldpreload` is a simple calibration case for real system-wide
LD_PRELOAD persistence plus one Father-native file-hiding check. It builds the
pinned Father source inside a disposable guest, installs the resulting shared
object at `/usr/local/lib/forensic-lab/father/selinux.so.3`, and atomically
activates it through `/etc/ld.so.preload`.

The scenario is for isolated thesis VMs only. It refuses the local executor, so
the Father archive, build, shared object, and activation helper are never run on
the development host.

## Prerequisites

- a disposable, isolated lab VM restored to its baseline snapshot;
- VM-backed execution through `.venv/bin/python cli.py run`;
- working SSH access and non-interactive `sudo -n` to effective UID 0 in the guest;
- guest `python3`, `gcc`, `make`, `libpam0g-dev`, `libgcrypt20-dev`, and
  `libgcrypt20`, all preinstalled in the offline baseline;
- dynamically linked `/usr/bin/python3`, `/usr/bin/sleep`, and `/bin/ls`
  binaries.

## Operational effect

The implementation reading order is `scenario.yml`, the thin host-side
`steps.py`, the linear `files/run_father_calibration.sh`, and the focused
privileged `files/activate_system_preload.py` helper. The lock remains host-side
and its declared archive SHA-256 is verified before any upload.

The orchestrator's existing Paramiko connection starts `/bin/bash -i` with one
PTY, types one fixed script invocation followed by `exit`, and reads the
combined terminal transcript to channel closure. Bash therefore saves genuine
history on normal logout, while the channel supplies one real final exit status.
There is no prompt parsing, per-command remote orchestration, or synthetic
history.

The Bash script is one direct sequence: check offline prerequisites, extract
and configure Father, build `rk.so`, create the hiding probe, invoke the
privileged helper, validate hiding, and print the helper's JSON as its final
structured output line.

The run-local configuration keeps the preload-name token away from
`/etc/ld.so.preload` and sets Father's file-hiding prefix to `__malicious_`.
Before activation, `ls -l` must see `probe/__malicious_file` and writes
`before.txt`. After activation, a new `ls -l` must fail to see that same file
and writes `after.txt`, while the Bash process started before activation uses
its built-in `[[ -e ... ]]` check to prove the file still exists. This is the
only hiding behavior exercised.

Before changing `/etc/ld.so.preload`, the root activation helper starts one
Python process with an explicit `LD_PRELOAD` value and requires the shared
object to appear in that process's `/proc/self/maps`.

After that preflight succeeds, the helper preserves the exact pre-existing
`/etc/ld.so.preload` bytes under
`/tmp/forensic-lab/father_ldpreload/recovery/`. If the file did not exist, it
writes an explicit `ld.so.preload.was_absent` marker instead. The final preload
content retains any existing entries, adds the Father path, and is installed
with an atomic same-directory replacement.

Activation starts three detached `/usr/bin/sleep` processes for 30 minutes.
The step succeeds only if every process remains alive and maps the installed
shared object. The run manifest records one concise `scenario_facts` block:

- deployed files;
- system-wide preload activation;
- affected PIDs;
- privilege used;
- treatment-validation result for system-wide mappings and file hiding.

These are experimental treatment checks, not automatic detection results or a
forensic conclusion. The append-only command log retains the verified source
identity, three uploaded destinations, fixed script invocation, integer exit
status, timestamps, and terminal-transcript excerpt.

## Acquisition moment

Use the normal full run:

```bash
.venv/bin/python cli.py run --distro ubuntu-22.04 \
  --scenario userland_father_ldpreload
```

The orchestrator begins memory acquisition after all three mapped processes
have passed validation and while the VM is still ON. It then powers the VM OFF
for disk acquisition. The probe marker, extracted source and build artifacts,
installed library, `/etc/ld.so.preload`, recovery artifact, and three mapped
processes are all left in place through acquisition. The marker is never
deleted or altered after validation.

`--no-acquire` is only for controlled troubleshooting and leaves the activated
guest running. Restore the VM snapshot immediately afterward.

## Failure-only recovery

The privileged activation helper remains alive while it changes the preload
configuration and validates the child processes. If the explicit preflight,
atomic activation, process liveness check, or mapping check fails, that already
running helper terminates any children, atomically restores the original
`/etc/ld.so.preload` state (including original absence), and restores or removes
the installed library. The failed validation and any recovery error remain
explicit in the command log and failed manifest status.

This rollback is only a failure path; there is no successful-run cleanup
variant in this scenario. Snapshot restoration remains the primary cleanup and
emergency-recovery mechanism.

## Known safety constraints

- System-wide preload affects every newly started dynamically linked guest
  process, including administrative and shutdown commands.
- Father retains its upstream hooks. The scenario configures the preload-hiding
  token away from `/etc/ld.so.preload` and exercises only the bounded
  `__malicious_file` check. It does not trigger its shell,
  privilege-escalation, network-hiding, or other capabilities, but the loaded
  code is not a benign substitute.
- Do not reuse the guest for unrelated work after activation. Acquire the
  evidence, then restore the baseline snapshot.
- This calibration adds no evasion, cleanup, automatic detector, canonical
  matching, expected-observable, or scoring behavior.
