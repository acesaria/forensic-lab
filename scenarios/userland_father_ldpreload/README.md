# userland_father_ldpreload

`userland_father_ldpreload` is a simple calibration case for real system-wide
LD_PRELOAD persistence. It builds the pinned Father source inside a disposable
guest, installs the resulting shared object at
`/usr/local/lib/forensic-lab/father/selinux.so.3`, and atomically activates it
through `/etc/ld.so.preload`.

The scenario is for isolated thesis VMs only. It refuses the local executor, so
the Father archive, build, shared object, and activation helper are never run on
the development host.

## Prerequisites

- a disposable, isolated lab VM restored to its baseline snapshot;
- VM-backed execution through `python cli.py run`;
- working SSH access and non-interactive `sudo -n` to effective UID 0 in the guest;
- guest `python3`, `gcc`, `make`, `libpam0g-dev`, `libgcrypt20-dev`, and
  `libgcrypt20` (the orchestrator temporarily enables VM networking only if it
  must install missing build prerequisites);
- dynamically linked `/usr/bin/python3` and `/usr/bin/sleep` binaries.

## Operational effect

The implementation reading order is deliberately short: `scenario.yml` defines
the four actions and all guest paths, `steps.py` performs those actions over
SSH, and `files/activate_system_preload.py` contains the privileged guest
transaction. No other scenario module contains Father behavior.

The four scenario steps stage and configure the pinned Father archive, build
its real `rk.so`, and install it at the documented root-owned guest path. Before
changing `/etc/ld.so.preload`, the root activation helper starts one Python
process with an explicit `LD_PRELOAD` value and requires the shared object to
appear in that process's `/proc/self/maps`.

The run-local Father configuration uses a non-matching preload-hiding token, so
this calibration does not add hiding of `/etc/ld.so.preload`. It does not
exercise Father's other hiding or shell capabilities.

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
- validation result.

These are execution-validation facts, not automatic detection results or a
forensic conclusion. The append-only command log retains the build commands,
source hash, privilege-bearing activation command, and validation output.

## Acquisition moment

Use the normal full run:

```bash
.venv/bin/python cli.py run --distro ubuntu-22.04 \
  --scenario userland_father_ldpreload
```

The orchestrator begins memory acquisition after all three mapped processes
have passed validation and while the VM is still ON. It then powers the VM OFF
for disk acquisition. `/etc/ld.so.preload`, the installed `.so`, and the
recovery copy or absence marker are deliberately left present throughout this
sequence.

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
  token away from `/etc/ld.so.preload` and does not trigger its shell,
  privilege-escalation, other file-hiding, network-hiding, or other
  capabilities, but the loaded code is not a benign substitute.
- Do not reuse the guest for unrelated work after activation. Acquire the
  evidence, then restore the baseline snapshot.
- This calibration adds no evasion, cleanup, automatic detector, canonical
  matching, expected-observable, or scoring behavior.
