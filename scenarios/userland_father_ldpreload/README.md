# userland_father_ldpreload

This disposable-VM scenario builds the pinned Father source, activates its
shared object system-wide through `/etc/ld.so.preload`, proves one native
file-hiding behavior, and opens Father's native `accept()` backdoor long enough
for memory acquisition.

The short implementation path is:

1. `scenario.yml` verifies the source, uploads the archive and
   `files/run_scenario.sh`, then invokes that script once in interactive Bash.
2. The script builds and activates Father, leaves three mapped processes alive,
   restarts `ssh.service`, and verifies the new root sshd maps Father.
3. `steps.py` starts the small host `files/verify_backdoor.sh` client, which
   validates `id` and remains alive while the orchestrator begins acquisition.

The vendored archive is locked by `father.lock.yml` to upstream commit
`4eb2712caf612a7dc55fd4f34ff5c72b74c7c332` and is hash-checked before upload.

## Guest execution

The existing Paramiko connection opens one `/bin/bash -i` PTY, types the one
script invocation followed by `exit`, and waits for channel closure. There is
no prompt parsing, repeated interactive command execution, completion token,
or synthetic history. Normal Bash logout saves the invocation in
`.bash_history`, and the command log records its real exit status and transcript
excerpt. The full combined output is retained as `terminal_transcript.txt` at
the run root.

The script directly performs the fixed experiment sequence:

- check the offline build prerequisites;
- extract and configure the pinned source;
- build `rk.so` and install it at
  `/usr/local/lib/forensic-lab/father/selinux.so.3`;
- retain the former preload file, or an explicit absence marker, under the run
  directory;
- write the installed library to `/etc/ld.so.preload`;
- start three detached root `sleep` processes and verify their mappings;
- restart `ssh.service` and verify the new listener's mapping;
- leave all successful-run effects present for acquisition.

Snapshot restoration is the cleanup mechanism. The script deliberately has no
transaction helper or successful-run rollback.

## Native file hiding

The run-local source sets Father's `STRING` token to the controlled prefix
`__malicious_` and keeps `PRELOAD` non-matching. The pinned source implements
this behavior in its `readdir()` hook; it does not hook the `statx` path used by
some exact-path `ls` calls.

The script saves plain before/after listings of the probe directory. A newly
started, Father-loaded `ls` must omit `__malicious_file`; the Bash process that
predates activation then checks that `before.txt` remains visible and proves the
marker still exists with `[[ -e ... ]]`. No completion token or synthetic shell
interaction is used, and both outputs and the marker remain on disk.

## Native backdoor

`SOURCEPORT 54321` is the connecting client's source port; Father does not
listen on 54321. Its hook must be loaded into a real listening service that
calls `accept()`. The script therefore restarts the root sshd after activation,
and the host client connects to that service's TCP port 22 from source port
54321.

The hook forks after the real `accept()`, prompts on the accepted socket, and
checks one raw read for `SHELL_PASS`, pinned here as `lobster`. The client waits
for the first response bytes without parsing a prompt, sends that password with
a terminating NUL, waits for Father's authentication response to grow, then
sends `id`. No environment value or SSH authentication participates in this
path.

The child keeps sshd's effective UID 0, changes to Father's magic GID 1337,
duplicates the accepted socket onto standard input/output/error, and executes
`/bin/sh`. Validation therefore requires both `uid=0(root)` and `gid=1337` in
`father_backdoor_response.txt`.

The host `nc` process and its stdin remain open after the scenario returns, so
the shell and TCP connection stay established during RAM acquisition. Shutting
down the VM afterward closes the connection naturally.

## Run and live-validation boundary

Use the normal full run:

```bash
.venv/bin/python cli.py run --distro ubuntu-22.04 \
  --scenario userland_father_ldpreload
```

The first controlled smoke run must confirm that restarting `ssh.service` does
not disturb the already-established Paramiko PTY, that Ubuntu's sshd calls the
hooked `accept()` symbol, and that the pinned `readdir()` hook hides the marker
under the guest's actual glibc/coreutils. Host OpenBSD `nc` must support `-p`,
and host source port 54321 must be free.

The scenario is for an isolated thesis VM only. System-wide preload affects new
administrative and shutdown processes; do not reuse the guest for other work.
