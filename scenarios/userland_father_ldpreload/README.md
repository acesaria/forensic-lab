# userland_father_ldpreload

The `userland_father_ldpreload` calibration uses a builder-produced Father object,
activates its shared object system-wide through `/etc/ld.so.preload`, validates
native file hiding and Father's native `accept()` backdoor, then preserves the
active compromise for optional acquisition. The
`userland_father_ldpreload_cleanup` treatment performs the same validated
deployment before applying a small, naive staging cleanup. These are treatment
checks, not forensic findings.

The active control flow is intentionally short:

`cli.py` -> explicit orchestrator dispatch -> `runner.py` -> `SSHTerminal`

There is no executable scenario YAML, loader, generic engine, executor adapter,
dynamic hook, or run-context object. The builder verifies and configures the
vendored source, then publishes `rk.so` with `build.json`. Before victim reset,
the run requires a build matching the selected image, copies both files
byte-for-byte into immutable inputs, and records their hashes in the manifest.
The runner then executes the fixed experiment as ordinary Bash commands in one
visible terminal. The terminal transcript and append-only command log are
written at the run root.

The vendored archive is locked by `father.lock.yml` to upstream commit
`4eb2712caf612a7dc55fd4f34ff5c72b74c7c332` and is hash-checked by the builder.
The runner uploads the staged artifact rather than the cache copy, then:

- compares the guest distro/version and architecture with `build.json` before
  installing anything;
- installs `rk.so` at Father's default `/lib/selinux.so.3` path;
- lists `__malicious_file`, writes the library path to `/etc/ld.so.preload`,
  then lists the same directory and confirms that the file is hidden;
- restarts `ssh.service` and validates Father's native root shell.

For the cleanup treatment only, the same interactive `labuser` Bash session
then removes the uploaded `/tmp/rk.so`, runs the naive history commands, and
confirms `$HOME/.bash_history` is absent while `/etc/ld.so.preload` and
`/lib/selinux.so.3` remain present. The cleanup does not target the probe
directory or controlled hidden file. The terminal transcript and append-only
command log preserve the guest identity check, activation, validation, and
cleanup commands as experimental ground truth. Builder provenance lives in the
separate build record, not the scenario command log.

## Native backdoor validation

Father's `SOURCEPORT 54321` is the connecting client's source port; Father does
not listen on destination port 54321. Its `accept()` hook must be loaded into a
real listener. The runner therefore connects to the guest's sshd listener from
host source port 54321 and consumes the fixed authentication-prompt length only
for synchronization; the prompt content is not separately validated. It then
sends the pinned password, requires the stable `Enjoy the shell!` marker, and
executes `id` in the resulting shell.

The bounded check succeeds only when the shell marker is observed and `id`
returns both `uid=0(root)` and `gid=1337`. The CLI displays only the shell marker
and parsed identity, not Father's ASCII drawing. `command_log.jsonl` retains
only a minimal `validate_backdoor` success or failure operation, with the
exception message on failure. The parsed identity, trigger source port,
listener service and port, and open connection at scenario completion live in
`scenario_facts`. No raw response, response excerpt, response tail, or separate
socket-response file is retained. This socket check is treatment validation,
not a forensic conclusion.

Both Father variants represent an active-compromise memory snapshot. The
ordinary SSH orchestration shell exits before acquisition, while Father's
native root `/bin/sh` and its TCP connection remain active during RAM capture.
The client connects from source port 54321 to sshd's port 22, but Father's
`accept()` hook intercepts it before SSH authentication, so it is not a second
genuine SSH login. The host closes the native socket immediately after memory
capture and before VM shutdown. A `--no-acquire` run instead closes it
immediately before the mandatory Father shutdown.

## Run

Build the pinned artifact once for the exact target image. Builder networking is
allowed for this explicit preparation step; the victim remains offline:

```bash
.venv/bin/python cli.py build --distro ubuntu-22.04 \
  --scenario userland_father_ldpreload
```

Both treatments consume that same published artifact.

The light production validation skips acquisition and still powers the Father
VM off:

```bash
.venv/bin/python cli.py run --distro ubuntu-22.04 \
  --scenario userland_father_ldpreload --no-acquire
```

The cleanup treatment uses the same runner and lifecycle:

```bash
.venv/bin/python cli.py run --distro ubuntu-22.04 \
  --scenario userland_father_ldpreload_cleanup --no-acquire
```

Omit `--no-acquire` for the established memory-while-on and disk-while-off
acquisition. The run stops there; TSK, Plaso, and Volatility examination is
manual. The scenario is only for an isolated disposable thesis VM.
