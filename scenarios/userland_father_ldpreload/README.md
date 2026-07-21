# userland_father_ldpreload

This disposable-VM scenario builds the pinned Father source, activates its
shared object system-wide through `/etc/ld.so.preload`, validates native file
hiding and Father's native `accept()` backdoor, then preserves the resulting
state for optional acquisition. These are treatment checks, not forensic
findings.

The active control flow is intentionally short:

`cli.py` -> explicit orchestrator dispatch -> `runner.py` -> `SSHTerminal`

There is no executable scenario YAML, loader, generic engine, executor adapter,
dynamic hook, or run-context object. `runner.py` verifies and uploads the
vendored archive, then executes the fixed experiment as ordinary Bash commands
in one visible terminal. The terminal transcript and append-only command log
are written at the run root.

The vendored archive is locked by `father.lock.yml` to upstream commit
`4eb2712caf612a7dc55fd4f34ff5c72b74c7c332` and is hash-checked before upload.
The runner then:

- extracts and configures the pristine pinned source in the guest;
- builds and installs `rk.so` at Father's default `/lib/selinux.so.3` path;
- lists `__malicious_file`, writes the library path to `/etc/ld.so.preload`,
  then lists the same directory and confirms that the file is hidden;
- restarts `ssh.service` and validates Father's native root shell.

Snapshot restoration is the cleanup mechanism. Successful-run state remains in
the disposable guest for acquisition.

## Native backdoor validation

Father's `SOURCEPORT 54321` is the connecting client's source port; Father does
not listen on destination port 54321. Its `accept()` hook must be loaded into a
real listener. The runner therefore connects to the guest's sshd listener from
host source port 54321, waits for Father's authentication prompt, sends the
pinned password, requires the stable `Enjoy the shell!` marker, and executes
`id` in the resulting shell.

The bounded check succeeds only when the authentication prompt and shell marker
were observed and the parsed identity contains both `uid=0(root)` and
`gid=1337`. The CLI displays only the shell marker and parsed identity, not
Father's ASCII drawing. The successful `command_log.jsonl` record retains the
endpoints and trigger source port, prompt and marker status, parsed identity,
timestamps, and status. It does not retain the full response or an excerpt. On
failure only, the same record may include a bounded decoded response tail for
diagnosis; no separate response file is created. This socket check is treatment
validation, not forensic evidence.

## Run

The light production validation skips acquisition and still powers the Father
VM off:

```bash
.venv/bin/python cli.py run --distro ubuntu-22.04 \
  --scenario userland_father_ldpreload --no-acquire
```

Omit `--no-acquire` for the established memory-while-on and disk-while-off
acquisition followed by raw TSK, Plaso, and Volatility extraction. The scenario
is only for an isolated disposable thesis VM.
