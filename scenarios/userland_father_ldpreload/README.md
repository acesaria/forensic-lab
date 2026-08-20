# userland_father_ldpreload

The `userland_father_ldpreload` calibration uses a builder-produced Father object
and runs one phased post-compromise timeline: reconnaissance with local data
staging, implant staging, installation with timestomping, local credential
harvesting, persistence through
`/etc/ld.so.preload`, activation, validation of native file hiding and Father's
native `accept()` backdoor, and an anti-forensic cleanup. It then preserves the
active compromise for optional acquisition. These are treatment checks, not
forensic findings.

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
The runner uploads the staged artifact rather than the cache copy, then walks one
deterministic post-compromise timeline. Every phase is bracketed in the command
log by `phase_<name>_start` and `phase_<name>_end`:

- a lab precondition first, outside the timeline: compare the guest
  distro/version and architecture against `build.json` and refuse to install an
  implant built for another target;
- `recon` — `id`, `uname -a`, `cat /etc/os-release`, `cat /etc/passwd`
  (T1033, T1082, T1087.001), staged to `/tmp/__malicious_recon` so the
  collected output survives on the victim rather than being discarded
  (T1074.001). `id`, `uname -a`, and `/etc/os-release` are also teed to the
  console; the account database is appended to the stage file only, with a
  concise `[recon] account database collected` marker printed in its place,
  so the full account list is retained as evidence without being echoed to
  the run's console output;
- `stage_artifact` — upload `rk.so` to `/tmp/rk.so`;
- `install_implant` — install it at Father's default `/lib/selinux.so.3` path,
  then timestomp it from `libc.so.6` with `touch -r` (T1070.006);
- `harvest_credentials` — copy `/etc/shadow` to `/tmp/__malicious_harvest` under
  Father's hidden prefix (T1003), and list the directory to show both staged
  files are visible before activation;
- `configure_persistence` — write the library path to `/etc/ld.so.preload`;
- `activate` — restart `ssh.service`;
- `dwell`, then `validate` — list the directory again, require the credential
  copy to be hidden, record whether the recon stage was also hidden, then
  validate Father's native root shell;
- `cleanup` — remove the uploaded `/tmp/rk.so` (T1070.004) and apply the
  naive history cleanup (T1070.003), while retaining the active preload
  configuration and installed library. `/var/log/auth.log` and
  `/var/log/syslog` are deliberately left untouched: truncating them
  (T1070.002) is a real anti-forensic action, but it removes evidence that
  makes the default run recoverable for investigation. A stronger-evasion
  variant that truncates them belongs in a separate, explicitly opted-in
  profile, not the default scenario.

Short fixed dwells separate the phases and a longer one precedes validation, so
the treatment spans roughly ninety seconds rather than landing in one timestamp.
The durations are scenario design, not a claim about attacker tempo.

Two choices are deliberate and are what make the case interesting rather than
circular. `touch -r` cannot reset `ctime`, so the implant keeps a truthful
install time behind a plausible library `mtime`. The cleanup clears the
plaintext logs and leaves the binary journal alone, which is what intruders who
script this step routinely miss.

Father's `readdir` hook skips a matching entry by fetching exactly one more
entry, not by looping, so two hidden names returned consecutively by the
underlying directory read leak the second one. With two staged files under the
prefix this is a real possibility on any given run. The scenario therefore
requires only the credential copy to be hidden and records the recon stage's
visibility as a `recon_stage_hidden` operation in the command log, carrying an
`error` note when the entry leaked. That is an upstream implementation flaw
worth observing, not a lab failure worth aborting a run for.

The credential copy is never read back, printed, or exported; only the directory
listing that shows whether it is visible is captured. Recon output is staged in a
separate file so that copy is never reopened for any reason. The cleanup does not
target `/tmp/__malicious_recon`, `/tmp/__malicious_harvest`,
`/etc/ld.so.preload`, or `/lib/selinux.so.3`, and it asserts nothing about its
own effects — whether the staging object was really removed is a question for the
acquired image, not for the scenario. The terminal
transcript and append-only command log preserve the guest identity check, every
phase boundary, activation, validation, and cleanup as experimental ground truth.
Builder provenance lives in the separate build record, not the scenario command
log.

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
exception message on failure. `scenario_facts` retains only the established
socket's client and server addresses and ports, obtained from the socket itself.
It does not repeat paths, validation booleans, cleanup outcomes, or the parsed
identity already enforced by the runner. No raw response, response excerpt,
response tail, or separate socket-response file is retained. These facts are
disclosed ground truth for validating an independently selected memory socket,
not candidate-selection inputs or forensic conclusions.

The scenario represents an active-compromise memory snapshot. The ordinary SSH
orchestration shell exits before acquisition, while Father's native root
`/bin/sh` and its TCP connection remain active during RAM capture.
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

The light production validation skips acquisition and still powers the Father
VM off:

```bash
.venv/bin/python cli.py run --distro ubuntu-22.04 \
  --scenario userland_father_ldpreload --no-acquire
```

Omit `--no-acquire` for the established memory-while-on and disk-while-off
acquisition. The run stops there; TSK, Plaso, and Volatility examination is
manual. The scenario is only for an isolated disposable thesis VM.
