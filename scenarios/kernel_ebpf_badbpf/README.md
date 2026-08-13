# kernel_ebpf_badbpf

This controlled Ubuntu scenario uses the pinned Bad-BPF `exechijack` and
`pidhide` programs to model a small XCrypto resource-hijacking chain. It is an
educational treatment, not a real miner: it performs no hashing, reaches no
Internet host, establishes no shell, and creates no persistence.

The victim consumes three builder-produced inputs:

- vendored `exechijack`, which rewrites a scoped `execve` pathname to `/a`;
- vendored `pidhide`, which removes one PID from `getdents64` results; and
- lab-owned `xcrypto`, a harmless worker that exchanges one fixed Stratum-like
  `mining.subscribe` request and reply with the isolated host gateway.

The runner installs XCrypto at Bad-BPF's hardcoded `/a` path, scopes
`exechijack` to the scenario shell, and triggers the hook with a background
`/usr/bin/uptime` execution. The shell records and disowns the resulting XCrypto
process, whose original `argv[0]` remains `/usr/bin/uptime`. It changes its short
task name to the kernel-worker-like `kworker/u8:2`, connects to the host-side
pool simulator on `192.168.100.1:3333`, and remains idle. This controlled
masquerade leaves intentionally inconsistent `/proc` identities: the executable
is `/a`, the command line says `/usr/bin/uptime`, and `comm` resembles a kernel
worker even though the user process owns a TCP socket.

The runner requires the successful hijack log, expected process-identity
mismatches, the fixed pool request/reply, visibility before `pidhide`, absence
from `/proc` enumeration afterward, direct `/proc/<pid>/status` access, and live
worker/loader processes at scenario completion.

The pool socket, hidden worker, and `pidhide` loader remain active during memory
acquisition. The host closes its socket after memory capture and before the
guest shuts down for offline disk acquisition. Scenario checks are disclosed
ground truth; subsequent filesystem, timeline, and memory discovery remains
manual and must not use the planted PID or paths to select candidates.

The Bad-BPF archive is hash-pinned by `badbpf.lock.yml` and is not modified.
`files/xcrypto.c` is separate lab-owned source. The builder records its hash, the
recipe hash, package versions, target image checksum, and target kernel in
`build.json`; every run stages and hashes the exact resulting inputs.

```bash
.venv/bin/python cli.py build --distro ubuntu-22.04 \
  --scenario kernel_ebpf_badbpf
.venv/bin/python cli.py run --distro ubuntu-22.04 \
  --scenario kernel_ebpf_badbpf --no-acquire
```

Omit `--no-acquire` only for the final memory-while-on and disk-while-off run.
