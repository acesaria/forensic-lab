# kernel_diamorphine

`kernel_diamorphine` is a bounded Diamorphine LKM calibration for the isolated
lab. Its treatment checks are not forensic findings.

The locked source archive is pristine upstream commit
`af494fad213654aae16cfdbbb50e7dc26383e4b2`, which is upstream master's tip.
Ubuntu backported direct `x64_sys_call` dispatch while retaining the now-unused
`sys_call_table`, and no upstream commit resolves this, so the builder applies
the separately hash-pinned compatibility patch and selects the
upstream FlipSwitch path from the exact running kernel's `/proc/kallsyms`. It publishes
`diamorphine.ko` with a `build.json` carrying the kernel, vermagic, dispatch
path, pristine-source hash, and patch hash. The victim never builds.

Before victim reset, `run` verifies and stages the artifact and record
byte-exact. Before upload, the runner checks the guest kernel and requires
module loading to be enabled. The treatment represents an attacker who already
has temporary administrative execution and prepares a host-survey note
containing the hostname, kernel, and execution identity before loading the
implant. It then validates only:

- ordinary listings omit the default-prefix reconnaissance directory and note
  beneath `/tmp` while direct access to the known note still works;
- `lsmod` omits the loaded module; and
- signal 64 changes only a dedicated non-root child shell's credentials to UID
  0, after which that helper exits.

Process hiding, networking, backdoors, and a persistent privileged helper are
absent. The module stays loaded through memory acquisition and ends at shutdown.
Cleanup is deferred for separate research and approval.

Build for the exact pinned image before running:

```bash
.venv/bin/python cli.py build --distro ubuntu-22.04 \
  --scenario kernel_diamorphine
.venv/bin/python cli.py run --distro ubuntu-22.04 \
  --scenario kernel_diamorphine --no-acquire
```

Omit `--no-acquire` for acquisition. This is only for the isolated thesis lab.
