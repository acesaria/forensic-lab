# userland_father_ldpreload

`userland_father_ldpreload` is the canonical Father-inspired LD_PRELOAD
scenario for the thesis pipeline. It uses the real Father source in a
controlled VM/lab context, builds a run-local shared object, and exercises a
small set of safe behaviors relevant to dynamic-linker hijacking.

This is a post-mortem DFIR scenario. It is not a live EDR/SIEM use case, a
wild-malware deployment, or an attempt to execute every Father capability.

## Scope

Selected behavior:

- build Father's real `rk.so` from the pinned source archive;
- configure only the temporary run-local source copy;
- load the installed library with explicit `LD_PRELOAD` for a bounded process;
- exercise the accept-hook source-port path with the configured password and keep
  a bounded localhost-only shell/session open for memory acquisition;
- observe Father prefix-based file hiding as contextual behavior.

Out of scope:

- local privilege escalation;
- reverse shell, external network access, or privilege escalation;
- malicious LKM, ptrace, CopyFail, GnuPG tampering, time bomb, or full APT
  behavior;
- system-wide LD_PRELOAD persistence;
- destructive cleanup, log wiping, timestomping, broad anti-detection, or live
  telemetry logic.

## Forensic Intent

The scenario generates evidence that can be reconstructed after acquisition:

- disk/filesystem artifacts;
- memory process, mapping, and socket artifacts;
- timeline artifacts;
- baseline comparison artifacts.

The teaching goal is to keep the case understandable: real Father source,
bounded execution, explicit safety limits, and enough artifacts for the
post-mortem pipeline to evaluate reconstruction quality.

Ground truth and expected artifacts are written for the GT-aware matching and
metrics layers. Detectors and YAML rules must remain GT-blind.

## Implementation Shape

The scenario extracts the pinned Father archive into the run workspace, edits
only that temporary copy's `src/config.h`, runs `make father`, and copies the
built `rk.so` to the scenario's lab install path.

The canonical run writes a scenario-local preload artifact and activates the
library with an explicit `LD_PRELOAD` environment for one bounded Python
listener. The accept-hook client connects only to `127.0.0.1` from the configured
source port, sends the configured password, and keeps the socket-backed
shell/session open for `process_duration_seconds`.

The manifest defines seven steps:

1. `prepare_father_source`
2. `configure_father`
3. `build_father_rootkit`
4. `install_preload_rootkit`
5. `trigger_accept_hook_capability`
6. `observe_file_hiding_effect`
7. `record_postconditions`

## Running

Local engine validation:

```bash
.venv/bin/python cli.py run-scenario \
  attacks/scenarios/userland_father_ldpreload/scenario.yml \
  --out-dir /tmp/father_local --run-id father_local
```

VM-backed scenario execution without acquisition:

```bash
.venv/bin/python cli.py run --distro ubuntu-22.04 \
  --scenario userland_father_ldpreload --no-acquire
```

Full thesis run:

```bash
.venv/bin/python cli.py run --distro ubuntu-22.04 \
  --scenario userland_father_ldpreload
```

## Outputs

A scenario run writes:

- `execution_truth.jsonl`
- `artifact_expectations.jsonl`
- `reference_context.json`
- `command_log.jsonl`

Full VM-backed runs then acquire RAM and disk while the listener and bounded
shell/session are still alive, extract post-mortem tool output, normalize
`ToolFinding` records, emit GT-blind candidate `DetectionClaim` records, match
against expected artifacts, and compute metrics/report outputs.

Cleanup/evasion and deterministic randomization of paths, ports, prefixes, and
related values are future variants, not the default scenario.
