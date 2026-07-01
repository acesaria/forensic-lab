# userland_father_ldpreload

`userland_father_ldpreload` is the canonical Father-based DFIR scenario for the
thesis pipeline. It models a bounded Linux userland rootkit case: Father
LD_PRELOAD installation, Father accept-hook behavior, and contextual file-hiding
behavior.

The upstream Father project is the scenario subject:
https://github.com/mav8557/Father. The repository keeps a pinned upstream
git-archive at commit `4eb2712caf612a7dc55fd4f34ff5c72b74c7c332` with SHA-256
`90e440a2ff8264a3f39c5c2b63ee7b8def9b85f87a7b79c666bfb46f25a2c125`. Source
provenance is recorded in `father.lock.yml`.

Father source is treated as upstream scenario material. forensic-lab does not
patch Father internals, rewrite Father hooks, or hardcode forensic-lab paths into
Father C source. Scenario-specific logging, safety controls, ground truth, and
expected artifacts live in `steps.py`, `scenario.yml`,
`expected_observables.yml`, and this README.

At runtime the scenario extracts the pristine archive into the run workspace,
edits only that temporary copy's `src/config.h`, runs `make father`, and uses the
resulting Father `rk.so`. The committed repository contains no scenario-local C
replacement for Father.
On Ubuntu, Father requires `libpam0g-dev` for `security/pam_appl.h` and `libgcrypt20-dev` for `gcrypt.h`; the scenario installs them if missing.

## Selected Capabilities

Canonical v1 demonstrates:

- Father LD_PRELOAD / dynamic-linker loading from the real `rk.so`;
- Father accept-hook/backdoor source-port behavior, bounded by sending a wrong
  password so no shell is spawned;
- contextual file-hiding observation using Father’s configured prefix behavior;
- no cleanup/evasion by default.

Excluded from this scenario:

- local privilege escalation;
- reverse shell or authenticated bind shell;
- malicious LKM, ptrace, CopyFail, GnuPG tampering, time bomb, and full APT
  behavior;
- broad anti-detection, log wiping, timestomping, or destructive cleanup;
- SIEM, EDR, or live telemetry logic.

## Forensic Intent

The scenario should answer:

> How would a basic attacker/script-kiddie use Father LD_PRELOAD behavior in a
> controlled Linux VM, and what post-mortem traces would remain?

Attack-core artifacts are the upstream source archive/provenance, run-local
Father configuration, built `rk.so`, installed Father library, preload
configuration artifact, preloaded process, process/library memory mapping, and
accept-hook/source-port evidence. File hiding is contextual: Father’s upstream
source defines prefix-based hiding, and disk, timeline, and baseline-diff
evidence should still reveal the prefix-matching file.

## Safety Model

The accept-hook trigger uses Father's real preloaded code but sends the wrong
password, so the hook path can be observed without authenticating to a shell. The
scenario writes under `/tmp/forensic-lab/father_ldpreload` by default. Father's
real `/etc/ld.so.preload` concept is recorded as a reference parameter, but the
canonical v1 activates the library with an explicit `LD_PRELOAD` environment for
one bounded process. This avoids destabilizing the VM while preserving the
forensic artifacts the pipeline should reconstruct.

The Python listener is a lab stand-in for a daemon whose `accept()` path is
executed under Father preload. In a more realistic compromise, the hooked
process could be an existing daemon and the client interaction could be
performed manually from an attacker shell. The lab listener keeps the scenario
deterministic and bounded.

## Step Shape

The manifest defines seven steps:

1. `prepare_father_source`
2. `configure_father`
3. `build_father_rootkit`
4. `install_preload_rootkit`
5. `trigger_accept_hook_capability`
6. `observe_file_hiding_effect`
7. `record_postconditions`

Each step writes execution truth and command log entries. Expectations are
declared separately in `expected_observables.yml` and are used only by the
GT-aware evaluation layer; detectors must not read those files.

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

VM-backed full runs then acquire RAM and disk and run the existing post-mortem
pipeline: extract tool output, normalize `ToolFinding` records, emit GT-blind
candidate `DetectionClaim` records, match against expected artifacts, and compute
metrics/report outputs.

## Deferred Variants

Cleanup/evasion is documented in `scenario.yml` but disabled by default. A later
variant may remove or alter the preload configuration, remove staging/build
files, and leave memory/timeline/baseline residue. It should not add broad log
wiping, timestomping, anti-forensics, or stealth expansion.
