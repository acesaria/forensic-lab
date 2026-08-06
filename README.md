# Linux Multi-Source DFIR Lab

[Canonical repository](https://github.com/acesaria/linux-multisource-dfir-lab)

Linux Multi-Source DFIR Lab supports a Master's thesis on reproducible Linux
post-mortem DFIR experiments. It runs controlled compromise scenarios in
isolated VMs, acquires disk and memory evidence, produces raw Sleuth Kit, Plaso,
and Volatility 3 exports, and supports manual investigation across filesystem,
timeline, and memory sources.

The project is research infrastructure, not a production SIEM, EDR, malware
sandbox, live-response platform, automatic detector, or automatic
reconstruction system.

## Current repository surface

The CLI exposes `init`, `setup`, `run`, and `destroy`. `run` dispatches directly
to one of four scenario keys:

- `interactive_shell`;
- `ptrace_fa`;
- `userland_father_ldpreload`;
- `userland_father_ldpreload_cleanup`.

A full run restores the prepared baseline, executes and validates the selected
scenario, acquires memory while the VM is on, shuts the VM down, acquires disk,
and produces raw filesystem, timeline, and memory exports. The implementation
then stops: investigation, cross-source interpretation, and conclusions are
human work.

Current runs use manifest schema v3 and are recorded as `vanilla`. There is no
runtime selector for a hardened security profile. Distro definitions exist for
Ubuntu 22.04, Ubuntu 24.04, and Debian 13, but Ubuntu 22.04 is the current
deep-analysis platform. Broader replication and optional scenarios must not
delay the minimum thesis deliverables.

## Evidence and run records

Each run is rooted under `shared/experiments/<run_id>/`. An acquired run keeps:

```text
manifest.json                         run identity, lifecycle status, revision, sidecar index
command_log.jsonl                     append-only scenario operations and commands
terminal_transcript.txt               human-readable scenario terminal record
dumps/acquisition.json                acquisition commands, hashes, verification, image metadata
analysis/raw_extraction_status.json   raw-tool versions, commands, outputs, hashes, failures
```

Raw outputs include the TSK bodyfile, Plaso storage/timeline exports, and
Volatility output. The root manifest is a small lifecycle index; the acquisition
and raw-extraction sidecars are the authorities for their respective provenance.
A successful `--no-acquire` run keeps the root records but no acquisition or
raw-extraction sidecars; it validates only the scenario and is not a complete
forensic experiment.

Accepted evidence and raw exports are immutable. Other generated caches may be
recreated, but accepted run material must not be overwritten. Tool failures,
zero-result tools, and source-scoped negative observations remain distinct.

## Repository layout

```text
cli.py                    command entry point
infra/                    libvirt/QEMU, Ansible, images, distro definitions
orchestrator/core/        lifecycle, VM state, configuration, run paths
orchestrator/forensics/   acquisition and raw TSK/Plaso/Volatility runners
scenarios/                explicit scenario runners and command logging
docs/investigations/      scenario/run notebooks, accepted reports, comparative material
shared/                   generated run evidence, exports, and local analysis
```

Operational identifiers such as the `forensic-lab` CLI name, schema names, guest
paths, and evidence artifacts are retained when they are part of the working
system or a recorded run.

## Basic use

Create the local configuration and virtual environment first:

```bash
cp config.yaml.example config.yaml
./setup-venv.sh
```

Then use the repository interpreter:

```bash
.venv/bin/python cli.py init
.venv/bin/python cli.py setup --distro ubuntu-22.04
.venv/bin/python cli.py run --distro ubuntu-22.04 \
  --scenario userland_father_ldpreload
```

Host prerequisites include KVM/QEMU with libvirt, `cloud-localds`, `ewfacquire`,
the configured forensic tools, and an SSH key for the lab VM. Passwordless sudo
inside the disposable guest is a documented deployment precondition, not an
emulation of initial compromise.

## Documentation

- `AGENTS.md` is the only repository-agent entry point.
- `METHODOLOGY.md` defines the thesis and investigation method.
- `TODO.md` contains mutable priorities and delivery milestones.
- Scenario-specific documentation explains controlled treatment behavior.
- Named investigation documents apply only to their cited immutable runs.

Previous automatic detection, matching, scoring, and reconstruction work is
historical. Its final checkpoint is preserved by the immutable
`automatic-reconstruction-v3-final` tag and must not be treated as the current
architecture.
