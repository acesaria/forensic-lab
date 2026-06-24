# CLAUDE.md

Guidance for Claude Code working in this repository.

## Project

Linux digital forensics thesis. A reproducible lab that reconstructs Linux
attacks (userland/kernel rootkits, process injection, log/history clearing) by
running ART-derived scenarios on disposable libvirt/KVM VMs, then acquiring and
analyzing disk and memory images.

## Critical invariants

Read these before touching orchestration, acquisition, or VM lifecycle code.

- Lab VMs stay vanilla. Anything installed on a victim VM must come from an
  Ansible playbook invoked by the orchestrator inside the experiment
  transaction. Never install or modify a lab VM over manual SSH.
- Exactly one snapshot per lab VM, named baseline. Created at the end of setup;
  the orchestrator reverts to it before every run and never auto-recreates it.
  To refresh it: destroy then setup.
- The build-isf VM is ephemeral and is the only VM with internet access. It is
  created, used to emit a Volatility ISF, and destroyed within one build_isf
  call.
- The orchestrator owns the VM power-state contract between acquisitions:
  acquire_memory requires the VM ON, acquire_disk requires it OFF. Dumper never
  transitions power state on its own.
- Lab VMs sit on the host-only forensics-isolated network (192.168.100.0/24, no
  NAT, no internet) so rootkits cannot phone home or pull updates.
- On error during a run, leave the VM destroyed. Do not leave a half-modified VM
  for the next run.
- infra/ is the "VMs as infrastructure" layer; orchestrator/ is the "VMs as
  experiment subjects" layer. They cross only through Provider, reached via
  VMManager.

## Environment

- Host: Linux Mint 22.3, libvirt/QEMU/KVM at qemu:///system.
- Single venv at .venv from ./setup-venv.sh (paramiko, libvirt-python, pyyaml,
  requests).
- Victim VMs are vanilla Ubuntu/Debian cloud images wi
- VM roles: persistent lab-* (host-only net); ephemera
  internet-connected net, ISF builds only).

## CLI

Single entry point, run from repo root. Everything else is inferred from
config.yaml, scenarios.yaml, and infra/profiles/<distro>.yaml. Default distro is
ubuntu-22.04; scenario keys come from scenarios.yaml.

python cli.py init                              one-time host setup (sudoers, system dirs, libvirt net + pool); needs sudo
python cli.py setup --distro                download i snapshot, build ISF, verify pipeline (idempotent)
python cli.py run --distro  --scenario   revert to basly acquire memory + disk
python cli.py destroy --distro              remove lab VM and its storage
python cli.py score --manifest --findings --out-dir   match + metrics from cached findings (no VM)
python cli.py pipeline --run-dir            detect from cached raw outputs, then match + metrics (no VM)
python cli.py verify                        check pinned tool versions + print ruleset hash (no VM)
            --debug                             raise bprocess output

## Repository areas

- cli.py: the single entry point. Wires Provider, VMManager, Dumper, and the
  Vol/Sleuth runners and builds ProjectPaths once, threading it everywhere. VM
  subcommands (init/setup/run/analyze/destroy) build the orchestrator; the
  offline evaluation subcommands (score/pipeline/verify) re-score cached
  artifacts and skip both the host prerequisite check and orchestrator
  construction.
- config.yaml: machine-local ssh keys, libvirt URI, po
  Gitignored.
- scenarios.yaml: scenario registry (single ART test,
  module path).
- infra/: provider.py (libvirt/virsh wrapper), image_s
  checksum), profiles/<id>.yaml, cloud-init seed, ansible/ playbooks
  (lab_baseline, isf_build, rootkit_deploy).
- orchestrator/core/: orchestrator.py (ForensicOrchest
  power-state contract), vm_manager.py (lab VM ops; de
  calls libvirt directly), ssh_client.py, config.py (constants +
  load_config/load_profile), bootstrap.py (init helpers).
- orchestrator/attacks/: art_runner.py (parses ART YAM
  SSH), scenario_01_ldpreload.py (custom multi-step), gitignored
  attack_0[156]_*.py WIP.
- orchestrator/forensics/: the tool-I/O layer. dumper.py (RAM + disk +
  manifest.json), vol_runner.py (Volatility3), sleuth_runner.py (Sleuth Kit),
  plaso_runner.py (log2timeline/psort), timeutil.py (ISO-8601 UTC ms helpers),
  filters/. No detection or scoring logic lives here.
- orchestrator/evaluation/: the GT-blind detector -> matcher -> metrics pipeline.
  contracts/ (dataclasses + *.schema.json validated at every stage boundary),
  detect/ (GT-blind heuristics over raw tool output; must never read ground
  truth), match/ (GT-aware entity matching against gt_manifest.json), metrics/
  (recall/precision/order + legacy columns), extract/ (thin adapters onto the
  orchestrator/forensics runners), scenario/manifest.py (GtManifestBuilder,
  seeded instance values), provenance.py (tool-version pins + SHA-256),
  config/ (pipeline.yaml, matching.yaml, rules/), pipeline.py (wires the three
  stages), tests/. Dependency direction is one-way: core -> evaluation ->
  forensics. The detect-blindness boundary is enforced by
  tests/test_detect_blindness.py and tests/test_rule_leakage.py.
- vendor/atomic-red-team/atomics/: ART YAMLs (squashed git subtree, not a
  submodule).

## Acquisition and outputs

- RAM: virsh dump --memory-only --live while running (
  baseline_memory.raw.
- Disk: VM shut down, qcow2 overlay exposed via qemu-nbd --read-only, ewfacquire
  produces compressed EWF (.E01); VM restarted after.
- Volatility3 ISF is keyed on distro family + kernel r
  ubuntu_5.15.0-119-generic.json), resolved by VolatilityRunner at call time.
- Outputs are gitignored under host.shared_dir: experi
  dumps/ (memory/, disk/, manifest.json, ground_truth.json) and analysis/
  (timeline, forensics_report.json). Generated ISFs live under isf/.

### run_id naming

One run_id is built once per experiment by _make_run_id(distro_id, scenario_id)
in orchestrator.py and names a single experiments/<run
and analysis/ stay in lockstep.

- distro_id: profile/VM family key, e.g. ubuntu-22.04.
- scenario_id: scenarios.yaml key, never carries a tim
  scenario_01_ldpreload or verify.
- run_id: <distro>_<scenario>_<timestamp>, e.g.
  ubuntu-22.04_scenario_01_ldpreload_20260529-123203.

The manifest records run_id and scenario_id as distinct fields and stores
absolute paths.

## Conventions

Code:
- No backticks or fancy unicode (arrows, em-dashes, decorative bullets, emojis)
  in code or comments.
- Comments explain why, not what; no LLM-style verbose comments or section
  dividers.
- Python: type hints on public functions, no bare except, prefer pathlib over
  os.path.
- Shell: set -euo pipefail on every script; no bashism
- Prefer explicit over clever.

Paths:
- Configured paths are normalized to absolute Paths once, at load time
  (load_config, _HOST_PATH_FIELDS). Layout lives in ProjectPaths, not callers.
  To add a tunable path field register it in _HOST_PAT
  subdirectory add it to ProjectPaths.

Orchestrator:
- Public Orchestrator methods take distro_id; private helpers use the resolved
  vm_name (e.g. lab-ubuntu-22.04).
- ART scenarios need technique_id + test_guid (empty guid means all guids for
  the technique). Complex scenarios set type: complex

## ART / ATT&CK scope

Single-technique tests run via the in-tree ArtRunner (parses atomics YAML
directly, no atomic-operator dependency). Multi-stage scenarios are custom
modules in orchestrator/attacks/ that may call ArtRunn
interest: T1574.006 (LD_PRELOAD), T1014 (kernel rootkits: Diamorphine,
libprocesshider), T1055 (ptrace injection, custom), T1
T1070.003/004 (history/log clearing), T1548.001 (SUID
(reverse shell, custom).

## What not to do

- Do not install or change anything on a lab VM outside an orchestrator-invoked
  playbook.
- Do not call sudo directly on the host outside init/b
  ops go through libvirt or the sudoers rules init installs.
- Do not commit config.yaml, CLAUDE.md, manifest.json,
  VM IPs, or SSH key paths (all gitignored).
- Do not git add -A: gitignored WIP files (attack_0[156]_*.py) must stay local.
- Do not treat vendor/atomic-red-team as a submodule;
  git subtree pull --prefix=vendor/atomic-red-team ... --squash.

## How to work in this repo

- Inspect the exact files you need, not whole folders;
  clear, so locate the one owner of a behavior before editing.
- Make minimal, targeted patches. Do not refactor broa
  the infra/ vs orchestrator/ boundary and the power-state contract.
- Keep run, debug, and analysis tasks separate: a run mutates VMs and writes a
  new run_id directory; analysis only reads an existin
  doing before you start.
- Experiments are long-running and mutate VM state. Co
  and scenario before run/setup/destroy, and use --deb
  VM operation hangs, surface it instead of blocking indefinitely.
- Treat shared/ outputs as disposable artifacts, not source.

