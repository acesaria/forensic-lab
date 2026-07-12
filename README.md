# forensic-lab

forensic-lab is a defensive Linux post-mortem forensic investigation lab for
controlled VM scenarios. It executes a scenario in an isolated lab VM, acquires
disk and memory evidence, produces raw TSK/Plaso/Volatility exports, and
supports manual correlation across filesystem, timeline, and memory evidence.

This is thesis research tooling, not a production SIEM, EDR, malware sandbox,
automatic detector, automatic reconstruction system, or live incident-response
platform.

## Migration State

The project has pivoted from automatic detection/evaluation to reproducible
manual multi-source investigation. Documentation now reflects the target
architecture. Some legacy automatic detector, canonical matching, and metrics
code remains in the repository until later cleanup commits.

Previous automatic reconstruction work is preserved by the immutable tag
`automatic-reconstruction-v3-final`.

## Target Workflow

The thesis workflow is intentionally layered:

1. provision a clean VM from a pinned distro image;
2. snapshot the pristine baseline;
3. run a controlled scenario from `scenarios.yaml`;
4. write a minimal run manifest and append-only command log;
5. acquire memory while the VM is ON;
6. acquire disk while the VM is OFF;
7. hash acquired evidence and retain provenance;
8. extract raw filesystem evidence with TSK;
9. extract raw timeline evidence with Plaso;
10. extract raw memory evidence with Volatility;
11. manually investigate and correlate the raw evidence;
12. compare vanilla and hardened profiles;
13. report findings, negative findings, tool failures, and limitations.

Automatic acquisition and raw extraction remain in scope. Investigation remains
manual. Precision, recall, canonical matching, ruleset hashes, and automatic
reconstruction scores are not current thesis outputs.

## Repository Layout

```text
forensic-lab/
├── cli.py                         # command entry point
├── scenarios.yaml                 # registered scenario keys
├── scenarios/
│   ├── scenarios/                 # declarative scenario.yml trees
│   └── art/                       # optional ART calibration inputs
├── infra/                         # libvirt/QEMU, Ansible, distro profiles
├── orchestrator/
│   ├── core/                      # lifecycle, VM state, paths, provenance
│   ├── scenarios/                 # declarative scenario engine
│   ├── forensics/                 # acquisition and raw tool runners
│   ├── adapters/                  # legacy normalization layer
│   └── canonical/                 # legacy canonical record models
├── detectors/                     # legacy automatic rule layer
├── matcher/                       # legacy automatic matching/metrics layer
├── docs/                          # methodology and orientation
├── shared/                        # generated experiment outputs
└── vendor/                        # vendored third-party rule/test data
```

Generated outputs under `shared/` are disposable artifacts or evidence for a
named run, not source.

## Typical Workflow

```bash
# One-time host setup: sudoers, system dirs, libvirt network and storage pool
python cli.py init

# Prepare a distro: download image, create VM, build ISF, take baseline snapshot
python cli.py setup --distro ubuntu-22.04

# Run the registered thesis scenario, then acquire and extract evidence
python cli.py run --distro ubuntu-22.04 --scenario userland_father_ldpreload

# Local scenario-engine validation without VM acquisition
python cli.py run-scenario \
  scenarios/scenarios/userland_father_ldpreload/scenario.yml \
  --out-dir /tmp/father_local --run-id father_local

# Destroy a lab VM when finished with a distro
python cli.py destroy --distro ubuntu-22.04
```

During migration, full runs may still emit legacy normalized, detector, matcher,
or metric artifacts. Current thesis use is the scenario log, run manifest,
acquired evidence, raw TSK/Plaso/Volatility exports, hashes, tool failures, and
manual investigation notes.

Scenario keys come from `scenarios.yaml`. The current registered thesis
scenario key remains `userland_father_ldpreload`.

## Evidence Contract

- Minimal run manifest and append-only command log are required.
- Memory acquisition requires the lab VM to be running.
- Disk acquisition requires the lab VM to be powered off.
- Disk and memory images retain hashes and provenance.
- Raw TSK, Plaso, and Volatility exports are preserved as raw evidence.
- Tool failures and negative findings are recorded explicitly.
- Raw evidence is immutable; reruns create separate derived artifacts.
- Filesystem, timeline, and memory source families stay distinguishable during
  manual correlation.

## VM Contract

The lab uses two VM roles:

| Role | Network | Purpose | Lifecycle |
|---|---|---|---|
| `lab` | `forensics-isolated` | Runs controlled scenarios | Persistent, snapshots |
| `build-isf` | `default` | Builds Volatility3 ISF symbols | Ephemeral |

Power transitions stay in the orchestrator, not in tool wrappers.

## Profiles

- Ubuntu 22.04 is the deep-analysis platform.
- Ubuntu 24.04 and Fedora receive targeted replication.
- Vanilla means distro defaults.
- Hardened means one fixed documented native-control bundle.
- Ubuntu hardening uses AppArmor.
- Fedora hardening uses SELinux.
- `hardened+telemetry` adds `auditd` and is used only for the Father cleanup
  comparison.

If a hardened profile blocks a scenario, the run is recorded as prevented.
Remaining evidence and denial traces are still acquired and analysed.

## Configuration

Copy `config.yaml.example` to `config.yaml` and adjust paths for your machine.
`config.yaml` is local and gitignored.

Python setup:

```bash
./setup-venv.sh
source .venv/bin/activate
```

Host prerequisites include KVM/QEMU with libvirt, `cloud-localds`,
`ewfacquire`, and an SSH key for the lab VM. Passwordless sudo inside the lab is
a controlled laboratory precondition for deploying scenario steps that require
root; it is not an emulation of initial compromise.

## Optional ART Calibration

Atomic Red Team data is kept as an optional calibration input, not as the core
scenario model. The locked calibration subset lives under `scenarios/art/`, and
the vendored technique YAMLs live under `vendor/atomic-red-team/atomics/`.

The thesis scenarios are controlled by this framework and produce reproducible
execution records, acquired evidence, raw forensic exports, and material for
manual investigation.
