# forensic-lab

forensic-lab is a defensive Linux post-mortem forensic reconstruction and
evaluation framework for controlled VM scenarios. It runs a scenario in an
isolated lab VM, acquires disk and RAM evidence, extracts disk/RAM/timeline
findings, and evaluates what can be reconstructed against artifact
expectations written during scenario execution.

This is thesis research tooling, not a production SIEM, EDR, malware sandbox,
or live incident-response platform.

## Pipeline

The thesis pipeline is intentionally layered:

1. provision a clean VM from a pinned distro image;
2. snapshot the pristine baseline;
3. run a controlled scenario from `scenarios.yaml`;
4. write execution truth and artifact expectations;
5. acquire memory while the VM is ON;
6. acquire disk while the VM is OFF;
7. extract disk, RAM, and timeline evidence;
8. normalize tool output into `ToolFinding` records;
9. emit GT-blind candidate `DetectionClaim` records;
10. match candidates against expectations and compute metrics/report outputs.

Headline results are based on matched reconstruction, not raw findings and not
the full candidate stream.

## Repository Layout

```text
forensic-lab/
├── cli.py                         # command entry point
├── scenarios.yaml                 # registered scenario keys
├── scenarios/
│   ├── scenarios/                 # declarative scenario.yml trees
│   └── art/                       # optional ART calibration inputs
├── orchestrator/
│   ├── core/                      # lifecycle, VM state, paths, baseline cache
│   ├── scenarios/                 # declarative scenario engine
│   ├── forensics/                 # acquisition and tool runners
│   ├── adapters/                  # tool output -> ToolFinding
│   └── canonical/                 # canonical record models and JSONL I/O
├── detectors/                     # GT-blind rules -> DetectionClaim
├── matcher/                       # GT-aware matching, metrics, report
├── docs/                          # methodology and schema notes
├── shared/                        # generated experiment outputs
└── vendor/                        # vendored third-party rule/test data
```

Generated outputs under `shared/` are disposable artifacts, not source.

## Typical Workflow

```bash
# One-time host setup: sudoers, system dirs, libvirt network and storage pool
python cli.py init

# Prepare a distro: download image, create VM, build ISF, take baseline snapshot
python cli.py setup --distro ubuntu-22.04

# Run the registered thesis scenario, then acquire and evaluate evidence
python cli.py run --distro ubuntu-22.04 --scenario userland_father_ldpreload

# Local scenario-engine validation without VM acquisition
python cli.py run-scenario \
  scenarios/scenarios/userland_father_ldpreload/scenario.yml \
  --out-dir /tmp/father_local --run-id father_local

# Destroy a lab VM when finished with a distro
python cli.py destroy --distro ubuntu-22.04
```

Scenario keys come from `scenarios.yaml`. The current registered thesis
scenario key remains `userland_father_ldpreload`.

## Evidence Layers

- `ToolFinding`: broad normalized output from forensic tools. Raw evidence,
  never a final result.
- `DetectionClaim`: GT-blind candidate/supporting evidence emitted by rules.
  Not a verdict.
- Per-expectation outcomes (`outcomes.jsonl`): GT-aware match of candidate
  evidence against expected artifacts (identified / supported / missed).
- `metrics.json` and `report.md`: schema-v3 reconstruction metrics and reporting.

Detectors, adapters, and YAML rules must not read ground truth, expectations,
target paths, hashes, step names, or seeds. Ground truth belongs in matching,
metrics, reports, and explicit scenario/execution-truth generation.

## VM Contract

The lab uses two VM roles:

| Role | Network | Purpose | Lifecycle |
|---|---|---|---|
| `lab` | `forensics-isolated` | Runs controlled scenarios | Persistent, snapshots |
| `build-isf` | `default` | Builds Volatility3 ISF symbols | Ephemeral |

Memory acquisition requires the lab VM to be running. Disk acquisition requires
the lab VM to be powered off. Power transitions stay in the orchestrator, not in
tool wrappers.

## Configuration

Copy `config.yaml.example` to `config.yaml` and adjust paths for your machine.
`config.yaml` is local and gitignored.

Python setup:

```bash
./setup-venv.sh
source .venv/bin/activate
```

Host prerequisites include KVM/QEMU with libvirt, `cloud-localds`,
`ewfacquire`, and an SSH key for the lab VM.

## Optional ART Calibration

Atomic Red Team data is kept as an optional calibration input, not as the core
scenario model. The locked calibration subset lives under `scenarios/art/`, and
the vendored technique YAMLs live under `vendor/atomic-red-team/atomics/`.

The thesis scenarios are controlled by this framework and produce the canonical
execution truth, artifact expectations, normalized findings, candidate evidence,
matches, metrics, and score reports.
