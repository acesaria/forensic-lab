# CONTEXT.md

Map of the forensic-lab codebase for audit and simplification work. Describes
what each part is *supposed* to do, so a reviewer can judge whether the code
matches its job. Pair with RULES.md (the guardrails and audit method).

## System Overview
* **System Name:** forensic-lab
* **Primary Function:** Reproducible Linux DFIR Thesis Lab
* **Target Audience:** Code Reviewer / Auditor
* **Key Objective:** Verify alignment between implementation and architectural rules

---

## Core Choreography (The Experiment Cycle)
Every experiment execution must rigidly follow this linear sequence:
1. **Provisioning:** Spin up a clean KVM/libvirt VM from a pinned cloud image.
2. **Snapshot:** Capture the pristine state as `baseline` (once per distro).
3. **Kernel ISF:** Build a Volatility3 ISF via an ephemeral VM if missing.
4. **Attack:** Run an ART-derived attack scenario (`LD_PRELOAD`, rootkits, injection).
5. **Acquisition:** Extract a live RAM dump and an offline disk image (EWF `.E01`).
6. **Scoring:** Parse outputs with forensic tools and score against a ground-truth manifest.

Single entry point: `cli.py`. Configuration inferred from `config.yaml`, `scenarios.yaml`, and `infra/profiles/<distro>.yaml`.

---

## Architectural Constraints & Data Flow

### Size & Gravity
* **Total Codebase:** ~9.6k LOC Python
* **Audit Center of Gravity:** The `evaluation/` block accounts for ~4.8k LOC (50% of the codebase).

### Dependency Direction (Strict One-Way)
[cli] ➔ [orchestrator] ➔ [vm_manager] ➔ [infra/provider]└── [forensics/dumper]│▼[evaluation] ➔ [forensics (runners)]

* **Invariant:** The infrastructure layer (`infra/`) must only be reached via the `Provider` interface through `VMManager`.

### Execution Paths
* **Online Half (Mutable State):** `cli` ➔ `orchestrator` ➔ `vm_manager` ➔ `infra/provider` + `forensics/dumper` for acquisition. Mutates VMs.
* **Offline Half (Immutable State):** `score` / `pipeline` / `verify` subcommands. Bypasses host prerequisite checks and orchestrator entirely. Runs strictly over cached artifacts.

---

## CLI Subcommands Matrix

| Command | Touches VM | Operational Target & Role |
| :--- | :---: | :--- |
| `init` | **Host Only** | Installs sudoers, system directories, libvirt network, and storage pool (requires root). |
| `setup` | **Yes** | Provisions the lab VM, captures baseline snapshot, builds ISF, and runs environment verification. |
| `run` | **Yes** | Reverts to baseline state, executes threat scenario, and acquires RAM + disk images. |
| `analyze` | **No** | Re-detects and re-scores threat artifacts using already cached dumps. |
| `destroy` | **Yes** | Permanently tears down the lab VM and removes its storage volumes. |
| `score` | **No** | Performs entity matching and computes metrics by evaluating `findings.jsonl` against `gt_manifest.json`. |
| `pipeline` | **No** | Parses raw cached tool logs, triggers detections, runs entity matching, and outputs performance metrics. |
| `verify` | **No** | Validates pinned tool versions and outputs the cryptographic hash of the active ruleset. |

---

## Area Component Maps

### `cli.py` (~415 LOC) — System Ingress
* **Role:** Handles CLI argument routing for all 8 subcommands via `argparse`.
* **Mechanism:** Assembles the runtime graph (`Provider` ➔ `VMManager` ➔ `Dumper` ➔ Runners) once, injecting the global `ProjectPaths` reference everywhere.
* **Gatekeeper:** `_check_prerequisites()` hard-blocks execution if 9 specific host external binaries are missing.

### `infra/` (~679 LOC) — KVM/Libvirt Abstraction
* `provider.py`: Direct wrapper around `libvirt-python`/`virsh`. Owns VM lifecycle, isolated host-only network, and storage pool allocations.
* `image_store.py`: Handles downloading and checksum verification of base cloud images.
* `profiles/`: Distro-specific YAML profiles pinning target environments (Ubuntu 22.04/24.04, Debian 13).
* `ansible/`: **The only sanctioned mechanism allowed to mutate a lab VM's internal state**. Contains playbooks for base configuration (`lab_baseline`), kernel profile generation (`isf_build`), and attack execution (`rootkit_deploy`).

### `orchestrator/core/` (~1.8k LOC) — State Machine & Lifecycle
* `orchestrator.py` (`ForensicOrchestrator`): Centralizes the high-level experiment verbs. Enforces the VM power-state contract: **memory capture requires an active VM (ON), disk imaging requires a stopped VM (OFF)**. Guarantees the safety invariant: *"Leave the VM destroyed on error to prevent cascading state contamination"*.
* `vm_manager.py`: Controls lab VM operations by delegating tasks to the `Provider` layer.
* `paths.py` & `config.py`: Exposes `ProjectPaths` and handles structural loading of `config.yaml`, `scenarios.yaml`, and constants.

### `orchestrator/attacks/` (~835 LOC) — Offense Engine
* `art_runner.py`: Parses Atomic Red Team (ART) atomic test YAML files directly and executes them over SSH (eliminates runtime dependencies on `atomic-operator`).
* `scenario_01_ldpreload.py`: **The single active production scenario**. Features a multi-step `run()` loop with embedded Ground Truth recording hooks (`_record()`) and an explicit cleanup path managed by `run_cleanup`.
* `attack_0{1,5,6}_*.py`: Git-ignored WIP scripts (ptrace, metasploit, kernel rootkits). Disregard during core pipeline auditing.

### `orchestrator/forensics/` (~1.5k LOC) — Tool I/O Wrapper
* **Constraint:** Purely agnostic translation layer. **Zero detection or scoring logic is permitted here**.
* **Components:** `dumper.py` (RAM acquisition via `virsh dump`, disk access via `qemu-nbd` + `ewfacquire`), specific runners for processing tools (`vol_runner.py`, `sleuth_runner.py`, etc.), and strict ISO-8601 UTC millisecond formatting via `timeutil.py`.

### `orchestrator/evaluation/` (~4.8k LOC) — Analysis & Metrics
* `pipeline.py`: Coordinates the offline 3-stage validation pipeline (`run_from_raw` vs `run_score`).
* `extract/`: Normalizes heterogeneous external outputs from `tsk`, `vol3`, and `plaso` into structured schemas.
* `detect/`: **Strictly Ground-Truth-blind heuristics running over raw tool output**. The driver (`run.py`) runs all detectors (e.g., `tsk_heuristics`, `plaso_sigma`). Blindness boundaries are defensively verified by `test_detect_blindness.py` and `test_rule_leakage.py` to prevent any data leak from the ground truth.
* `match/` & `metrics/`: `matcher.py` correlates blind detections with `gt_manifest.json`. `compute.py` calculates micro-averaged Precision, Recall, and F1-scores.
* `contracts/`: Implements runtime dataclasses (`models.py`) and schema validation (`validate.py`) across all stage boundaries.

---

## Operational Data Flow Diagram

### Online Run Execution (`run`)
[Scenario Trigger] ➔ Ground Truth Hooks ➔ gt_manifest.json[Acquisition Target] ➔ RAM/Disk Dumps ➔ manifest.json[Detect Phase] ➔ Extractors ➔ Detectors ➔ findings.jsonl[Match Phase] ➔ findings.jsonl + gt_manifest.json ➔ matches.json[Metrics Phase] ➔ metrics.csv + report.md

### Offline Run Execution (`pipeline`)
[Cached Raw Artifacts] (timeline.jsonl / vol3.json / bodyfile) ➔ [Detect Phase] ➔ Match ➔ Metrics
---

## Audit Hotspots (High-Risk Targets)

1. **Over-Engineering in `evaluation/`:** The `detect/`, `match/`, and `metrics/` directories harbor 50% of the entire codebase complexity. Look for unnecessary abstractions here.
2. **Ground Truth Leakage Boundary:** Extensively review `extract/` adapters and `detect/` rules. Ensure no aspect of the `gt_manifest.json` schema leaks into or influences the blind detection heuristics.
3. **Layer Violations:** Confirm that code dependency remains strictly one-way (`core ➔ evaluation ➔ forensics`) and that `infra/` is never circumvented or called outside of the `Provider` interface.
4. **Working-Tree Drift:** Audit the current `git diff` explicitly, not just the clean HEAD. There are ~12 modified files, a deleted `docs/` directory, and untracked tools (`dfir-tools/ftkimager`).
5. **Active Surface Area:** Only `scenario_01_ldpreload` is functional. Scope your code execution review strictly to this module and ignore `attack_0{1,5,6}` files.
