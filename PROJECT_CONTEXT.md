# PROJECT_CONTEXT.md

This is the single repo-level source of truth for coding agents working in
forensic-lab. Agent-specific files should point here instead of carrying
independent project truth.

## Project Identity

forensic-lab is a thesis-oriented Linux forensic reconstruction and evaluation
framework. It runs controlled VM scenarios, acquires disk/RAM/timeline evidence,
normalizes forensic tool output, and scores reconstruction quality against
ground truth.

The project priority is working code and presentable metrics for 3-4 scenarios.
It is not a production SIEM, EDR, malware sandbox, or general incident response
platform.

## Active Scope

The current primary scenario is `scenario_01_ldpreload` / Father_LDPRELOAD.
`scenarios.yaml` currently also registers `scenario_01_ldpreload_cleanup`,
`art_calibration`, and the declarative `userland_father_ldpreload` scenario.
Verify the registry before changing scenario behavior.

LKM, eBPF, CopyFail, ptrace/process injection, broader Sigma expansion, and
other advanced scenarios are future or secondary work until they are registered,
working end to end, and producing useful evaluation artifacts.

Before adding Timesketch, HashR, THOR Lite, Velociraptor, broader Sigma
coverage, or any new forensic tool, simplify the existing Father_LDPRELOAD
pipeline. A Timesketch Claude skill exists under `.claude/skills/`, but
Timesketch is not part of the active thesis pipeline until explicitly adopted.

Repeat this review question during planning:

> "This system may work, but is it too complex for the thesis deadline? Which part can be removed, flattened, or made explicit?"

## Official Pipeline

The thesis pipeline is:

1. scenario execution
2. ground truth/artifact expectations
3. acquisition
4. disk/RAM/timeline extraction
5. normalized tool findings
6. GT-blind candidate evidence
7. GT-aware matching
8. metrics/report

Reports must distinguish:

- raw finding
- candidate evidence
- matched reconstruction
- metric result

## Evidence Terminology

YAML rules are candidate/supporting evidence rules, not final detections. They
may emit candidate evidence for later matching, but they do not decide whether a
scenario objective was reconstructed.

`DetectionClaim`, where still used in code, means candidate evidence emitted by
GT-blind rules. It is not a final verdict. The GT-aware matcher and metrics
layer decide how candidate evidence relates to ground truth/artifact
expectations.

GT-blind rules, detectors, adapters, and candidate-evidence generation must not
read ground truth, scenario target paths, expected hashes, step names, or
artifact expectations. Ground truth is only allowed in GT-aware matching,
metrics, reports, and explicit scenario/execution-truth generation.

## Current Architecture Map

`cli.py` is the main entry point. It loads `scenarios.yaml`, builds runtime
objects for VM-facing commands, and also exposes offline evaluation commands
such as `score`, `pipeline`, `verify`, `run-scenario`, `run-detectors`, and
`match-canonical`.

`infra/` owns libvirt/QEMU infrastructure and host setup helpers.
`orchestrator/core/` owns experiment lifecycle, VM state coordination, paths,
and config loading.
`orchestrator/attacks/` owns executable attack/scenario modules.
`orchestrator/scenarios/` owns the minimal declarative scenario engine.
`orchestrator/forensics/` owns acquisition and forensic tool I/O wrappers.
`orchestrator/adapters/` converts tool output into canonical records.
`detectors/` and detector YAML rules emit GT-blind candidate evidence.
`matcher/` and `orchestrator/evaluation/match/` perform GT-aware matching.
`orchestrator/evaluation/metrics/` computes metric outputs.
`orchestrator/canonical/` contains canonical record models, including
`ToolFinding`, `DetectionClaim`, `MatchResult`, and metric records.

Generated experiment outputs under `shared/` are disposable artifacts, not
source files.

## Invariants

Preserve the VM power-state contract: memory acquisition requires the lab VM to
be ON; disk acquisition requires it to be OFF. Do not move power-state
transitions into forensic tool wrappers.

Keep scenario execution, acquisition, analysis, matching, and metrics as
separate phases. VM-facing commands may mutate lab state; offline evaluation
commands should operate on cached artifacts.

Do not change the VM mutation mechanism unless the task explicitly asks for VM
lifecycle refactor. Current code uses `ansible-playbook` in the VM manager path,
but instruction files should not promote a broad VM-mutation rewrite.

Preserve GT-blindness. Detectors and YAML rules must operate only on tool
findings and other approved non-GT inputs.

Keep changes small unless a task explicitly asks for a larger refactor. Prefer
the current codebase's structure and naming over inventing a new architecture.

## Current Short-Term Priority

The current priority is not to tune detector rules until Father_LDPRELOAD metrics look good. The priority is to make the post-mortem reconstruction pipeline defensible and generalizable:

1. keep `ToolFinding` as broad raw evidence;
2. keep `DetectionClaim` as GT-blind candidate/supporting evidence;
3. prevent weak candidates from becoming final thesis results directly;
4. derive final reconstruction from matched expectations / matched evidence;
5. compute simple metrics over the reconstruction layer, not over raw detector noise.

The current Father_LDPRELOAD cached result is:

* 7608 `ToolFinding` records
* 266 `DetectionClaim` records
* TP: 10
* FP: 256
* FN: 0
* precision: 0.0376
* recall: 1.0
* F1: 0.0725

This poor precision is mostly architectural: broad candidate evidence is being scored too directly, timeline findings dominate false positives, baseline-diff evidence is missing as a canonical source, memory findings need aggregation, and class-level matching is too permissive for headline thesis metrics.

Coding agents tend to over-engineer. During planning and after every few implementation patches, perform an explicit simplification review: identify unused paths, legacy code, boilerplate tests, duplicated abstractions, and places where the design can be flattened or made more explicit. Prefer KISS changes that support the thesis deliverable over new frameworks, new tools, or broad refactors.
