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

The current primary and registered thesis scenario is the declarative
`userland_father_ldpreload` Father-style LD_PRELOAD / accept-hook scenario.
Legacy `scenario_01_ldpreload`, `scenario_01_ldpreload_cleanup`, and
`art_calibration` code remains in the tree for regression/history, but it is not
the normal thesis registry path. Verify `scenarios.yaml` before changing
scenario behavior.

LKM, eBPF, CopyFail, ptrace/process injection, broader Sigma expansion, and
other advanced scenarios are future or secondary work until they are registered,
working end to end, and producing useful evaluation artifacts.

forensic-lab owns RAM, disk, baseline comparison, ground truth, matching, and
metrics. Keep it post-mortem, simple, and thesis-deliverable.

Timesketch is an optional timeline sidecar only. It is not the active core and
must not become the primary metric backend. A Timesketch Claude skill exists
under `.claude/skills/`, but Timesketch is not part of the active thesis pipeline
until a task explicitly adopts it.

Do not add Timesketch, Sigma, YARA, baseline tooling, HashR, THOR Lite,
Velociraptor, OpenRelik, Dissect, FTK, package-DB integrity checks, or any other
external tool unless a task explicitly asks for it. Before adding any new tool,
simplify the existing Father_LDPRELOAD pipeline first.

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

Do not create a persisted `FinalClaim` model or a large final-claim architecture
unless a task explicitly requests it. Until a final-claim selection layer is
explicitly introduced, final reconstruction is derived from matched expected
artifacts / strong instance matches, and `DetectionClaim` stays candidate
evidence.

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

Headline metrics must not silently score raw findings or all candidate claims as
final reconstruction. Candidate precision/recall are diagnostics only. See
`docs/metrics_methodology.md` for the headline-vs-diagnostic split.

Next delivery sequence (do these in order; do not jump ahead to a second
scenario or to new tools):

1. metric semantics cleanup (headline vs diagnostic; postpone claim precision);
2. baseline-aware evidence/filtering;
3. generic rule cleanup (remove scenario-flavored tokens such as `father`);
4. only then a second scenario.

The Father_LDPRELOAD raw cached run is still the same experiment:

* 7608 `ToolFinding` records
* 10 `ArtifactExpectation` records

The ignored generated analysis artifacts under
`shared/experiments/ubuntu-22.04_userland_father_ldpreload_20260618-183143/analysis/`
may still contain the original pre-memory-dedup candidate stream:

* 266 `DetectionClaim` records
* 256 candidate FP

Current code regenerates the canonical Father detector/matcher output with:

* 255 `DetectionClaim` records
* TP: 10
* FP: 245
* FN: 0
* candidate precision: 0.0392
* recall: 1.0
* candidate F1: 0.0755
* strong instance matches: 7
* class-only/support matches: 3

Use current regenerated detector/matcher output for thesis-relevant numbers, not
stale ignored generated files in `shared/experiments/`. Candidate precision
remains poor mostly for architectural reasons: broad candidate evidence is being
scored too directly, timeline findings dominate false positives, baseline-diff
evidence is missing as a canonical source, and class-level matching remains
separate from strong instance reconstruction.

Coding agents tend to over-engineer. During planning and after every few implementation patches, perform an explicit simplification review: identify unused paths, legacy code, boilerplate tests, duplicated abstractions, and places where the design can be flattened or made more explicit. Prefer KISS changes that support the thesis deliverable over new frameworks, new tools, or broad refactors.
