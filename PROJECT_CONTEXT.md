# PROJECT_CONTEXT.md

Repo-level source of truth for anyone (human or coding agent) working in
forensic-lab. Facts only; behavioral rules live in AGENTS.md.

## Identity

forensic-lab is a thesis-oriented Linux post-mortem forensic reconstruction
and evaluation framework. It runs controlled VM scenarios, acquires disk /
RAM / timeline evidence, normalizes forensic tool output, and scores
reconstruction quality against artifact expectations.

It is NOT a production SIEM, EDR, live-telemetry platform, or general
incident-response system, and must not grow toward one.

## Official pipeline

1. controlled scenario execution (declarative scenario.yml)
2. artifact expectations (ground truth, written at execution time)
3. acquisition (memory with VM ON, disk with VM OFF)
4. disk / RAM / timeline extraction
5. normalized ToolFinding records (canonical adapters)
6. GT-blind candidate evidence: DetectionClaim records (detectors/)
7. GT-aware expectation matching (matcher/)
8. metrics + score report

Evaluation semantics (vocabulary, matching rules, metric definitions) are
normative in METHODOLOGY.md; matcher/metrics code implements that page.

## Evidence terminology

- Raw finding      = ToolFinding. Broad extracted evidence. Never a result.
- Candidate evidence = DetectionClaim. GT-blind, supporting only. Not a verdict.
- Matched outcome  = per-expectation outcome in outcomes.jsonl
  (identified / supported / missed; contextual if not scored).
- Metric result    = metrics.json / report.md, schema v3 (METHODOLOGY §6).

Ground truth is read ONLY by matching, metrics, reports, and explicit
scenario/execution-truth generation. Detectors, adapters, and rules must
never read expectations, target paths, hashes, step names, or seeds.

There is no persisted FinalClaim model. Final reconstruction is derived from
identified expectations.

## Current architecture map

- cli.py                     entry point; VM commands + offline evaluation
- infra/                     libvirt/QEMU, ansible, distro profiles
- orchestrator/core/         lifecycle, VM state, paths, config, baseline cache
- orchestrator/scenarios/    declarative scenario engine (canonical)
- orchestrator/forensics/    acquisition + tool runners (plaso/vol3/tsk)
- orchestrator/adapters/     tool output -> ToolFinding
- orchestrator/canonical/    canonical record models + JSONL io
- detectors/                 GT-blind rules -> DetectionClaim
- matcher/                   GT-aware matching + metrics + report (canonical)
- scenarios/scenarios/       scenario.yml + expected_observables.yml + steps.py

Registered thesis scenario:
- userland_father_ldpreload  scenarios/scenarios/userland_father_ldpreload/scenario.yml

The old detect/match/metrics stack (orchestrator/evaluation/), the ART/module
execution path (orchestrator/scenario_execution/), and the gt_manifest
migration shim (orchestrator/canonical/legacy.py) have been removed.

Generated outputs under shared/ are disposable artifacts, not source.

## Invariants

- Memory acquisition requires the VM ON; disk acquisition requires the VM OFF.
  Power transitions stay in the orchestrator, never inside tool wrappers.
- Scenario execution, acquisition, analysis, matching, and metrics are
  separate phases. Offline commands operate on cached artifacts only.
- Headline metrics score matched reconstruction against expectations -
  never raw findings, never the whole candidate stream.
- Timesketch is an optional timeline sidecar, never the metric backend.
