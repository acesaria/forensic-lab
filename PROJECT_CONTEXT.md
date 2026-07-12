# PROJECT_CONTEXT.md

Repo-level source of truth for anyone (human or coding agent) working in
forensic-lab. Facts only; behavioral rules live in AGENTS.md.

## Identity

forensic-lab is a thesis-oriented Linux post-mortem forensic investigation
lab. It reproducibly executes controlled Linux compromise scenarios, acquires
disk and memory evidence, automatically produces raw TSK, Plaso, and
Volatility exports, and supports manual multi-source investigation across
filesystem, timeline, and memory evidence.

The current thesis contribution is reproducibility, acquisition, raw extraction,
manual correlation, profile comparison, provenance, and explicit documentation
of tool limitations including negative findings.

It is NOT a production SIEM, EDR, live-telemetry platform, automatic detector,
automatic reconstruction system, or general incident-response system, and must
not grow toward one.

## Migration state

The repository is temporarily in a migration state. Documentation now describes
the target manual-investigation architecture. The old automatic
detection/matching/reconstruction pipeline has been removed from current
runtime source. Historical documentation and generated artifacts may still
refer to it.

Previous automatic reconstruction work is preserved by the immutable tag
`automatic-reconstruction-v3-final`. Treat that tag as the reference for the
old detector/matcher/metrics contribution, not as current methodology.

## Official workflow

1. controlled scenario execution (declarative `scenario.yml`)
2. minimal run manifest and append-only command log
3. acquisition (memory with VM ON, disk with VM OFF)
4. hash and provenance recording for acquired evidence
5. raw filesystem extraction with TSK
6. raw timeline extraction with Plaso
7. raw memory extraction with Volatility
8. manual investigation and correlation across filesystem, timeline, and
   memory evidence
9. vanilla vs hardened profile comparison
10. written findings, negative findings, tool failures, and limitations

Automatic acquisition and raw extraction remain in scope. Investigation and
interpretation remain manual. Automatic scoring is not a current deliverable.

## Evidence terminology

- Controlled scenario: scripted, deterministic lab compromise using a classic,
  documented Linux technique.
- Run manifest: minimal run metadata needed to identify the scenario, platform,
  profile, tools, evidence paths, and hashes.
- Command log: append-only record of scenario and orchestration commands.
- Acquired evidence: immutable disk and memory images, with hashes and
  provenance.
- Raw export: unscored TSK, Plaso, or Volatility output produced from acquired
  evidence.
- Investigation note: analyst-authored interpretation that cites raw exports,
  command logs, provenance, and tool failures.
- Prevented scenario: a hardened profile blocks a scenario step; remaining
  evidence and denial traces are still acquired and analysed.

`ToolFinding`, `DetectionClaim`, canonical matching, precision/recall metrics,
automatic reconstruction, and ruleset hashes are legacy automatic-evaluation
terms. They are not normative requirements for the current thesis.

## Current architecture map

- cli.py                     entry point; setup, VM, verification, scenario and acquisition commands
- infra/                     libvirt/QEMU, Ansible, distro profiles
- orchestrator/core/         lifecycle, VM state, paths, config
- orchestrator/scenarios/    declarative scenario engine
- orchestrator/forensics/    acquisition + tool runners (plaso/vol3/tsk)
- scenarios/scenarios/       scenario.yml + steps.py

Registered thesis scenario:
- userland_father_ldpreload  scenarios/scenarios/userland_father_ldpreload/scenario.yml

The old detect/match/metrics stack under `orchestrator/evaluation/`, the
ART/module execution path under `orchestrator/scenario_execution/`, the
`gt_manifest` migration shim, the detector/matcher/canonical source packages,
and the automatic finding-baseline cache have been removed.

Generated outputs under shared/ are disposable artifacts, not source.

## Invariants

- Memory acquisition requires the VM ON; disk acquisition requires the VM OFF.
  Power transitions stay in the orchestrator, never inside tool wrappers.
- Scenario execution is deterministic and writes a minimal manifest plus an
  append-only command log.
- Acquired raw evidence and raw tool exports are immutable once written; later
  analysis writes separate notes or derived artifacts.
- Evidence hashes and provenance are retained for disk images, memory images,
  and raw exports.
- Tool failures are recorded explicitly, including empty or negative results.
- Manual investigation is evidence-led and keeps filesystem, timeline, and
  memory source families distinguishable.
- Timesketch is an optional timeline sidecar, never the analysis backend.
