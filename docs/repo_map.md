# Repository Map

Status: orientation document for the Father/Scenario-F metrics cleanup pass.
It describes the current canonical thesis path and documents confusing surfaces;
it does not replace `PROJECT_CONTEXT.md`, `AGENTS.md`, or `METHODOLOGY.md`.

## Thesis Direction

- Controlled Linux post-mortem forensic reconstruction and evaluation.
- Evidence sources: disk, memory, timeline, clean baseline, and scenario
  expectations.
- `ToolFinding` is broad raw evidence from extraction/adapters.
- `DetectionClaim` is GT-blind candidate/supporting evidence, not a verdict.
- Final thesis-level outcomes are expectation-level matches after the matcher.
- Metrics are expectation-level; raw candidate precision/F1 is not a headline.
- Short-term work: Father/Scenario-F no-cleanup report, then cleanup variant,
  then one second full-depth scenario.
- Avoid new major platforms or broad integrations before the Father metrics
  story is stable.

## Top-Level Layout

| Path | Purpose | Class | Touch now? |
|---|---|---|---|
| `cli.py` | Command entry point for VM-backed runs and offline evaluation. | core | Touch only for CLI/report wording work. |
| `orchestrator/` | VM lifecycle, scenario execution, acquisition/extraction, adapters, canonical records. | core/support | Touch only the named subpackage for a task. |
| `detectors/` | GT-blind rule engine, rule YAML, and clean-baseline filtering. | core | Defer rule behavior changes until metrics cleanup asks for them. |
| `matcher/` | GT-aware matching, outcomes, metrics, and report rendering. | core | Primary area for expectation-level metrics/report cleanup. |
| `scenarios/` | Declarative scenario definitions and optional ART calibration subset. | core/support | Keep Father scope stable; do not edit payload/source code in hygiene work. |
| `infra/` | libvirt/QEMU, Ansible, distro profiles, image helpers. | support | Ignore unless VM lifecycle is explicitly in scope. |
| `docs/` | Orientation, audits, and historical notes. | docs | Use current docs first; refresh stale historical notes later. |
| `shared/` | Generated experiments, clean-baseline caches, ISF files, and local report artifacts. | generated/cache | Do not edit current Father/baseline artifacts during cleanup. |
| `vendor/` | Vendored third-party Sigma/YARA/ART data. | support/vendor | Do not touch in Father hygiene or metrics cleanup. |
| `.claude/`, `.github/` | Agent and assistant instruction surfaces. | support/docs | Keep lightweight; local settings may be stale. |
| `.venv/`, `.pytest_cache/`, `.vscode/` | Local environment/cache/editor state. | local/cache | Ignore or clean only when explicitly allowed. |

The old `orchestrator/evaluation/` source stack is retired. If that path appears
again as bytecode or empty directories, treat it as legacy residue, not active
source.

## Main Pipeline

Canonical flow:

`scenario execution -> acquisition -> extraction/adapters -> ToolFinding -> DetectionClaim -> matching/outcomes -> metrics/report`

| Step | Responsibility | Key files/modules |
|---|---|---|
| Scenario registry | Selects registered declarative scenarios. | `scenarios.yaml`, `cli.py` |
| Scenario execution | Runs `scenario.yml`, writes command log, execution truth, expectations, and reference context. | `orchestrator/scenarios/engine.py`, `loader.py`, `run_context.py`, `scenarios/scenarios/userland_father_ldpreload/scenario.yml`, `expected_observables.yml`, `steps.py` |
| Acquisition | Preserves VM power-state contract: memory while VM is ON, disk after VM shutdown. | `orchestrator/core/orchestrator.py`, `orchestrator/forensics/dumper.py`, `orchestrator/core/vm_manager.py` |
| Extraction | Runs Sleuth Kit, Volatility3, and Plaso over acquired evidence. | `orchestrator/forensics/extract.py`, `sleuth_runner.py`, `vol_runner.py`, `plaso_runner.py` |
| Adapters | Normalize raw tool output into canonical `ToolFinding` rows. | `orchestrator/adapters/common.py`, `sleuthkit/bodyfile.py`, `volatility3/json_output.py`, `plaso/jsonl.py`, `yara/matches.py` |
| Canonical records | Defines `GroundTruthEvent`, `ArtifactExpectation`, `ToolFinding`, `DetectionClaim`, and JSONL IO. | `orchestrator/canonical/models.py`, `io.py` |
| Clean baseline | Builds/reuses clean-baseline cache and filters known-good disk/timeline rows without GT. | `orchestrator/core/baseline_cache.py`, `detectors/baseline.py` |
| Detection claims | Runs GT-blind rule packs over canonical findings. | `detectors/engine.py`, `detectors/rules/**` |
| Matching/outcomes | Compares claims/findings to expectations in the only GT-aware layer. | `matcher/engine.py` |
| Metrics/report | Writes `outcomes.jsonl`, `metrics.json`, and `report.md`. | `matcher/engine.py`, `cli.py`, `orchestrator/core/orchestrator.py` |

Offline evaluation commands in `cli.py` (`run-adapters`, `run-detectors`,
`match-canonical`) operate on cached artifacts and do not require VM
orchestration.

## Tracked `engine.py` Files

| Path | Role | Confusing? | Decision |
|---|---|---|---|
| `detectors/engine.py` | GT-blind rule runner from `ToolFinding` rows to `DetectionClaim` rows. | Mildly generic name, but package path is clear. | Document only; do not rename now. |
| `matcher/engine.py` | GT-aware expectation matcher, metric builder, and report/console renderer. | Central file with a broad name. | Document only; renaming would add churn before metrics cleanup. |
| `orchestrator/scenarios/engine.py` | Minimal declarative `scenario.yml` runner. | Similar name to the other engines. | Document only; package path makes role clear. |

The duplicate `engine.py` names are now documented. They should not be renamed
before Father metrics/rule cleanup unless a concrete maintenance problem appears.

## Notes For Future Agents

- Read `PROJECT_CONTEXT.md`, `AGENTS.md`, and `METHODOLOGY.md` before using this
  map.
- Do not infer current behavior from historical `TODO`, `REFACTOR`, `AUDIT`, or
  prompt files without checking current source.
- Treat `shared/baselines/*` and `shared/experiments/*` as generated artifacts;
  current Father/baseline outputs may still be needed for metric comparison.
- Treat Sigma/YARA references as planned/future unless a task proves the path is
  currently wired into the canonical pipeline.
