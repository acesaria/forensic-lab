# Repository Map

Status: orientation document for the current manual-investigation repository.
It does not replace `PROJECT_CONTEXT.md`, `AGENTS.md`, or `METHODOLOGY.md`.

## Thesis Direction

- Controlled Linux post-mortem forensic investigation.
- Reproducible scenario execution, disk acquisition, memory acquisition, and raw
  tool extraction.
- Evidence sources: filesystem state from TSK, timeline events from Plaso, and
  memory state from Volatility.
- Investigation remains manual; source-family correlation is analyst work.
- Vanilla means distro defaults.
- Hardened means one fixed documented native-control bundle.
- Ubuntu uses AppArmor.
- Fedora/SELinux is a postponed optional extension and is not part of the
  current committed matrix.
- Ubuntu 22.04 is the deep-analysis platform.
- Ubuntu 24.04 and Debian 13 receive targeted replication.
- Automatic detector claims, canonical matching, precision/recall metrics,
  ruleset hashes, and automatic reconstruction are legacy, not current thesis
  requirements.

## Migration State

Current runtime source contains the manual investigation path only. The old
automatic detector/matcher pipeline is preserved for comparison by the
immutable tag `automatic-reconstruction-v3-final`.

Do not reintroduce legacy automatic-evaluation areas into current source.

## Top-Level Layout

| Path | Purpose | Status | Touch now? |
|---|---|---|---|
| `cli.py` | Command entry point for setup, VM lifecycle, verification, scenario execution, acquisition, and raw extraction. | active | Touch only for named migration tasks. |
| `infra/` | libvirt/QEMU, Ansible, distro profiles, image helpers. | active | Ignore unless VM lifecycle/profile work is explicitly in scope. |
| `orchestrator/core/` | Lifecycle, VM state, run paths, config. | active | Preserve acquisition and provenance contracts. |
| `orchestrator/forensics/` | Acquisition and raw TSK/Plaso/Volatility tool runners. | active | Current extraction surface. |
| `scenarios/` | Explicit scenario runners and append-only command logging. | active/support | Keep scenario commands direct, deterministic, and bounded. |
| `docs/` | Orientation, methodology, and historical notes. | docs | Keep current docs aligned with the manual methodology. |
| `shared/` | Generated experiments, ISF files, and local artifacts. | generated/cache | Do not edit as source. |
| `.claude/`, `.github/` | Agent and assistant instruction surfaces. | support/docs | Keep lightweight; local settings may be stale. |
| `.venv/`, `.pytest_cache/`, `.vscode/` | Local environment/cache/editor state. | local/cache | Ignore or clean only when explicitly allowed. |

## Target Workflow

`scenario execution -> manifest/command log -> disk+memory acquisition -> raw TSK/Plaso/Volatility extraction -> manual investigation -> profile comparison -> thesis reporting`

| Step | Responsibility | Key files/modules |
|---|---|---|
| Scenario dispatch | Selects an explicit runner from the requested CLI scenario. | `cli.py`, `orchestrator/core/orchestrator.py` |
| Scenario execution | Runs readable commands through the existing SSH terminal and writes the run-root command log and minimal manifest index. | `scenarios/interactive_shell/runner.py`, `scenarios/userland_father_ldpreload/runner.py`, `scenarios/command_log.py` |
| Acquisition | Preserves VM power-state contract and writes `dumps/acquisition.json`: memory while VM is ON, disk after VM shutdown. | `orchestrator/core/orchestrator.py`, `orchestrator/forensics/dumper.py`, `orchestrator/core/vm_manager.py` |
| Raw extraction | Runs Sleuth Kit, Volatility3, and Plaso over acquired evidence. | `orchestrator/forensics/extract.py`, `sleuth_runner.py`, `vol_runner.py`, `plaso_runner.py` |
| Provenance | Keeps a minimal root index plus separate acquisition and raw-extraction status records. | `orchestrator/core/`, run output directories |
| Manual investigation | Analyst-authored correlation across raw filesystem, timeline, and memory outputs. | thesis notes/reports, raw exports under named runs |
| Profile comparison | Compares vanilla, hardened, and Father-only hardened+telemetry results without automatic scoring. | run artifacts and analyst notes |

## Legacy Automatic Pipeline

The old flow was:

`extraction/adapters -> normalized records -> detector claims -> canonical matching -> metrics/report`

That flow is no longer the current thesis methodology. It is preserved by the
immutable `automatic-reconstruction-v3-final` tag and may appear in archived
planning notes only, not as current runtime source.

## Notes For Future Agents

- Read `PROJECT_CONTEXT.md`, `AGENTS.md`, and `METHODOLOGY.md` before using this
  map.
- Do not infer current behavior from historical `TODO`, `REFACTOR`, `AUDIT`, or
  prompt files without checking current source.
- Treat `shared/baselines/*` and `shared/experiments/*` as generated artifacts;
  they may be evidence for a named run, not project instructions.
