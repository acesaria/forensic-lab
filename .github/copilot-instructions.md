# forensic-lab Copilot Instructions

Read `PROJECT_CONTEXT.md` first. It is the repo-level source of truth.

forensic-lab is a thesis-oriented Linux forensic reconstruction/evaluation
framework. Keep changes small and inspect current code before editing.

Important entry points:

- `cli.py`: CLI entry point and command routing.
- `scenarios.yaml`: scenario registry.
- `orchestrator/core/`: experiment lifecycle, config, paths, VM coordination.
- `orchestrator/forensics/`: acquisition and forensic tool I/O wrappers.
- `orchestrator/adapters/`: tool-output normalization.
- `detectors/`: GT-blind candidate evidence from tool findings.
- `matcher/` and `orchestrator/evaluation/match/`: GT-aware matching.
- `orchestrator/evaluation/metrics/`: metric computation.

Critical constraints:

- Preserve the VM power-state contract: memory acquisition requires VM ON; disk
  acquisition requires VM OFF.
- Preserve GT-blindness: detectors and YAML rules must not read ground truth,
  artifact expectations, scenario target paths, hashes, or step names.
- Treat YAML rules and `DetectionClaim` records as candidate evidence, not final
  detections or verdicts.
- Reports must distinguish raw finding, candidate evidence, matched
  reconstruction, and metric result.
- Do not change VM mutation mechanism unless the task explicitly asks for VM
  lifecycle refactor.
- Do not expand Timesketch, HashR, THOR Lite, Velociraptor, Sigma coverage, or
  new tools before the Father_LDPRELOAD pipeline is simple and working.

Coding guidance:

- Prefer existing repository patterns and explicit code.
- Avoid broad refactors unless explicitly requested.
- Keep VM-facing run/setup/destroy behavior separate from offline analysis.
- Treat generated outputs under `shared/` as disposable artifacts, not source.
