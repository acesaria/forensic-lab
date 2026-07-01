# TODO_NOW - Canonical Father scenario first

Date: 2026-06-30
Scope: `attacks/scenarios/userland_father_ldpreload`

## Current decision

`userland_father_ldpreload` is the canonical thesis scenario. Stabilize this
Father-style LD_PRELOAD / accept-hook case before changing detector rules,
matcher semantics, metrics, or adding a second scenario.

## Immediate

1. Verify Father import/source integrity:
   - no scenario-local fake Father C files;
   - pristine pinned upstream archive or future submodule/vendor tree;
   - run-local configuration only.
2. Stabilize the Father scenario.
3. Run the canonical Father scenario.
4. Inspect generated truth, logs, and expectations:
   - `execution_truth.jsonl`
   - `artifact_expectations.jsonl`
   - `reference_context.json`
   - `command_log.jsonl`
5. Validate disk, RAM, timeline, and baseline-diff artifacts.
6. Only after the Father scenario is stable, simplify rules and metrics.

## Next

- Capture or emulate `.bash_history` / shell-session residue for a more natural
  attacker flow.
- Add timeline timestamp constraints for the preload file, installed `.so`,
  build directory, and scenario logs.
- Later evaluate the cleanup/evasion variant.
- Later add deterministic seeded randomization.
- Remove scenario-specific hardcoded detector strings.
- Improve baseline-aware filtering.
- Refine artifact classes and metric presentation.

## Deferred

- Cleanup/evasion variant.
- Deterministic seeded randomization.
- ptrace scenario.
- malicious LKM scenario.
- CopyFail privilege-escalation scenario.
- LPE scenario.
- second scenario.
- full APT scenario.
- SIEM, EDR, or live telemetry work.

## Guardrails

- Do not tune detector rules merely to improve the latest score.
- Do not introduce a large new architecture.
- Keep the pipeline post-mortem: disk, memory, timeline, clean baseline, and
  scenario expectations.
- Treat file hiding as contextual live-userland evidence, not a primary
  post-mortem artifact.
- Treat candidate precision as diagnostic only, not the thesis headline.
