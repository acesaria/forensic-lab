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


## !!! Extra (manually added, need to refactor and replaced in this file)
- there are still some minor problems on scenario userland_father_ldpreload:
  - (current output):
```
=== experiment: userland_father_ldpreload on ubuntu-22.04 ===
[*] reverting 'lab-ubuntu-22.04' to baseline snapshot...
[*] shutting down 'lab-ubuntu-22.04' before snapshot revert...
[+] VM 'lab-ubuntu-22.04' shut down gracefully
[+] VM 'lab-ubuntu-22.04' reverted to 'baseline'
[*] waiting for SSH on lab-ubuntu-22.04 (192.168.100.36)...
[+] SSH ready on lab-ubuntu-22.04 (192.168.100.36)
[i] clean baseline cache reused: /home/anto/forensic-lab/shared/baselines/lab-ubuntu-22.04-baseline-c94f1200087a/tool_findings.jsonl
[1/7] prepare_father_source - using pinned upstream Father archive
[2/7] configure_father - applying run-local Father configuration
[3/7] build_father_rootkit - running make father
[i] NAT NIC link up
[i] NAT NIC link down
[4/7] install_preload_rootkit - installing rk.so into scenario preload path
[5/7] trigger_accept_hook_capability - exercising accept hook with bounded password failure
[6/7] observe_file_hiding_effect - comparing live listing before/after hook
[7/7] record_postconditions - verifying mapped library, hook result, hashes
```
  - problem 1: NAT NIC link up should appear on 1/7 preparation/prerequisites while NAT NIC link down should appear immediatly after that (logically is the best way)

  - problem 2: steps messages ( [1/7] ..., [2/7] ..., ecc..) should use some 'decoration' using appropriate logging function (choose the appropriate one).. moreover since is an "internal phase" it should have identation
