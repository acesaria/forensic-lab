# 02 Experiments

## Problem

Execute and record one approved DFIR scenario experiment: scenario run,
artifact collection, metrics, and a factual per-scenario handoff. This stage
does not redesign code or modify source files, and does not re-derive forensic
facts (that is stage 03).

## Current state

- Last run: `userland_father_ldpreload`, ubuntu-22.04/vanilla, final evidence
  run `father-u22-20260818-01`. Notes under
  `ai/02_experiments/output/father/` (experiment-summary, artifacts, metrics,
  handoff).
- Run outputs live under `shared/experiments/<RUN_ID>/`.

## Required inputs (confirm before running)

scenario id; distro/profile; exact experiment command; target VM; expected
output directory; whether this is a final evidence run. If one is missing, ask
one concise question — do not scan the repo to infer it. Read only the files in
`ai/IDENTITY.md`'s read order plus the exact runner/command/investigation file
the user names; do not default-read README/TODO/METHODOLOGY/unrelated scenarios.

## Next steps

1. Execute only the approved command; preserve the complete run output.
2. Record scenario/distro/command/VM/times/status/artifact paths/results/
   metrics/cleanup/limitations under
   `ai/02_experiments/output/<scenario>/`.
3. Do not modify source files; run the DF investigation workflow only if
   explicitly requested.
