# 02 Experiments

## Problem

Execute and record one approved DFIR scenario experiment: scenario run,
artifact collection, acquisition, and a factual per-scenario handoff. This stage
does not redesign code or modify source files, and does not re-derive forensic
facts (that is stage 03).

## Current state

- `ai/02_experiments/output/father/` contains a historical handoff for
  `father-u22-20260818-01`; do not treat it as the active/final run unless a
  task explicitly selects it.
- Run outputs live under `shared/experiments/<RUN_ID>/`.

## Required inputs (confirm before running)

scenario id; distro/profile; exact experiment command; target VM; expected
output directory; whether this is a final evidence run. If one is missing, ask
one concise question — do not scan the repo to infer it. Read only the files in
`ai/IDENTITY.md`'s read order plus the exact runner/command/investigation file
the user names; do not default-read README/TODO/METHODOLOGY/unrelated scenarios.

## Next steps

1. Execute only the approved command; preserve the complete run output.
2. Record scenario/distro/command/VM/times/status/artifact paths/validated
   behaviour/acquisition/cleanup/limitations under
   `ai/02_experiments/output/<scenario>/`.
3. Do not modify source files; run the DF investigation workflow only if
   explicitly requested.
