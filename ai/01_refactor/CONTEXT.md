# 01 Refactor

## Problem

Perform bounded, behavior-preserving refactors: simplify reader-facing
structure and reduce clearly-safe duplication without redesigning anything.

## Current state

- Last completed task: Father scenario integration (recon quieting +
  evidence-preserving cleanup). Handoff:
  `ai/01_refactor/output/father-rootkit-integration.md`.

## Rules

- Minimal diffs; no large abstractions; no rewriting unrelated modules.
- Do not add tests unless strictly required to confirm a breakage.
- Do not update README or thesis files here (see `ai/_config/scope.md`).

## Next steps

- Run any new refactor against a single named target; validate narrowly; run
  `git diff --check`; write a handoff note to `output/` (objective, files
  changed, validations run, known risks, recommended next stage).
