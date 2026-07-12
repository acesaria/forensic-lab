# Active TODO - Manual Investigation Pivot

## Status

- This file is the active execution plan for the thesis migration phase.
- The repository is in a temporary migration state: documentation now describes
  the target manual multi-source investigation architecture, while the old
  automatic detector/matcher pipeline remains in source for later removal.
- Historical plans are archived under
  `docs/archive/stale-planning-2026-07-08/`.
- Do not use archived TODO/REFACTOR/AUDIT files as current instructions.

## Current Source Of Truth

1. `PROJECT_CONTEXT.md` and `AGENTS.md`, when present and current.
2. `METHODOLOGY.md` for manual investigation, provenance, profile comparison,
   and explicit non-goals.
3. `TODO.md` for the active execution order.
4. `docs/repo_map.md` for repository orientation.
5. Named run artifacts only as evidence for that run: manifest, command log,
   raw TSK/Plaso/Volatility exports, hashes, and analyst notes.

Generated `shared/` artifacts are evidence for a named run, not standing
project instructions.

## Immediate Next Task

Remove or quarantine the old automatic evaluation path after this documentation
stage.

Keep the next implementation pass focused on deleting or clearly fencing legacy
automatic reconstruction surfaces. Do not change scenario behavior, VM
orchestration, evidence acquisition, raw extraction, distro profiles, tests, or
dependencies unless the task explicitly asks.

Acceptance criteria:

- Current docs no longer present detector claims, canonical matching, or
  automatic metrics as thesis requirements.
- Manual investigation artifacts are the documented output surface.
- Legacy detector/matcher/canonical code is either removed or clearly fenced as
  migration-only.
- The immutable tag `automatic-reconstruction-v3-final` remains the reference
  for previous automatic reconstruction work.
- No new automatic scoring, rule profile, or ruleset-hash result is introduced.

Guardrails:

- Preserve deterministic scenario execution.
- Preserve minimal run manifests and append-only command logs.
- Preserve memory-ON and disk-OFF acquisition contracts.
- Preserve hashes, provenance, raw evidence immutability, and explicit tool
  failure reporting.
- Keep investigation manual.
- Keep automatic acquisition and raw TSK/Plaso/Volatility extraction in scope.
- Keep changes small and tests minimal.

## Next Phases

1. Legacy automatic pipeline removal/quarantine.
2. Manual investigation report template for a named run.
3. Ubuntu 22.04 deep-analysis Father no-cleanup and cleanup write-up.
4. Father cleanup hardened+telemetry comparison with `auditd`.
5. Targeted Ubuntu 24.04 and Fedora replication.
6. Thesis figures, limitations tables, and writing freeze.

## Explicit Deferrals

Defer these unless a later task explicitly reopens them:

- Timesketch integration.
- Velociraptor integration.
- AIDE/NSRL integration.
- Graph database or CASE/UCO full ontology.
- Broad Sigma/YARA corpus.
- Automatic detector/rule expansion.
- Automatic reconstruction or scoring.
- Precision/recall/F1 metric design.
- Ruleset hashes as experimental results.
- Large test rewrite.
- Broad architecture refactor.
- New major dependencies or platforms.

## Testing Warning

The current tests are useful smoke and source-shape guards for migration. They
do not prove forensic correctness, live acquisition reliability, thesis
validity, or manual investigation quality.

Use tests to catch regressions in code that remains active, then validate thesis
claims against explicit run artifacts, raw tool exports, command logs, hashes,
and analyst notes.
