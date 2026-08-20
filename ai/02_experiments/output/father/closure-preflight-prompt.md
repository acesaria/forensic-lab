# Claude prompt — Father experiment-set preflight

## Recommended executor

- Model: Claude Sonnet 5
- Effort: medium
- Mode: read-only, except for the single report file below

## Objective

Audit the current Father experiment set and produce an exact, deletion-safe plan
for one final acquired run on each of:

- `ubuntu-22.04`
- `ubuntu-24.04`
- `debian-13`

Do not run a scenario, operate a VM, delete data, or begin a forensic
investigation in this task. Ubuntu will be investigated later; the other two
distributions will stop after experiment validation and acquisition.

Start at `ai/INDEX.md` and follow ICM routing for stage `02_experiments`.

## Read/command allowlist

- ICM files required by the stage-02 read order.
- `ai/02_experiments/output/father/*.md`.
- Metadata and file listings only under `shared/experiments/father-*`:
  `manifest.json`, `dumps/acquisition.json`, acquisition status JSON files,
  and top-level artifact names/sizes. Do not read EWF segments or memory dumps.
- Directory names only under `shared/investigations/`, to identify dependent
  derived work. Do not interpret investigation findings.
- Read-only repository state: `git status`, current `HEAD`, and the recorded
  revision/cleanliness in each manifest.
- Read-only capability checks: `.venv/bin/python cli.py run --help` and
  `virsh list --all`. Do not start, reset, suspend, or shut down a VM.

## Required report

Write only:

`ai/02_experiments/output/father/closure-preflight-report.md`

Keep it concise and include:

1. A table for every existing Father experiment directory: run ID, distro,
   scenario status, overall status, acquisition status, recorded revision and
   working-tree state, dependent investigation directory, eligibility, and
   `keep / delete later / unresolved` recommendation.
2. Any mismatch between the existing stage-02 Father handoff and directories
   that actually exist.
3. Whether Ubuntu 22.04 must be rerun for the final three-distribution set,
   considering the current scenario key, current `HEAD`, acquisition status,
   and provenance. Do not treat a dirty revision as clean.
4. The proposed final three rows and exact commands, using the current scenario
   key `user_ldpreload_father`. Mark every not-yet-executed run `NOT RUN`.
5. The exact old experiment directories proposed for later deletion, their
   approximate sizes, and any derived investigation directories that depend on
   them. Do not delete anything.
6. Any blocker that must be resolved before producing final evidence runs,
   especially repository cleanliness, missing baselines/VMs, or ambiguous
   acquisition metadata.

Do not assign reconstruction states, forensic findings, coverage, temporal
error, or source-contribution metrics in this stage.

## Validation and stop gate

- Confirm that no VM state, experiment directory, investigation directory, or
  source file changed.
- Run `git diff --check` and report the scoped working-tree status.
- Stop immediately after writing the report. Do not delete old runs, execute
  Father, acquire evidence, edit the existing handoff, or start stage 03.
