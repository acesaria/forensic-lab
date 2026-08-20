# Father experiment-set closure preflight report

Read-only audit. No VM, experiment directory, investigation directory, or
source file was changed by this task.

## 1. Existing Father experiment directories

All four directories under `shared/experiments/` are `ubuntu-22.04` runs.
There are **no** `debian-13` or `ubuntu-24.04` Father experiment directories
at all (checked, none found).

| run_id | distro | scenario_status | overall status | acquisition | recorded revision / working tree | dependent investigation dir | eligibility | recommendation |
|---|---|---|---|---|---|---|---|---|
| `father-u22-20260818-02` | ubuntu-22.04 | `completed` | `completed` | completed (memory + offline disk) | `fc381d5a4dd8...` / `modified` (dirty) | `shared/investigations/father-u22-20260818-02/` | not eligible as final run (see §3) | **keep** (has dependent investigation) |
| `father-u22-20260819-01` | ubuntu-22.04 | `completed` (scenario only) | `running` (never finalized — no `run_ended_at`, no acquisition manifest) | memory only; **no disk acquisition** (`dumps/disk/` absent) | `fc381d5a4dd8...` / `modified` (dirty) | none found | not eligible (incomplete run) | **delete later** |
| `father-u22-20260819-02` | ubuntu-22.04 | `completed` | `completed` | completed (memory + offline disk) | `fc381d5a4dd8...` / `modified` (dirty) | none found | not eligible as final run (see §3) | **delete later** |
| `father-u22-20260819-03` | ubuntu-22.04 | `completed` | `completed` | completed (memory + offline disk) | `fc381d5a4dd8...` / `modified` (dirty) | `shared/investigations/father-u22-20260819-03/` | not eligible as final run (see §3) | **keep** (has dependent investigation) |

All four manifests record `"scenario": "father"`. Codex supervisor review
confirmed that this is the current runner's intentional short manifest token:
`_SCENARIO_SHORT` maps the CLI key `user_ldpreload_father` to `father`.
Therefore this field does not establish which CLI spelling launched an old
run and is not, by itself, a reason to reject one.

## 2. Mismatch: stage-02 handoff vs. actual directories

The existing stage-02 Father handoff (`experiment-summary.md`, `artifacts.md`,
`metrics.md`, `handoff.md`) documents run_id **`father-u22-20260818-01`** and
directory `shared/experiments/father-u22-20260818-01/`. **This directory does
not exist.** The closest match by name/date is `father-u22-20260818-02`, but
its manifest timestamps (`scenario_started_at: 2026-08-18T18:54:59Z`) do not
match the handoff's narrative timestamps (`2026-08-18T15:00:13Z`), and its
`command_log.jsonl` size (4,844 B) matches all four runs identically — i.e.
the handoff was written against a run that has since been superseded/removed
and cannot be reconciled to any currently-existing directory. The stage-02
handoff should be treated as stale and not used as the closure basis.

## 3. Is a Ubuntu 22.04 rerun required for the final three-distribution set?

**Yes.** Codex supervisor review confirms the rerun, but corrects two claims in
the initial audit: `father` is the expected short manifest token, and commit
`fc381d5a...` is an ancestor of the current local and remote branch, not a
dangling commit. The valid reasons to rerun are:

- **Dirty working tree at run time**: every manifest records
  `"working_tree": "modified"` on top of the recorded commit.
  Per task instructions, a dirty revision is not treated as clean regardless
  of scenario outcome.
- **Changed execution/acquisition implementation**: current `HEAD` postdates
  the recorded revision and contains material changes to the CLI, orchestrator,
  acquisition path, and Father runner. The final three-distribution set should
  use the same current revision and procedure.
- **One run is incomplete**: `father-u22-20260819-01` never finished
  (`status: running`, no disk acquisition, no acquisition manifest, no
  `run_ended_at`).

None of the four runs is usable as the final Ubuntu 22.04 evidence run.
**Ubuntu 22.04 must be rerun** using the current scenario key
`user_ldpreload_father` against the current, clean `HEAD`.

## 4. Proposed final three rows (all `NOT RUN`)

| distro | scenario key | command | status |
|---|---|---|---|
| ubuntu-22.04 | `user_ldpreload_father` | `.venv/bin/python cli.py run --distro ubuntu-22.04 --scenario user_ldpreload_father` | **NOT RUN** |
| ubuntu-24.04 | `user_ldpreload_father` | `.venv/bin/python cli.py run --distro ubuntu-24.04 --scenario user_ldpreload_father` | **NOT RUN** |
| debian-13 | `user_ldpreload_father` | `.venv/bin/python cli.py run --distro debian-13 --scenario user_ldpreload_father` | **NOT RUN** |

`--acquire` is the documented default for `cli.py run` (memory + disk), so it
is omitted from the commands above; pass `--no-acquire` explicitly only if a
future task deliberately wants to skip acquisition (not recommended for final
evidence runs).

## 5. Old experiment directories proposed for later deletion

| run_id | approx. size | dependent investigation directory | notes |
|---|---|---|---|
| `father-u22-20260819-01` | ~2.1 GiB | none | incomplete run (no disk acquisition); safest to delete first |
| `father-u22-20260819-02` | ~3.8 GiB | none | completed but superseded (dirty older revision; no dependent investigation) |
| `father-u22-20260818-02` | ~3.8 GiB | `shared/investigations/father-u22-20260818-02/` | **do not delete until the dependent investigation directory's fate is decided** |
| `father-u22-20260819-03` | ~3.8 GiB | `shared/investigations/father-u22-20260819-03/` | **do not delete until the dependent investigation directory's fate is decided** |

Additionally, `shared/investigations/ubuntu-22.04_userland_father_ldpreload_20260722-175300/`
is a Father-related investigation directory (old pre-run-id naming
convention) with **no corresponding experiment directory** currently present
under `shared/experiments/` — its source run has already been removed at
some earlier point. Flagged for awareness only; no action taken.
`shared/investigations/ubuntu-22.04_ptrace_fa_20260807-150736/` is unrelated
(different scenario, `ptrace_fa`) and out of scope for this audit.

Nothing was deleted. No investigation directory contents were read or
interpreted — only directory names/existence were checked, per the read
allowlist.

## 6. Blockers before producing final evidence runs

1. **Repository cleanliness**: the working tree is currently dirty (19
   changed/untracked paths under `git status --porcelain`, all within `ai/`
   plus `.mcp.json`). Per the task's own standard ("do not treat a dirty
   revision as clean"), the three final runs should not be executed against
   this dirty tree if a clean-commit provenance record is required for the
   final evidence set. This needs an explicit decision: commit/clean the tree
   first, or accept and record `dirty` provenance for the final runs.
2. **Stale stage-02 handoff**: `ai/02_experiments/output/father/handoff.md`,
   `experiment-summary.md`, `artifacts.md`, and `metrics.md` all document a
   run (`father-u22-20260818-01`) that no longer exists and cannot be
   reconciled to any current directory (§2). These files should not be reused
   or trusted as-is once real final runs exist; they were not modified by
   this task.
3. **VM state**: `virsh list --all` shows all six lab/builder VMs
   (`lab-ubuntu-22.04`, `lab-ubuntu-24.04`, `lab-debian-13`, and their
   `builder-*` counterparts) as `shut off`. No baseline-snapshot check beyond
   this was performed (out of allowlist); confirm each target VM has a valid
   `baseline` snapshot before running.
4. **Dependent investigations**: two of the four old ubuntu-22.04 runs
   (`father-u22-20260818-02`, `father-u22-20260819-03`) have dependent
   investigation directories. Any deletion plan must resolve those
   investigations' status first — this is unresolved, not blocking the new
   runs themselves, but blocking cleanup of the old runs.
5. **No current-revision sample run**: no Father run exists from current
   `HEAD`, so there is no confirmation that the current runner and acquisition
   path complete end-to-end. Treat the first final run as that validation.

## Validation

- No VM was started, reset, suspended, or shut down; no experiment,
  investigation, or source file was created, modified, or deleted, other than
  writing this single report file.
- `git diff --check`: clean (exit 0, no whitespace/conflict-marker errors).
- Scoped working-tree status: 19 paths changed/untracked per
  `git status --porcelain` (pre-existing at task start; unchanged by this
  task) — `ai/02_experiments/CONTEXT.md`, `ai/03_investigation/CONTEXT.md`,
  `ai/03_investigation/references/investigation-architecture.md`,
  `ai/03_investigation/references/investigation-guidelines.md`,
  `ai/05_thesis/CONTEXT.md`, `ai/DECISIONS.md`, `ai/IDENTITY.md`,
  `ai/INDEX.md`, `ai/ROUTING.md`, `ai/STRUCTURE_MAP.md`, `ai/_config/done.md`,
  `ai/_config/review-report.md`, `ai/icm-cleanup-prompt.md`,
  `ai/thesis-finalization-plan.md` (modified), plus untracked `.mcp.json`,
  `ai/02_experiments/output/father/closure-preflight-prompt.md`,
  `ai/03_investigation/output/metrics-methodology-deep-research-report.md`,
  `ai/03_investigation/references/results-tables-methodology.md`,
  `ai/05_thesis/references/`.
- Stopping here per the stop gate: no scenario executed, no VM operated, no
  data deleted, no forensic investigation started, existing handoff not
  edited, stage 03 not started.
