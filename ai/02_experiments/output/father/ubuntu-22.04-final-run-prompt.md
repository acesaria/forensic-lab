# Claude prompt — Father Ubuntu 22.04 final run

## Recommended executor

- Model: Claude Sonnet 5
- Effort: medium
- Mode: execute one approved experiment and record it

## Objective

Produce exactly one final acquired Father run on `ubuntu-22.04` from the clean
current repository revision. Validate the experiment and acquisition only.
Do not delete old runs or start a forensic investigation.

Start at `ai/INDEX.md` and follow ICM routing for stage `02_experiments`.

## Preconditions

1. Record `git rev-parse HEAD`.
2. Run `git status --porcelain`. If it returns any path, do not run the
   experiment; write the blocker to the output file below and stop.
3. Confirm `lab-ubuntu-22.04` is shut off and has a snapshot named `baseline`.
   These checks are read-only. If either condition fails, report and stop.

Do not run setup, build, destroy, or any other scenario command.

## Approved command

Run exactly once:

```bash
.venv/bin/python cli.py run --distro ubuntu-22.04 --scenario user_ldpreload_father --acquire
```

If it fails, preserve the failed run and stop. Do not repair source code,
reset the VM manually, delete the run, or retry automatically.

## Required validation

Identify the new run directory created by this command and verify from its own
records:

- `manifest.json`: expected run ID/distro, `scenario_status=completed`,
  `status=completed`, recorded commit equals the pre-run `HEAD`, and recorded
  working tree is `clean`;
- the acquisition manifest exists and reports completed memory and offline
  disk acquisition;
- the memory image and EWF disk segments exist with the hashes/status records
  named by the acquisition manifest;
- the final VM state is off;
- no source or investigation file changed.

Do not read or interpret memory/disk contents. Scenario validation facts may be
reported as experiment results, not forensic findings.

## Write allowlist

The run command may create its normal directory under `shared/experiments/`.
Write only one ICM handoff:

`ai/02_experiments/output/father/final-runs.md`

Create or update it with:

1. the scenario-execution table containing the new Ubuntu row plus
   `NOT RUN` rows for `ubuntu-24.04` and `debian-13`;
2. the exact command, run ID, revision, timestamps, bounded behaviour
   validation, acquisition status and paths/hashes, and limitations;
3. explicit notice that old Father runs and their investigations remain
   untouched and are not final results.

## Stop gate

Stop after validating and documenting this one Ubuntu run. Do not run another
distribution, delete old experiment/investigation directories, edit the stale
legacy Father handoff files, run disk/memory/timeline analysis, calculate
coverage, or modify source code.
