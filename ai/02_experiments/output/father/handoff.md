# Handoff — userland_father_ldpreload final evidence run

## Task

Execute the approved final evidence run of the `userland_father_ldpreload` scenario
(ubuntu-22.04, vanilla profile, VM `lab-ubuntu-22.04`, target 192.168.100.32) using
the exact command:

```
.venv/bin/python cli.py run --distro ubuntu-22.04 --scenario userland_father_ldpreload
```

## Files produced (this stage)

- `ai/02_experiments/output/father/experiment-summary.md`
- `ai/02_experiments/output/father/artifacts.md`
- `ai/02_experiments/output/father/metrics.md`
- `ai/02_experiments/output/father/handoff.md` (this file)

## Artifacts produced (run output, outside `ai/`)

- `shared/experiments/father-u22-20260818-01/` — full run directory: manifest, transcript, command log, staged inputs, memory dump, disk image (EWF), acquisition manifest. See `artifacts.md` for the itemized breakdown.

## Validations performed

- Confirmed all required experiment parameters with the user before running (scenario, distro/profile, VM, target IP, exact command, final-run status).
- Ran only the exact approved command; did not search for or substitute another command.
- Did not modify any source files.
- Did not run any other scenario.
- Did not run the DF investigation workflow (not explicitly requested in this task).
- Verified `manifest.json` reports `scenario_status: completed` and `status: completed`.
- Verified disk image integrity via the run's own `ewfverify` step (`SUCCESS`, hash match).
- Confirmed cleanup behavior matches the evidence-preserving default described in `ai/01_refactor/output/father-rootkit-integration.md` (no log truncation; only staged artifact removal and history clearing).

## Blockers

None. Run completed end-to-end with no errors.

## Known limitations carried from Phase B (unchanged, not re-tested here)

- Adjacent-hidden-file demonstration remains single-view (hooked listing only), not a two-view hooked-vs-bypass comparison.
- No stronger-evasion cleanup profile (log truncation) exists; out of scope for this run.
- Repository working tree was `-dirty` at run time (commit `fc381d5a...-dirty`) — the run reflects the current working tree state, not a clean commit. This is noted for traceability only; no source files were modified by this experiment stage.

## Next recommended stage

`03_docs` — this validated final evidence run (completed scenario, verified acquisition, confirmed recon/cleanup behavior) is suitable as input for factual scenario documentation, and subsequently for `04_thesis` fragment drafting.
