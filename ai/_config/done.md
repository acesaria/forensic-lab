# Done criteria

Stage numbering matches `ai/ROUTING.md` (5 stages).

## 01_refactor
Done means:
- bounded target files updated
- behavior preserved unless explicitly allowed otherwise
- `git diff --check` passes
- only focused validation performed
- summary note written to `ai/01_refactor/output/`

## 02_experiments
Done means:
- scenario run/acquisition completed and recorded
- artifact paths captured
- validated scenario behaviour and acquisition status summarized factually
- per-scenario note written under `ai/02_experiments/output/<scenario>/`

## 03_investigation
Done means:
- forensic phase(s) executed against a real run (`RUN_ID`)
- derived outputs land only under `shared/investigations/<RUN_ID>/`
- each finding points to an evidence/output file
- limitations and unperformed checks are explicit
- the two active result tables are completed when the task reaches reporting
- partial/recovery/disputed classifications and arithmetic receive the bounded
  review required by `references/results-tables-methodology.md`
- handoff note written to `ai/03_investigation/output/`

## 04_docs
Done means:
- target README/docs updated directly
- content reflects validated stage 02/03 outputs only
- no speculative claims added
- summary note written to `ai/04_docs/output/`

## 05_thesis
Done means:
- `.tex` fragment produced
- fragment derived only from validated stage 02/03/04 materials
- limitations stated honestly
- fragment saved under `ai/05_thesis/output/`
