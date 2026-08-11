# Thesis delivery queue

Updated 2026-08-11. This is the sole active execution plan. Verify mutable
implementation facts from the current source and preserve unrelated work.

## Hard deadlines

- By `2026-08-12 23:00`: send the supervisor a concise status email. Do not wait
  for optional infrastructure or cross-distribution work.
- By `2026-08-17`: freeze the abstract.
- By `2026-09-21`: complete the thesis, final project material, and slides.

## Gate 0 — storage and repository baseline

- Finish the read-only storage audit and set the required free-space target.
- Distinguish deletion, archival, compaction, and true virtual-disk shrinking.
- Preserve evidence and all three exact-profile builder VMs. Do not delete,
  shrink, rename, replace, or recreate a builder without explicit approval.
- Record the dirty worktree and registered worktrees before implementation.
- Require explicit approval before any destructive, privileged, VM, forensic,
  or commit operation.

## Implementation sequence

Complete exactly one task at a time. Each task requires a Codex plan, human
approval, bounded implementation, independent review, and an explicit commit
decision. Never push unless requested.

1. **Minimal prebuilt workflow and Father** — recheck the CLI end to end; add
   only the smallest explicit `build` workflow; resolve an exact prebuilt plus
   `build.json`; copy both into immutable run inputs; and convert Father retained
   and cleanup to one builder-produced `.so`. Validate Ubuntu 22.04 with
   `--no-acquire`. Ceiling: 350 changed text lines and 9 files.
2. **ptrace prebuilt conversion** — reuse Task 1's mechanism, remove victim-side
   compilation, and upload and execute the exact prebuilt. Validate Ubuntu 22.04
   with `--no-acquire`. Ceiling: 180 changed text lines and 5 files.
3. **Diamorphine retained and cleanup** — build for the exact target kernel,
   verify vermagic, implement only the bounded hidden-file/module and signal-64
   behavior, and fail closed on incompatibility. Validate Ubuntu 22.04 with
   `--no-acquire`. Ceiling: 320 changed text lines and 8 files.
4. **Bounded compatibility validation** — on Ubuntu 24.04 and Debian 13, run
   Father retained, ptrace, and Diamorphine retained with `--no-acquire`. Make no
   code changes by default. A compatibility fix needs separate approval and is
   limited to 80 changed lines per technique; otherwise record the limitation.
5. **Remove automatic forensic extraction and freeze** — stop new runs from
   automatically producing the TSK bodyfile, Plaso storage/JSONL, broad
   `vol3.json`, and `raw_extraction_status.json`; make prerequisite checks
   command-specific; preserve acquisition and input provenance; align current
   documentation and focused existing tests; and produce the final run command
   sheet. Ceiling: 280 changed text lines and 8 files.

For Tasks 1, 2, 3, and 5, review is read-only first and returns `PASS` or
`BLOCKED`. Commit only after `PASS` and explicit authorization. Task 4 needs
review and commit only if code changes.

## Frozen engineering and method boundaries

- Freeze runner, execute an immutable run, then investigate. Every run records
  the exact repository revision.
- Builders may use networking for explicit builds. Victims never build, install
  packages, or access the network during scenario execution.
- `run` consumes an already prepared compatible input and never mutates the
  builder cache. Missing or incompatible input fails before victim reset and
  prints the exact build command required.
- Father retained/cleanup share one `.so`; Diamorphine retained/cleanup share
  one exact-kernel `.ko`. Copy the selected artifact and `build.json` into the
  immutable run and index them in the manifest.
- Keep scenario validation, forensic observation, and analyst interpretation
  distinct. Target inventory and source applicability are prospective.
- Do not add automatic detection, matching, scoring, reconstruction, a build
  DSL, a scenario registry, new dependencies, or speculative abstractions.
- Do not modify or delete historical runs or raw outputs. A changed executor
  requires a new run; never relabel an earlier run.

## Authoritative experiment matrix

After Task 5, require a clean committed tree and execute these Ubuntu 22.04 full
acquisitions one at a time:

1. Father retained;
2. Father cleanup;
3. ptrace;
4. Diamorphine retained;
5. Diamorphine cleanup.

After each run, verify repository revision, scenario and acquisition statuses,
input hashes, acquisition hashes, EWF verification, and artifact sizes. Stop
before investigation if any gate fails. Retain all older experiment directories
until replacement runs and investigations are accepted.

## Investigation and writing

- Decide concise Father, ptrace, and Diamorphine investigation plans from the
  completed runs. Use only relevant TSK, Plaso, and Volatility commands in
  reproducible Runme notebooks; record versions, commands, output paths, hashes,
  failures, and valid zero results.
- Produce a small LaTeX results/implementation chapter with the accepted cases,
  reproducibility design, source complementarity, limitations, and figures.
- Write in the author's own voice, verify every claim, and disclose tool use as
  required by university policy. Do not use detector-evasion or "humanizer"
  workflows.
- Add an accurate thesis acknowledgment or methods disclosure for tools used in
  implementation, testing, and documentation.

## Deferred unless explicitly reopened

- Dynamic kernel-version verification for profile `kernel:` fields: Task 1
  adds a static, human-verified `kernel:` field to `infra/profiles/ubuntu-22.04.yaml`
  for pre-reset prebuilt-path resolution. Automatically resolving the actual
  kernel the first time it hasn't been checked, and updating the static field
  on a detected mismatch, is deferred for now;
- ftrace, Meterpreter, eBPF, CopyFail, ART, worms, timestomping, generalized
  cleanup levels, extra privilege-escalation scenarios, and broad hardening;
- Fedora/SELinux, Timesketch, Velociraptor, AIDE/NSRL, graphs/ontologies, and
  broad Sigma/YARA work;
- automatic detection, matching, scoring, reconstruction, new frameworks,
  architecture rewrites, major dependencies, and cosmetic CLI work; and
- read-only permissions for accepted memory/EWF files. This is optional
  defense-in-depth, not evidence immutability or an acceptance condition.
