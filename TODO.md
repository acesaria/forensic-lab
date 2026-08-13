# Thesis delivery queue

Updated 2026-08-13. This is the sole active execution plan. Verify mutable
implementation facts from the current source and preserve unrelated work.

## Hard deadlines

- `2026-08-12 23:00` supervisor status email: **overdue, not sent** as of
  2026-08-13 — deliverables were not ready. Send it as soon as a truthful
  concise status exists; do not keep waiting for optional infrastructure or
  cross-distribution work to look further along than it is.
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

1. **Minimal prebuilt workflow and Father** — DONE (`33d0073`, `1490697`,
   `7010c86`). `cli.py build` compiles Father on the builder and publishes
   `rk.so` plus `build.json`; `run` verifies and stages both into the immutable
   run before touching the victim. Compatibility is keyed on the profile's
   pinned image checksum, not the kernel. The former retained and cleanup keys
   were validated on Ubuntu 22.04 with `--no-acquire`, including the build,
   idempotent rebuild, and fail-closed negative test. The consolidated
   cleanup-by-default runner completed a full dirty-worktree validation in
   `ubuntu-22.04_userland_father_ldpreload_20260813-124003`; a clean committed
   authoritative run is still required before freeze. Actual cost was 9 files
   and 545 changed text lines against a 350-line ceiling that predated the
   scenario README, source-lock note, and tests. The `build-isf` -> `builder`
   rename followed separately.
2. **ptrace prebuilt conversion** — DONE (`d86dba8`). Runs from prepared
   artifacts with no victim-side compilation; accepted investigation exists at
   `docs/investigations/ptrace_fa/ubuntu-22.04_ptrace_fa_20260807-150736/` and
   is in `COMPARATIVE_RESULTS.md`.
3. **Diamorphine retained** — implemented (`b889b83`,
   `scenarios/kernel_diamorphine/`), builds for the exact target kernel,
   verifies vermagic/dispatch path, and implements the bounded hidden-file/
   module and signal-64 behavior. Cleanup remains deferred per
   `scenarios/kernel_diamorphine/README.md` ("Cleanup is deferred for separate
   research and approval") and is outside the delivery matrix. No Diamorphine
   run has an accepted investigation yet (no
   `docs/investigations/kernel_diamorphine/` directory).
4. **Bounded compatibility validation** — on Ubuntu 24.04 and Debian 13, run
   Father, ptrace, and Diamorphine retained with `--no-acquire`. Make no
   code changes by default. A compatibility fix needs separate approval and is
   limited to 80 changed lines per technique; otherwise record the limitation.
   Not started.
5. **Remove automatic forensic extraction and freeze** — DONE (`b38ea01`).
   Automatic per-run extraction and command-specific prerequisite checks are
   removed; the final run command sheet is in `README.md`
   ("Complete experiment command sheet").

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
- Father uses one `.so` and one cleanup-by-default treatment; Diamorphine uses
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

1. Father;
2. ptrace;
3. Diamorphine retained.

After each run, verify repository revision, scenario and acquisition statuses,
input hashes, acquisition hashes, EWF verification, and artifact sizes. Stop
before investigation if any gate fails. Retain all older experiment directories
until replacement runs and investigations are accepted.

**In-flight, uncommitted, as of 2026-08-13 (dirty worktree, not yet part of the
authoritative matrix):**

- `docs/investigations/userland_father_ldpreload/ubuntu-22.04_userland_father_ldpreload_20260813-124003/`
  — disk notebook drafted only; this is the dirty-worktree validation run
  referenced in Task 1, not the clean authoritative run.
- `docs/investigations/userland_father_ldpreload_cleanup/ubuntu-22.04_userland_father_ldpreload_cleanup_20260813-105240/`
  — disk notebook drafted only; a second, more recent cleanup run than the
  already-accepted `..._20260805-144919` (which is in `COMPARATIVE_RESULTS.md`).
  Confirm whether this supersedes the accepted 08-05 row or is a separate
  draft, since the cleanup treatment changed in `1e8f5d3`.

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
- Near delivery, review error checking and exception handling across the runners
  and the orchestrator to confirm it is minimal rather than excessive. Covering
  the full space of exception cases stays out of scope.

## Deferred unless explicitly reopened

- Kernel identity for userland artifacts: rejected, not deferred. Task 1 keys
  Father's compatibility on `image.checksum`, which both the builder and the
  victim already derive from, so no profile carries a `kernel:` field. Task 3
  records kernel and vermagic for Diamorphine's `.ko`, where they matter;
- Diamorphine cleanup, ftrace, Meterpreter, eBPF, CopyFail, ART, worms,
  timestomping, generalized cleanup levels, extra privilege-escalation
  scenarios, and broad hardening;
- Fedora/SELinux, Timesketch, Velociraptor, AIDE/NSRL, graphs/ontologies, and
  broad Sigma/YARA work;
- automatic detection, matching, scoring, reconstruction, new frameworks,
  architecture rewrites, major dependencies, and cosmetic CLI work; and
- read-only permissions for accepted memory/EWF files. This is optional
  defense-in-depth, not evidence immutability or an acceptance condition.
