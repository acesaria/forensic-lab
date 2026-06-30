# TODO_NOW — Scenario-first Father LD_PRELOAD refinement

Date: 2026-06-30
Scope: `attacks/scenarios/userland_father_ldpreload`

## Current decision
Start from the scenario, not from metrics tuning.

The immediate goal is to make the Father LD_PRELOAD scenario readable, standard, teachable, and methodologically defensible. Metrics, matcher terminology, and report layout will be simplified after the scenario semantics are clean.

## Constraints

- Do not tune detector rules just to improve the latest score.
- Do not introduce a large new architecture.
- Do not turn the project into SIEM / EDR / live telemetry.
- Keep the pipeline post-mortem: disk, memory, timeline, clean baseline, and scenario expectations.
- Keep Father as the canonical thesis path until this case is defensible.
- Treat candidate precision as diagnostic only, not as the thesis headline.

## Immediate thesis framing

Canonical question:

> In a clean controlled VM environment, using post-mortem disk, memory, timeline, and baseline evidence, which attack-core artifacts of an LD_PRELOAD compromise can be reconstructed?

Scenario label to prefer:

> Controlled LD_PRELOAD dynamic-linker hijacking scenario inspired by Father.

Avoid claiming:

> Full Father rootkit execution, full stealth realism, production detection, or live telemetry coverage.

## Scenario problems to fix first

1. The scenario is currently partly a provenance/sample-management case and partly an attack reconstruction case.
2. Several currently exact matches are source/archive/marker files, not attack-core compromise artifacts.
3. The lab-only preload marker is not standard `/etc/ld.so.preload` persistence.
4. The current harness does not implement cleanup/evasion strongly enough to support a cleanup-focused forensic lesson.
5. Some expected artifacts are better treated as contextual evidence, not headline reconstruction targets.
6. Scenario-specific strings such as `father` must not be required by GT-blind rules.

## Proposed attack-core evidence chain

Attack-core expected artifacts should describe the compromise behavior itself:

1. Preload mechanism:
   - environment-level `LD_PRELOAD`, or
   - controlled modification of a realistic preload configuration path if safely possible.
2. Shared object payload:
   - a `.so` exists on disk in a non-standard or user-writable staging path.
   - it is new or changed relative to the clean baseline.
3. Process-library relation:
   - a live process maps the same `.so` in memory.
   - the benign process should count only through this relationship, not as an independent suspicious process.
4. Timeline/log support:
   - file create/modify events, command/log traces, or shell traces can support the reconstruction.
5. Cleanup/evasion residue, when enabled:
   - deleted marker/stager/log/config residues are expected only if cleanup is part of the scenario.
   - exact reconstruction requires the deleted path/entity to match the expected artifact.
   - generic deleted-file evidence is contextual only.

## Taxonomy decision for cleanup/deleted artifacts

Do not add a new top-level thesis category for deleted files.

A deleted artifact is still an expected artifact or evidence candidate whose state is `deleted` / `cleanup residue`.

Use:

- exactly reconstructed: deleted path/entity is recovered or timeline-correlated with concrete identity;
- contextual support: deletion activity exists but the exact expected entity is not recovered;
- missed: no deletion evidence and no timeline/log support.

## Expected artifact reclassification to review

Attack-core / headline candidates:

- shared object on disk;
- preload mechanism/configuration/environment evidence;
- memory mapping of the shared object in a process;
- cleanup residue only after cleanup/evasion is intentionally implemented.

Contextual / supporting:

- shell/log trace;
- timeline create/modify/delete events;
- generic deleted-file evidence;
- benign process identity unless linked to the mapped library.

Provenance / appendix only:

- upstream Father archive;
- sample lock metadata;
- lab harness source file;
- hiding marker if no real hiding/evasion behavior is implemented.

## Scenario rewrite direction

Create a clearer `v2` scenario behavior before touching metrics:

1. Prepare a generic attacker workspace with randomized/non-Father-specific names where feasible.
2. Compile or deploy a lab-safe preload `.so`.
3. Activate it through a standard LD_PRELOAD mechanism appropriate for a safe lab.
4. Start a benign long-lived process with the preload library mapped.
5. Record enough ground truth to evaluate disk, memory, and timeline reconstruction.
6. Add controlled cleanup/evasion as the next immediate scenario variant:
   - delete a staging marker or temporary build artifact;
   - optionally remove the preload activation marker after the process is already running;
   - keep the process alive long enough for memory acquisition;
   - avoid destructive behavior and avoid hiding from the acquisition pipeline.

## Rule-review questions to answer from the scenario

For each rule, determine whether it would fire if names were randomized:

- `ld_preload_configuration`: should rely on `LD_PRELOAD`, `ld.so.preload`, or artifact class, not bare `preload` in a directory name.
- `suspicious_shared_object`: should rely on `.so` plus suspicious/user-writable path and baseline-new status, not `father`.
- `process_library_correlation`: should rely on PID/process-library relation plus non-standard path, not scenario codename.
- `deleted_artifact_cleanup`: support-only unless the deleted entity is exactly reconstructed.
- `suspicious_temp_path`: triage-only unless baseline-new and executable/deleted/correlated.
- `userland_persistence`: not part of Father headline unless a persistence mechanism is intentionally added.
- `process_socket_correlation`: not part of Father unless network behavior is intentionally added.
- `suspicious_shell_history`: contextual only.

## Report simplification to do after scenario cleanup

First page should show only:

- attack-core expected artifacts;
- exactly reconstructed;
- contextually supported;
- missed;
- short baseline note.

Move to diagnostics/appendix:

- candidate precision;
- candidate recall;
- candidate F1;
- unmatched candidates by rule;
- per-source candidate precision;
- raw-to-candidate noise reduction;
- baseline-present candidate details.

## Suggested agent workflow

Use two-agent review deliberately:

1. Codex task: inspect the scenario files and propose the smallest concrete `v2` scenario patch.
2. Claude review: critique whether the patch is methodologically standard, teachable, and post-mortem defensible.
3. Codex task: implement only the accepted scenario changes.
4. Claude review: verify expected artifacts, documentation wording, and whether randomized names would still be detected.
5. Only after scenario semantics are stable: update metrics/report terminology.

## Stop condition

Before changing metrics, we should be able to explain the scenario in one sentence:

> A controlled Linux process is launched through LD_PRELOAD with a lab-safe shared object; disk, memory, timeline, and baseline evidence are then used to reconstruct the preload mechanism, staged shared object, process-library mapping, and optional cleanup residue.
