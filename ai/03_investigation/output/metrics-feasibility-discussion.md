# Metrics feasibility: prospective ground truth, findings, and scenario design

## Scope and short verdict

**[ASSUMPTION]** Here, “automatic metrics” means deterministic calculation from
frozen ground-truth records and machine-readable investigation findings. It does
not mean automatic forensic interpretation, automatic reconstruction, or a claim
that the notebook detects unknown compromises.

**[INFERENCE]** Automatic calculation is realistic and desirable, but only after
the project prospectively freezes: (1) the unit being measured, (2) the eligible
denominator, (3) scenario ground truth, (4) the source-specific observation
procedure and matching predicate, (5) acquisition timing and validity gates, and
(6) status/failure/unknown rules. Without those items, automation merely makes an
ill-defined number reproducible.

**[FACT from files]** The present Father notebook cannot support a fresh automatic
calculation: its current source imports a removed helper, reads an undefined
`precondition`, passes a malformed `fls` argument, and cites a no-longer-produced
evidence file. The existing `findings.json` and `metrics.json` were generated
before those edits and are therefore stale with respect to the current notebook
source (`ai/03_investigation/output/disk-investigation-refactor-plan.md`;
`investigations/father/disk_investigation.ipynb`, cells `b43b4782380bcf2f`,
`a1004d31`, `7cd9cb9f`, `1ed90145`, and `3c0ab4c7`).

## 1. Project model (one-page view)

**[FACT from files]** Work flows through five bounded stages: refactor, experiment,
investigation, documentation, and thesis. Experiment outputs under
`shared/experiments/<RUN_ID>/` are inputs to source-specific investigation outputs
under `shared/investigations/<RUN_ID>/`; raw acquisition, derived analysis, and
thesis prose must remain separate (`ai/ROUTING.md`; `ai/INDEX.md`;
`ai/03_investigation/references/investigation-architecture.md`).

**[FACT from files]** For Father, the fixed Python runner executes a deterministic
timeline: verify guest identity, reconnaissance, stage `rk.so`, install and
timestomp `/lib/selinux.so.3`, create two `/tmp/__malicious_*` files, configure
`/etc/ld.so.preload`, activate, validate hiding/backdoor behavior, then delete
`/tmp/rk.so` and shell history. The append-only command log records executed
commands and phase boundaries; the manifest records run/platform/input hashes and
the validated socket facts. These are treatment ground truth, not disk findings
(`scenarios/userland_father_ldpreload/runner.py`;
`scenarios/userland_father_ldpreload/README.md`;
`shared/experiments/father-u22-20260819-03/command_log.jsonl`;
`shared/experiments/father-u22-20260819-03/manifest.json`).

**[FACT from files]** The run captures memory while the compromise socket remains
active, then shuts down and acquires the disk offline; the disk acquisition is
independently verified, while the acquisition sidecar marks the memory image
`verified: false` (`scenarios/userland_father_ldpreload/README.md`;
`shared/experiments/father-u22-20260819-03/dumps/acquisition.json`).

**[FACT from files]** The disk notebook resolves a `RUN_ID`, re-verifies the EWF,
discovers filesystem facts with TSK, examines named paths and journal markers,
builds one `findings` dictionary, derives `metrics` from it, and renders a report.
Its findings therefore sit between immutable evidence and interpretation; they
must not be treated as scenario ground truth (`ai/03_investigation/CONTEXT.md`;
`investigations/father/disk_investigation.ipynb`;
`investigations/father/investigation_utils.py`).

**[INFERENCE]** The defensible relationship is:

> prospective scenario/measurement contract → runner treatment record → acquired
> disk/memory state → source-bounded examination → atomic observations/findings →
> post-investigation join to ground truth → metrics → manual cross-source
> interpretation.

The join must occur after observations are produced if the thesis wants any claim
stronger than targeted verification. The current notebook embeds exact expected
names and markers before examination, so its valid claim is “observability under a
known-target procedure,” not blind detection performance
(`investigations/father/disk_investigation.ipynb`, cells `b43b4782380bcf2f`,
`1ccec6a0`, and `19ad2939`).

### Explicit gaps/questions

- **[FACT from files]** Which Father run is authoritative? The experiment notes
  call `father-u22-20260818-01` the final run, while the current notebook and
  refactor plan use `father-u22-20260819-03`
  (`ai/02_experiments/CONTEXT.md`;
  `ai/02_experiments/output/father/experiment-summary.md`;
  `ai/03_investigation/output/disk-investigation-refactor-plan.md`;
  `shared/experiments/father-u22-20260819-03/manifest.json`).
- **[FACT from files]** The investigation context points to a reporting contract
  inside `archive/`; it was not read because this task forbids archive access.
  Therefore its existing coverage formula and status vocabulary could not be
  reconciled with this proposal (`ai/03_investigation/CONTEXT.md`).
- **[FACT from files]** The prescribed scenario evidence is Father-specific. No
  other scenario runner or accepted run was examined, so cross-scenario
  denominators remain unverified (`ai/02_experiments/output/father/handoff.md`).
- **[FACT from files]** The only inspected complete three-source derived set is
  `father-u22-20260818-02`; its top-level `investigation.json` still says
  `in_progress` and memory/timeline `not_started` despite existing derived
  outputs. Which status is authoritative must be settled before aggregation
  (`shared/investigations/father-u22-20260818-02/investigation.json`;
  `shared/investigations/father-u22-20260818-02/derived/memory/findings.json`;
  `shared/investigations/father-u22-20260818-02/derived/timeline/findings.json`).

## 2. Feasibility verdict by candidate metric

The table separates mechanical computability from scientific validity. “Yes”
means the value can be reproduced from current records; “conditional” means the
definition or denominator must be frozen prospectively; “not defensible now”
means a number could be emitted but would not support the implied claim.
All source descriptions in the table are **[FACT from files]**; feasibility
judgments and failure conditions are **[INFERENCE]**.

| Candidate metric | Verdict | Data source | Required conditions; what breaks it |
|---|---|---|---|
| Scenario, phase, acquisition, and total duration | **Yes, descriptive** | Manifest timestamps, command-log phase boundaries, acquisition sidecar (`ai/02_experiments/output/father/metrics.md`; `shared/experiments/father-u22-20260819-03/manifest.json`; `shared/experiments/father-u22-20260819-03/command_log.jsonl`; `shared/experiments/father-u22-20260819-03/dumps/acquisition.json`) | Clock/format consistency and complete boundaries. Missing end events, retries, or mixed clocks break the calculation. It measures laboratory cost, not forensic effectiveness. |
| Evidence size, compression, acquisition throughput | **Yes, descriptive** | Acquisition sidecar and segment metadata (`ai/02_experiments/output/father/artifacts.md`; `shared/experiments/father-u22-20260819-03/dumps/acquisition.json`) | Freeze byte definitions and whether throughput is tool-reported or recomputed. Hardware/compression/content make cross-run comparison confounded. |
| Scenario functional outcome (install, activation, backdoor, hiding, cleanup commands) | **Yes as treatment validation; no as forensic metric** | Runner assertions, command log, manifest scenario status/facts (`scenarios/userland_father_ldpreload/runner.py`; `shared/experiments/father-u22-20260819-03/manifest.json`; `shared/experiments/father-u22-20260819-03/command_log.jsonl`) | A successful command is not proof of the post-acquisition disk state. Cleanup effects are deliberately not asserted by the runner (`scenarios/userland_father_ldpreload/README.md`). |
| `acquisition_integrity_verified` | **Yes; use as an eligibility gate** | Independent notebook `ewfverify` output plus acquisition hash (`investigations/father/disk_investigation.ipynb`, cell `6ea80c7da305817e`; `shared/experiments/father-u22-20260819-03/dumps/acquisition.json`) | Require success and digest equality. Missing sidecar/hash, failed tool, or an unverified source makes source-dependent outcome metrics ineligible, not zero. The current memory source is not independently verified in the sidecar. |
| Presence of `/etc/ld.so.preload` and installed library | **Yes for targeted observability** | `ifind`/`icat`/`istat` findings (`investigations/father/disk_investigation.ipynb`, cells `b6ac6bc3c9d7cd7b` and `659c384f3a121381`) | Predefine path resolution/symlink policy, source, and observation predicate. Hard-coded paths make this verification, not discovery. `false` must not conflate valid absence, tool failure, and not tested. |
| Installed-library identity match | **Yes** | Recovered bytes from `icat` versus manifest input SHA-256 (`shared/experiments/father-u22-20260819-03/manifest.json`; `investigations/father/disk_investigation.ipynb`, cell `659c384f3a121381`) | Pre-register which artifact/hash is authoritative and require a valid extraction. It proves byte identity, not that a hook executed (`shared/investigations/father-u22-20260819-03/derived/disk/findings.json`). |
| Timestomp flag and `mtime − crtime` | **Conditional** | TSK `istat` values plus scenario action (`scenarios/userland_father_ldpreload/runner.py`; `investigations/father/disk_investigation.ipynb`, cells `659c384f3a121381` and `1ed90145`) | Freeze the timestamp relation and timezone normalization. Current calculation strips timezone labels even though the observed `mtime` is CET and `crtime` is CEST, so the numeric delta is not cross-run safe (`shared/investigations/father-u22-20260819-03/derived/disk/findings.json`; `shared/investigations/father-u22-20260819-03/derived/disk/metrics.json`; `ai/03_investigation/references/linux-dfir-artifacts.md`). Treat it as a conditional magnitude/signal, not a universal verdict. |
| Expected `/tmp` artifact count/missing count | **Yes, but rename and define denominator** | Expected set embedded in notebook; live `fls` findings (`investigations/father/disk_investigation.ipynb`, cells `b43b4782380bcf2f`, `1ccec6a0`, `da67e5bf`) | Call this targeted artifact observability, not “recovery.” Freeze the expected set, eligible source, expected state, and all/any rule. Current `tmp_artifacts.status` becomes `confirmed` when any expected name is present, even if another is missing (`investigations/father/disk_investigation.ipynb`, cell `7cd9cb9f`). |
| `expected_tmp_artifacts_recovered_ratio` | **Conditional and currently misnamed** | Proposed in refactor plan from expected names versus observed live entries (`ai/03_investigation/output/disk-investigation-refactor-plan.md`) | Denominator must distinguish the two surviving files from deleted `rk.so`; the plan itself leaves this unresolved. Live allocated files were observed, not recovered. |
| Journal directory-entry corroboration | **Yes as a bounded boolean** | Predefined marker in bounded journal extraction and saved `jcat` blocks (`investigations/father/disk_investigation.ipynb`, cells `19ad2939` and `15553455`; `shared/investigations/father-u22-20260819-03/derived/disk/findings.json`) | Predefine marker, journal scope, success predicate, and collision risk. It corroborates name/metadata bytes, not original file content. Journal recycling and acquisition delay can change the result (`ai/03_investigation/references/linux-dfir-artifacts.md`). |
| Journal marker/block count | **Yes, descriptive; weak comparison metric** | Marker hits/unique journal blocks (`investigations/father/disk_investigation.ipynb`, cells `19ad2939`, `15553455`) | Counts depend on journal churn, duplicate names, dwell/acquisition timing, and search terms. Do not interpret a larger count as stronger detection. |
| Deleted target content recovered | **Conditional; not measured in current Father pass** | Hash-verified output of a declared recovery method versus a prospectively recorded unique target hash | Current `rk.so` is byte-identical to the still-allocated installed library, has no observed directory entry, and no unallocated/content-recovery method was run (`ai/03_investigation/output/disk-investigation-refactor-plan.md`; `shared/investigations/father-u22-20260819-03/derived/disk/findings.json`). The current `journal_file_content_recovered: false` is only “no ELF header observed in the journal,” not a completed recovery attempt. |
| Recovery-tool availability/status | **Yes as environment metadata; not an outcome metric** | Tool version calls and invocation record (`investigations/father/disk_investigation.ipynb`, cells `132e5ee6`, `7cd9cb9f`) | “Available but not run” cannot enter a success denominator. Tool presence does not establish recoverability or method coverage. |
| Forensic-layer coverage | **Yes as procedure quality control** | Planned-versus-successfully executed method IDs (`ai/03_investigation/output/disk-investigation-refactor-plan.md`; `ai/03_investigation/references/tsk-ext4-cheatsheet.md`) | Freeze the layer list and success rule. It measures procedure execution, not evidential yield; adding tools must not improve a scientific score by definition. |
| Memory plugin row counts/process visibility/socket counts | **Yes, descriptive; not automatic proof** | Memory findings/metrics (`shared/investigations/father-u22-20260818-02/derived/memory/findings.json`; `shared/investigations/father-u22-20260818-02/derived/memory/metrics.json`) | Plugin status, exact ISF, candidate selection, and semantic matching are required. Current notes explicitly retain manual PID/socket confirmation, so row counts cannot become “backdoor detected.” |
| Timeline window/event-family/auth/inode counts | **Yes, descriptive** | Timeline findings/metrics (`shared/investigations/father-u22-20260818-02/derived/timeline/findings.json`; `shared/investigations/father-u22-20260818-02/derived/timeline/metrics.json`) | Freeze window, timezone, parser set/version, source availability, and deduplication. More events do not mean better forensic visibility. |
| Per-source or cross-source action corroboration | **Conditional; academically useful** | Prospective action/artifact ground truth joined to normalized disk, memory, and timeline findings | Current source schemas are incompatible: disk is nested by artifact, memory is plugin status plus prose observations, and timeline is aggregate counts (`shared/investigations/father-u22-20260819-03/derived/disk/findings.json`; `shared/investigations/father-u22-20260818-02/derived/memory/findings.json`; `shared/investigations/father-u22-20260818-02/derived/timeline/findings.json`). Normalize atomic observations before calculation. |
| Precision, recall, F1, false-positive rate, or “automatic detection accuracy” | **Not defensible under the current design** | Would require a prospectively labeled candidate universe, negative cases, and an investigator/detector that does not consume exact ground-truth locators | The notebook searches exact expected names/paths and markers, so there is no independent candidate universe and no valid false-positive denominator (`investigations/father/disk_investigation.ipynb`, cells `b43b4782380bcf2f`, `b6ac6bc3c9d7cd7b`, `1ccec6a0`, `19ad2939`). A number could be calculated only after redesigning the study question and protocol. |

**[INFERENCE] Feasibility verdict.** Automate extraction of descriptive run facts,
eligibility gates, and post-hoc arithmetic. Do not automate the final
cross-source conclusion. Call targeted, ground-truth-informed outputs
“observability/verification,” not “detection.” With one accepted run per
condition, report case-level descriptive values, not inferential statistics or
general capability estimates.

## 3. A-priori measurement plan

### 3.1 Freeze a measurement contract before another run

**[INFERENCE]** The minimum prospective contract should contain:

1. `measurement_plan_id`, schema version, scenario revision, platform/profile,
   acquisition order, and the research question being served.
2. Unit of analysis: action, artifact, source family, and run. These units must
   not be mixed in one denominator.
3. One stable `action_id` per treatment action and `artifact_id` per expected
   trace; creation method, expected acquisition state (`allocated`, `deleted`,
   `volatile`, or declared negative control), source eligibility, and whether
   the item is unique/hash-addressable.
4. Observation predicate per artifact/source: method, query scope, matching key,
   required values, valid tool exit, and durable evidence locator.
5. Status vocabulary and denominator rules. At minimum: `observed`,
   `not_observed`, `not_tested`, `tool_failed`, `inconclusive`, and
   `not_applicable`. Only predeclared `not_applicable` items leave the
   denominator; failures and unknowns remain visible.
6. Ground-truth access mode: targeted verification, blinded discovery, or a
   two-pass procedure. The label must match the protocol.
7. Acquisition timing and filesystem conditions that materially affect the
   construct, especially dwell, shutdown order, filesystem type/mode, deletion
   timing, later disk activity, and any `sync`/`fsync` policy.

**[FACT from files]** The runner already provides stable commands, phases, paths,
dwell values, cleanup steps, and input hashes, but those facts are spread across
code, manifest, and command log rather than expressed as a frozen measurement
contract (`scenarios/userland_father_ldpreload/runner.py`;
`shared/experiments/father-u22-20260819-03/manifest.json`;
`shared/experiments/father-u22-20260819-03/command_log.jsonl`).

### 3.2 Minimal committed set

The recommendation is two eligibility gates and four outcome measures. Timing,
sizes, throughput, plugin row counts, event counts, journal-block counts, and tool
versions should remain descriptive metadata.

| ID | Definition and formula | Data source | Ground-truth comparison |
|---|---|---|---|
| **G1 Evidence eligibility** | Per source: `eligible = acquisition completed ∧ required digest present ∧ independent verification policy satisfied`. No percentage. | Acquisition sidecar plus independent verification finding. Current disk has both; current memory sidecar says `verified: false` (`shared/experiments/father-u22-20260819-03/dumps/acquisition.json`). | Compared with the predeclared integrity policy, not scenario artifacts. Failed eligibility blocks that source's outcome metrics. |
| **G2 Investigation completeness** | `successful required checks / predeclared required checks`, reported with failed/not-tested counts. | Method execution records and raw evidence locators; the architecture already requires raw output and per-phase derived output (`ai/03_investigation/references/investigation-architecture.md`). | Compared with the frozen investigation plan. This is procedure QC, not forensic success. |
| **M1 Source-conditioned artifact observability** | For source `s`: `O_s = observed eligible artifact-source pairs / all evaluable artifact-source pairs declared for s`. Report numerator, denominator, and item statuses—not percentage alone. | Atomic findings joined after examination to the prospective artifact registry. | Compared with each artifact's expected acquisition state and source eligibility. “Observed” requires the frozen source-specific predicate; exact-path checks are labeled targeted verification. |
| **M2 Action corroboration coverage** | Per source: `C_s = ground-truth actions with ≥1 qualifying independent observation in s / evaluable actions declared observable in s`. Cross-source: `C_2+ = actions corroborated by ≥2 independent source families / actions declared evaluable in ≥2`. | Normalized disk/memory/timeline findings. | Compared with prospectively declared `action_id`→eligible-source mappings, not raw artifact counts. This prevents one noisy action with many traces from dominating. |
| **M3 Verified deleted-content recovery** | `R = unique deleted targets reconstructed and hash-matched / eligible unique deleted targets for which the frozen recovery procedure completed`. If no eligible target exists, report `N/A`, not `0`. | Recovery output hash, method execution record, and raw locator. | Compared with a pre-run target hash and expected `deleted` state. Directory-entry or journal-name corroboration is a different finding and never counts as recovered content. |
| **M4 Timestamp displacement (conditional)** | Per timestomped target: `Δmtime = UTC(mtime_observed) − UTC(crtime_observed)`; also record whether the predeclared ordering predicate holds. Do not average across scenarios unless the same construct applies. | TSK metadata finding after explicit timezone normalization. | Compared with the runner's declared timestomp action and reference-file policy, not with a generic “malicious” threshold. The current naive CET/CEST stripping must not be reused (`shared/investigations/father-u22-20260819-03/derived/disk/metrics.json`; `ai/03_investigation/references/linux-dfir-artifacts.md`). |

### 3.3 Scenario implication: should Father be changed?

**[FACT from files]** Father does have a deleted file, `/tmp/rk.so`, but it is
not a unique lost-content target: its bytes match the surviving installed
library. The notebook observed journal name/metadata bytes but did not execute a
content-recovery procedure (`ai/03_investigation/output/disk-investigation-refactor-plan.md`;
`shared/investigations/father-u22-20260819-03/derived/disk/findings.json`).

**[INFERENCE]** This is a valid bounded negative/limitation and need not be
“fixed” to make the existing case academically useful. Changing a scenario
after seeing the result solely to obtain a positive recovery would be outcome-
driven design. Preserve the accepted Father case as-is.

**[INFERENCE]** If deleted-content recovery is an explicit research question,
create a new, versioned recovery-calibration treatment rather than silently
changing the accepted Father run. Before execution, define a unique target with
known bytes/hash, size/type, path, creation/write/flush/deletion sequence,
post-deletion activity budget, acquisition delay, filesystem, recovery methods,
attempt scope, and hash-match success rule. A persisted (`fsync`/`sync`) arm and
a naturalistic non-forced-flush arm would test the condition rather than
guarantee a desired result. Even the persisted arm must treat recovery as an
empirical outcome, not an assured positive.

## 4. Findings format required for mechanical metrics

### 4.1 Separate three records

**[INFERENCE]** Do not keep expectation, observation, and interpretation in one
nested scenario-specific object.

1. **Ground-truth/measurement registry (frozen before run):** scenario revision,
   action/artifact IDs, expected state, eligible sources, unique hash/identity,
   observation/recovery predicates, denominator class, and acquisition
   conditions.
2. **Investigation findings (produced without metric arithmetic):** one atomic
   record per candidate artifact/source/method, including valid negatives and
   failures.
3. **Metric result (post-hoc join):** measurement-plan version, included item
   IDs, numerator, denominator, exclusions with reasons, formula version, and
   computed value.

For a targeted verification protocol, a finding may carry the registered
`artifact_id`. For a blinded/two-pass protocol, the finding should first record
observed attributes (path, inode, hash, socket tuple, event identity) and receive
the ground-truth match only in the post-processing join.

### 4.2 Minimum atomic finding fields

| Field group | Required content |
|---|---|
| Identity | schema version, run ID, investigation-plan ID, source family, phase, finding ID |
| Subject | artifact type, observed path/name, inode/PID/socket/event key where applicable; never a prose-only subject |
| Method | method/test ID, tool and version, command/procedure ID, query scope/time window, execution status |
| Observation | enumerated observation status, raw observed values, normalized values (including UTC), and whether content, metadata, name, or contextual evidence was observed |
| Provenance | one or more existing raw evidence locators plus source evidence hash/identity |
| Matching | candidate ground-truth match and predicate result, added only at the permitted stage of the protocol |
| Limits | bounded negative scope, tool/parser failure, ambiguity, alternative explanation, and analyst-review-required flag |
| Interpretation | optional and separate from the observation; never used directly as a metric numerator without a frozen rule |

### 4.3 Where the current outputs fall short

- **[FACT from files]** Disk findings are bespoke nested sections rather than
  atomic per-artifact records; memory findings mix plugin status with prose
  observations; timeline findings are aggregate counts. They cannot be joined
  mechanically across sources without scenario-specific code
  (`shared/investigations/father-u22-20260819-03/derived/disk/findings.json`;
  `shared/investigations/father-u22-20260818-02/derived/memory/findings.json`;
  `shared/investigations/father-u22-20260818-02/derived/timeline/findings.json`).
- **[FACT from files]** Expectations and observations are mixed in
  `tmp_artifacts.expected_present/expected_missing`, while exact expected names
  and journal markers are embedded in notebook configuration. This makes the
  current procedure ground-truth-informed verification
  (`investigations/father/disk_investigation.ipynb`, cells `b43b4782380bcf2f`,
  `da67e5bf`, `7cd9cb9f`).
- **[FACT from files]** Status values represent different dimensions:
  `confirmed`, `observed`, `not_observed`, `inspected`, `not-met`,
  `precondition_not_met`, and `available_but_not_run`. Tool execution, artifact
  observation, interpretation, and applicability are therefore conflated
  (`shared/investigations/father-u22-20260819-03/derived/disk/findings.json`).
- **[FACT from files]** `tmp_artifacts.status` is `confirmed` when the
  intersection of expected and present names is merely non-empty; partial
  observation can therefore receive the same aggregate status as complete
  observation (`investigations/father/disk_investigation.ipynb`, cell
  `7cd9cb9f`).
- **[FACT from files]** `journal_file_content_recovered: false` is derived from
  an absent ELF header in the journal, although no unallocated-space recovery
  method was executed. This is a bounded journal observation, not a general
  deleted-content recovery result (`investigations/father/disk_investigation.ipynb`,
  cells `19ad2939`, `a6d62d6a`, `132e5ee6`).
- **[FACT from files]** Stored findings cite
  `derived/disk/raw/14-recovery-precondition.json`, while the current notebook no
  longer produces it; current metrics also depend on the removed precondition
  field (`ai/03_investigation/output/disk-investigation-refactor-plan.md`;
  `shared/investigations/father-u22-20260819-03/derived/disk/findings.json`;
  `shared/investigations/father-u22-20260819-03/derived/disk/metrics.json`).
- **[FACT from files]** Findings do not consistently carry tool versions,
  command/test IDs, query scopes, or normalized timestamps. The notebook's raw
  command log exists, but the join from an atomic finding to the exact invocation
  is not a stable field (`investigations/father/investigation_utils.py`;
  `shared/investigations/father-u22-20260819-03/derived/disk/findings.json`).
- **[FACT from files]** The cross-source investigation state is stale relative
  to derived outputs, so an aggregator cannot reliably know which phases are
  complete (`shared/investigations/father-u22-20260818-02/investigation.json`).

## 5. Open decisions

1. **Measurement claim.** Options: (a) targeted observability/verification;
   (b) blind detection accuracy; (c) two-pass candidate generation followed by
   ground-truth matching. **Recommendation:** (c), while explicitly labeling
   exact-path checks as targeted verification; do not claim precision/recall.
2. **Father's accepted result.** Options: (a) preserve it as a bounded
   negative/limitation; (b) replace it with a modified run; (c) retain it and
   add a separately versioned calibration. **Recommendation:** (c) only if
   deleted recovery is an explicit research question; otherwise (a).
3. **Recovery treatment.** Options: (a) naturalistic deletion only; (b) forced
   persistence before deletion only; (c) two prospectively defined arms,
   persisted and non-forced-flush. **Recommendation:** (c), because it measures
   the condition without designing only for a positive.
4. **Primary metrics.** Options: (a) retain all eight draft disk metrics as
   outcomes; (b) adopt G1/G2 plus M1–M4 above; (c) report only narrative
   findings. **Recommendation:** (b); keep timings/counts/tool coverage as
   descriptive or QC fields.
5. **Denominator unit.** Options: (a) raw findings/artifacts; (b) ground-truth
   actions; (c) both, kept as separate metrics. **Recommendation:** (c): M1 for
   artifacts and M2 for actions; never merge them into one completeness score.
6. **Ground-truth storage.** Options: (a) derive expectations later from runner
   code; (b) freeze a versioned measurement registry before the run; (c) embed
   expectations only in each notebook. **Recommendation:** (b), with runner/
   manifest/command log retained as provenance and validation evidence.
7. **Status vocabulary.** Options: (a) preserve phase-specific free strings;
   (b) use one observation-status enum and separate execution/applicability
   fields; (c) reduce everything to booleans. **Recommendation:** (b).
8. **Replication and generalization.** Options: (a) one accepted run per case
   and descriptive case-level metrics; (b) repeated runs per condition for
   variability estimates; (c) pooled cross-scenario percentages from single
   runs. **Recommendation:** (a) if schedule-bound, with narrow claims; choose
   (b) only for metrics intended to generalize. Do not choose (c).
9. **Authoritative Father run.** Options: (a) `father-u22-20260818-01`; (b)
   `father-u22-20260819-03`; (c) retain separate roles (final experiment versus
   notebook-refactor reference). **Recommendation:** decide explicitly and
   update the handoff/index; (c) is acceptable only if the roles are documented.
10. **Reporting-contract reconciliation.** Options: (a) adopt this proposal
    independently; (b) reconcile it with the existing status/coverage contract;
    (c) discard automatic metrics. **Recommendation:** (b) before implementation;
    the governing archive file was intentionally not read in this task.

## 6. Follow-up reconciliation and research position (2026-08-20)

This section records the subsequent human decisions and supersedes conflicting
recommendations above. It is a research position, not yet the final measurement
contract.

### 6.1 Decisions now fixed

- **[FACT from discussion]** Use a **hybrid/two-pass investigation**: first
  generate candidates from technique and operating-system knowledge without
  using exact planted locators; then disclose scenario ground truth to validate,
  measure coverage, and perform explicitly labelled targeted checks. Any result
  dependent on the second pass must remain identifiable and the summary must be
  recomputable without it.
- **[FACT from discussion]** Keep the behaviour represented by
  `father-u22-20260819-03`. If the prospective measurement contract needs a few
  additional ground-truth facts, extend the runner-produced `manifest.json` and
  rerun the disposable experiment; do not redesign the compromise to force a
  favourable result (`scenarios/userland_father_ldpreload/runner.py`;
  `shared/experiments/father-u22-20260819-03/manifest.json`).
- **[FACT from discussion]** For a deleted-content question, define two future
  arms prospectively: a persisted write before deletion and a naturalistic
  non-forced-flush write. This is a condition comparison, not a guarantee that
  recovery will succeed.
- **[FACT from discussion]** `father-u22-20260819-03` is the authoritative Father
  run for this work. Runs remain reproducible and disposable; evidence selected
  for final thesis reporting must still be pinned before its results are cited.
- **[FACT from discussion]** G1/G2 are outside the scientific outcome set. They
  remain validity gates/QC metadata: a failed acquisition or incomplete required
  procedure controls whether M1–M4 are interpretable, but is not itself a
  detection or reconstruction result.
- **[FACT from discussion]** Use one reusable disk, memory, and timeline notebook
  template per scenario across distribution runs. The first executed notebook
  may carry the full educational narrative; later runs may be terse, but must
  execute the same frozen checks and emit the same structured records. Bounded
  human adjudication is acceptable: the goal is reproducible **almost-automatic
  metric calculation**, not automatic forensic interpretation.
- **[FACT from discussion]** Keep a compact, standard vocabulary and separate
  observation status from execution and applicability. Network is deferred, but
  the eventual model must add a source family without changing metric semantics.

### 6.2 Reconciliation with the existing reporting contract

**[FACT from files]** The existing contract already enforces the key epistemic
boundary: scenario validation, forensic observation, and analyst interpretation
are separate; scenario facts may validate a technique-led candidate but must not
silently select it (`ai/archive/METHODOLOGY.md`, “Epistemic separation” and
“Practical investigation workflow”). This is substantively compatible with the
selected hybrid design.

**[FACT from files]** It also fixes the compact target statuses `O`, `P`, `N`,
`TF`, and `--`; defines `A = O + P + N + TF`, `Found = O + P`, and
`Coverage = 100 × Found / A`; separates union contribution into `U`, `C`, and
`S`; records contradictions as `X`; and requires sensitivity values without
ground-truth-guided recovery (`ai/archive/METHODOLOGY.md`, “Status and metric
rules”). Rejected candidates are explicitly not false positives, and TTF is
prospective descriptive context rather than an effectiveness claim
(`ai/archive/METHODOLOGY.md`).

**[INFERENCE]** Therefore the final design should **reconcile, not replace**, the
contract. The likely mapping is: its fixed target matrix becomes the prospective
measurement registry; `O/P/N/TF/--` remains the human-adjudicated observation
vocabulary; M1 is a machine calculation over those target statuses; and M2–M4
must either map cleanly to the existing union/reconstruction fields or be
renamed/deleted. Execution status and applicability should be separate fields so
that `TF` and `--` are not overloaded in machine-readable findings.

**[INFERENCE]** The denominator remains the main unresolved design choice. Raw
tool hits are unsuitable because duplicates and verbose sources dominate. A
ground-truth **atomic target** is the most defensible default for observability;
an **action** is a different reconstruction unit and must be reported separately.
Source-artifact pairs are useful only inside source-conditioned M1. No single
percentage should mix these units or compare unlike source inventories.

### 6.3 Preliminary literature verdict

**[FACT from external research]** NIST CFReDS distinguishes controlled tool-test
data (fully documented contents, known locations, and explicit tests) from
realistic investigation scenarios, whose documentation may be less granular
([CFReDS project](https://cfreds-archive.nist.gov/)). The CFTT method traces each
test assertion to a requirement and defines its measurement method, dataset, and
expected/actual result before testing ([NIST, *Ten Years of Computer Forensic
Tool Testing*](https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=909329)).

**[FACT from external research]** SWGDE permits search and aggregation tools to
be assessed by known data, comparison, or bounded manual verification, whereas
deleted-file recovery requires known data and operational verification of the
recovered result. Its baseline recovery cases include contiguous, fragmented,
and partially overwritten deleted files ([SWGDE 18-Q-001](https://www.swgde.org/documents/published-complete-listing/18-q-001-minimum-requirements-for-testing-tools-used-in-digital-and-multimedia-forensics/)).
NIST's deleted-file images similarly freeze disk state between controlled
operations and document deleted files, timestamps, overwrites, and sector layout
([NIST CFReDS deleted-file recovery images](https://cfreds-archive.nist.gov/dfr-test-images.html)).

**[FACT from external research]** Precision and recall have been proposed for
automated forensic extraction/categorization against an investigator-derived
gold standard ([James, Lopez-Fernandez, and Gladyshev 2015](https://doi.org/10.1007/978-3-319-14289-0_11)).
Recent Linux rootkit studies instead commonly report known-sample capability
tables and explicit detected/undetected cases; for example, Nagy evaluates two
labeled rootkit sets and reports how many were detected while disclosing crash
and acquisition limitations ([Nagy 2025](https://doi.org/10.1016/j.fsidi.2025.301928)).

**[INFERENCE]** There is no evidence here for a universal standard metric for an
entire human-led DFIR investigation. The defensible standard pattern is:
pre-register the question and atomic assertions, acquire a controlled
known-ground-truth dataset, preserve a technique-led first pass, validate in a
disclosed second pass, and report bounded counts/ratios with failures and
limitations. Precision/recall/F1 become valid only if this thesis deliberately
defines a closed candidate universe and a reproducible positive/negative
decision procedure; they must not be retrofitted to narrative findings.

### 6.4 Items deliberately left for the deep research phase

1. Select the final denominator(s): atomic target, action, or two separate
   measures, with an explicit rule for source-artifact pairs.
2. Decide whether M1–M4 are retained, renamed, merged into the existing
   coverage/union contract, or reduced. G1/G2 remain gates only.
3. Define the exact information hidden in pass one and the allowed transition to
   pass two, including how assisted findings are tagged and excluded in the
   sensitivity view.
4. Decide whether Father itself supplies a valid reconstruction target or only
   an observability/limitation case; use the two-arm recovery treatment only if
   reconstruction is part of the thesis question.
5. Freeze the minimal `manifest.json` facts and atomic finding fields. Do not add
   a new framework or duplicate registry unless the existing manifest cannot
   express a required, prospectively fixed fact.

## Evidence base

The original Phase A did not read any `archive/` file. The subsequent human
choice to reconcile with the prior contract required reading the one archive
file listed below. The files below are every local file whose content was read
across the original analysis and this follow-up; external sources are linked in
Section 6.3.

### Project files, in mandated order

1. `ai/ROUTING.md`
2. `ai/INDEX.md`
3. `ai/IDENTITY.md`
4. `ai/03_investigation/CONTEXT.md`
5. `ai/02_experiments/CONTEXT.md`
6. `ai/02_experiments/output/father/artifacts.md`
7. `ai/02_experiments/output/father/experiment-summary.md`
8. `ai/02_experiments/output/father/handoff.md`
9. `ai/02_experiments/output/father/metrics.md`
10. `ai/03_investigation/output/disk-investigation-refactor-plan.md`
11. `ai/03_investigation/references/linux-dfir-artifacts.md`
12. `ai/03_investigation/references/tsk-ext4-cheatsheet.md`
13. `ai/_config/scope.md`
14. `ai/_config/conventions.md`
15. `ai/DECISIONS.md`

### Additional project files needed to close the named gaps

16. `investigations/father/disk_investigation.ipynb`
17. `investigations/father/investigation_utils.py`
18. `scenarios/userland_father_ldpreload/runner.py`
19. `scenarios/userland_father_ldpreload/README.md`
20. `investigations/father/README.md`
21. `shared/experiments/father-u22-20260819-03/manifest.json`
22. `shared/experiments/father-u22-20260819-03/dumps/acquisition.json`
23. `shared/experiments/father-u22-20260819-03/command_log.jsonl`
24. `shared/investigations/father-u22-20260819-03/derived/disk/findings.json`
25. `shared/investigations/father-u22-20260819-03/derived/disk/metrics.json`
26. `ai/03_investigation/references/investigation-architecture.md`
27. `shared/investigations/father-u22-20260818-02/derived/memory/findings.json`
28. `shared/investigations/father-u22-20260818-02/derived/memory/metrics.json`
29. `shared/investigations/father-u22-20260818-02/derived/timeline/findings.json`
30. `shared/investigations/father-u22-20260818-02/derived/timeline/metrics.json`
31. `shared/investigations/father-u22-20260818-02/investigation.json`

### Procedural and memory files read

32. `/home/anto/.codex/skills/review-linux-dfir-thesis/SKILL.md`
33. `/home/anto/.codex/skills/review-linux-dfir-thesis/references/academic-validity.md`
34. `/home/anto/.cache/JetBrains/PyCharm2026.2/aia/agents/views/codex/.agents/skills/jupyter/SKILL.md`
35. `/home/anto/.cache/JetBrains/PyCharm2026.2/aia/agents/views/codex/.agents/skills/jupyter/reference/tools.md`
36. `/home/anto/.codex/memories/MEMORY.md` (routing only; current claims were
    verified from project files)
37. `ai/03_investigation/output/metrics-feasibility-discussion.md` (read back
    only to verify the deliverable)
38. `ai/archive/METHODOLOGY.md` (follow-up reconciliation only)
39. `ai/03_investigation/references/investigation-guidelines.md`
