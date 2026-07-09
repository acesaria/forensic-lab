# AUDIT_NOTES.md — Step 1 ponytail-audit (report only, 2026-07-04)

Map for Steps 2–5 of REFACTOR_PLAN.md. Spec = METHODOLOGY.md §3–§10.
Ranked biggest cut first. LOC = current → target.

## Inspected

matcher/engine.py, matcher/tests/test_matcher_engine.py, detectors/engine.py,
detectors/baseline.py, detectors/rules/*, detectors/tests/*,
orchestrator/canonical/{models,io,baseline_paths,__init__}.py + tests,
orchestrator/adapters/{common,sleuthkit/bodyfile,volatility3/json_output,
plaso/jsonl,yara/matches}.py + tests, orchestrator/forensics/{yara_runner,
sigma_runner}.py (wiring check), orchestrator/core/orchestrator.py (call sites),
cli.py (call sites), orchestrator/scenarios/run_context.py (`_artifact_record`).

## Verdict on matcher/engine.py: FULL DELETE — confirmed

1219 LOC, nothing to salvage. Only external consumers are
`cli.py:255` and `orchestrator/core/orchestrator.py:39`
(`run_matcher_files`, `render_console_summary`) — both get v3 equivalents in
Steps 3/6. No other module imports `matcher.engine`; `metrics.json` /
`score_report.md` / `matches.jsonl` are read nowhere else. Every block is
condemned by a §10 guardrail, so there is no "good half" to keep:

- greedy 1:1 assignment with `used_exp`/`used_cand` + priority sort
  (engine.py:216-238) — violates §10.1, structurally zeroes corroboration.
- `relation="fp"` rows + `_prf` precision/recall/F1, micro, per-source,
  per-class, macro-F1 (engine.py:256-267, 796-858) — violates §10.3.
- basename equality establishes identity (`_path_match`, engine.py:416) and
  a timestamp counts as an instance field (`_instance_fields` → `"time"`,
  engine.py:396) — both violate §10.4.
- `_class_context_compatible` reads `cand.entity.get("step_id")`
  (engine.py:358-360) — the exact GT-leak vector named in §10.8.
- open alias table with cross-domain edges (preload↔shell_history,
  shell_history↔process, socket↔process; engine.py:331-343) — violates §10.5.
- `methodology_warnings` self-disclaimers (engine.py:506-523) — §10.3: a
  metric that needs a disclaimer is deleted, not disclaimed.

Delete `matcher/tests/test_matcher_engine.py` (344 LOC) with it — it pins the
condemned behaviors. Also delete the debug raw-finding fallback
(`allow_raw_finding_fallback` / `--debug-raw-findings` path,
engine.py:75-81, 110-115, 139-150, 173-186): v3 computes `observed` from raw
findings by definition (§10.7), so the fallback mode has no reason to exist.

## Ranked findings

### 1. delete matcher v2 + its tests. Replaced by ~300-LOC §5/§6 matcher (Step 3). [matcher/] — 1563 → ~400
Includes `MatchLevel` + `MatchResult` in models.py (engine.py is their only
consumer) and their canonical-test sections.

### 2. shrink detectors/baseline.py: per-claim metadata bloat. [detectors/baseline.py] — 299 → ~120
Every claim's `entity["baseline"]` embeds comparison-wide data
(`status_counts`, `baseline_path_count`, `compromised_path_count`,
`compared_fields`, `identity` — baseline.py:188-198, duplicated again in
`_with_unknown_baseline` 207-217). v3 block C needs per-claim only a status
string + a downgraded flag; comparison-wide counts are computed once at
metrics time. Cut `PathBaselineStatus.compared_fields`/`baseline_record_count`,
collapse `_with_baseline_status`/`_with_unknown_baseline` into one function,
keep the conservative downgrade semantics (`_should_downgrade…`, `_downgrade_claim`)
verbatim. `test_baseline.py` shrinks with it (204 → ~120). (Step 4)

### 3. delete memory-claim dedup machinery by not generating duplicates. [detectors/engine.py] — 514 → ~400
`_dedupe_memory_correlation_claims` + `_memory_correlation_key` +
`_collapse_memory_group` + identity helpers (engine.py:124-228, ~105 LOC)
exist only to collapse the cartesian process×library / process×socket products
that `_process_library_correlation` / `_process_socket_correlation` emit.
Key the loop on (pid, lib-path) / (pid, endpoint) and emit one claim per group
directly (~+15 LOC in the two detectors); `prepare_detection_claims` becomes
`assign_claim_ids`. Also delete confidence arithmetic (+0.12/+0.08 nudges,
engine.py:309-314): v3 reads no float confidence — if Step 4 keeps only the
baseline downgrade, replace `confidence` with that boolean and drop
`confidence_default` from rules and `DetectionClaim.validate`. (Step 4)

### 4. shrink canonical models: dead records + dead enum + dead fields. [orchestrator/canonical/] — 313+53 → ~200
- delete: `ScenarioStep`, `ReferenceContext` dataclasses — zero non-test
  consumers (scenario engine uses raw dicts; run_context writes
  reference_context.json as plain JSON). (~40 LOC + test sections)
- delete: `TemporalQuality` — adapters only ever emit EXACT/NONE, which is
  exactly `time is not None`; §6.D wants the timestamp **kind**
  (crtime/mtime/ctime/timestamp_desc, → `time_kind` entity field in Step 5),
  not a quality enum. §10.9: a level no adapter produces must not gate
  matching. Drops the field from 3 records + `_best_temporal_quality` in the
  matcher (dies anyway) + `make_tool_finding`'s quality param.
- delete after Step 3: `ArtifactExpectation.critical`, `.observability`
  (read only by condemned matcher), `.persistence`, `.observable_kind`
  (write-only pass-throughs). v3 needs `required_for_scoring` (Step 2) —
  don't carry five flags where one is scored.
- delete: `io.write_json` / `io.load_json` — test-only consumers.
- shrink: cache `get_type_hints` per class (one `ClassVar` or
  `functools.cache`) — currently reflected on every record instantiation,
  thousands per run. Keep the coercion logic itself: contained, works.
(Steps 2–3)

### 5. shrink adapter provenance bloat. [orchestrator/adapters/] — 169+90 → ~140+90
- vol3: `provenance["row"] = _jsonable_row(row)` copies the entire raw row
  into every finding; `raw_ref` already locates plugin+row. Delete the copy +
  helper. Big JSONL-size win. (json_output.py:111, 164-165)
- plaso: keep `timestamp_desc` (it becomes `time_kind` per §10.6); `parser`/
  `data_type` stay (classification inputs), rest is fine.
- common.py: `UNKNOWN_TIME = "unknown"` sentinel → plain `None`
  (§10.6 says time may be null; the sentinel forces `!= "unknown"` guards
  downstream). Drop the throwaway pre-assign sha1 `initial_id` in
  `make_tool_finding` — `assign_tool_finding_ids` overwrites it; a counter
  placeholder suffices. 165 → ~130. (Step 5)

### 6. bodyfile MACB collapse — correctness fix, not a cut. [orchestrator/adapters/sleuthkit/bodyfile.py:86] — 145 → ~150
`iso_from_epoch(crtime or mtime or ctime)` mislabels times and drops atime;
§10.6 requires the kind label beside the value. Fix in Step 5 with the
`time_kind` convention; expect LOC ≈ flat. Flagged here so Step 5 scopes it.

## Not cut (deliberate)

- YARA stack (`orchestrator/adapters/yara/`, `orchestrator/forensics/
  yara_runner.py`, ~185 LOC, currently unwired): **kept by decision
  (2026-07-04)** — will be integrated into the pipeline in future work (§7
  YARA content-scanning). Do not delete in Step 5; leave as-is until wired.
- `sigma_runner.py` (106 LOC, unimported): header + memory say it is the
  deliberate placeholder for the planned pySigma→SQL path (§7). Plan decides;
  pure ponytail would delete and re-vendor when wired.
- `EvidenceSource.LOG`: 1 LOC enum member; §10.9 only bans it in
  `source_eligibility`. Keep for the Sigma future.
- detectors rule YAMLs + `load_rules`: small, GT-blind, cited — fine.
- `filter_findings_to_window`, `baseline_paths.py`, `io.py` JSONL trio:
  lean already.
- plaso `_classify` fallback ("everything else → shell_history_log_event")
  is a Step 5 forensic-lens call, not a laziness one.

## Net

net: ~−1,800 LOC (focus tree 4,250 → ~2,450 incl. new matcher+tests and the
kept YARA adapter), −0 deps.

## Open questions (for Steps 2–5, not blockers)

1. Does `DetectionClaim.confidence` survive as float anywhere in §6? If block
   C only counts downgrades, the boolean wins (finding 3).
2. Do report consumers (figures scripts) read any v2 metrics keys? cli.py and
   orchestrator.py are the only readers found; verify figure generation
   before Step 6 renames.
3. `ArtifactExpectation` field prune (finding 5) touches authored
   `expected_observables.yml` — prune model-side only, or YAML too? (Step 2)
