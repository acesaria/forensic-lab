Step 5 handoff summary — what 5a/5b/5c/5d were meant to do

Step 5 overall context

Step 5 was an adapter-cleanup/refinement pass for the forensic-lab pipeline. The initial audit found that the adapter layer had a few correctness problems and some unnecessary complexity/bloat. The most important issues were:

1. Sleuthkit bodyfile adapter collapsed MACB timestamps into a single unlabeled timestamp, losing timestamp kind information and ignoring atime.
2. Plaso adapter over-classified generic events such as syslog/auth/cron as shell_history_log_event.
3. Deleted-reallocated bodyfile rows were trusted as if they described the deleted file, even though their metadata may belong to the newly reallocated inode.
4. Plaso had timestamp_desc but did not place it into entity["time_kind"].
5. Volatility3 provenance duplicated the full raw plugin row inside every finding.
6. common.py had nullable-time/temporal_quality/id-generation dead weight.
7. Filesystem path classification logic was duplicated across bodyfile, plaso, and vol3 with small semantic drift.

The goal of Step 5 was not to redesign the pipeline. The goal was to make the adapter output more forensically correct, simpler, and cleaner while keeping matcher/detector/scenario behavior stable unless a real bug was exposed.

Step 5a — bodyfile timestamps and deleted-realloc handling

Purpose:
Fix forensic timestamp correctness in the bodyfile adapter, plus one small Plaso time_kind fix.

What 5a was supposed to change:

* In `orchestrator/adapters/sleuthkit/bodyfile.py`, parse all four bodyfile timestamps: atime, mtime, ctime, crtime.
* Emit one ToolFinding per present timestamp kind.
* Set `entity["time_kind"]` explicitly to `"atime"`, `"mtime"`, `"ctime"`, or `"crtime"`.
* Keep duplicate timestamp rows if different kinds share the same epoch. No dedupe logic: same timestamp value but different timestamp kind still means separate evidence events.
* Treat `(deleted-realloc)` conservatively:

  * keep `artifact_class = deleted_file_candidate`;
  * add `entity["reallocated"] = true`;
  * emit no timed findings for those rows, because times/size/mode may describe the new file occupying the inode, not the deleted file.
* Plain `(deleted)` rows still keep their timestamps.
* In `orchestrator/adapters/plaso/jsonl.py`, copy `timestamp_desc` into `entity["time_kind"]`.
* Update only the focused adapter test.

Expected effect:

* Disk evidence timestamps become explicit and auditable.
* RQ4 offset calculations can know whether they came from atime/mtime/ctime/crtime.
* Some raw finding counts may increase because one bodyfile row can now generate multiple timestamp-kind findings.
* Coverage outcomes should remain unchanged; offsets may shift or become absent where the previous value was unsafe.

Step 5b — Plaso/bodyfile artifact classes

Purpose:
Fix the artifact-class conflation where generic timeline/log events were being labeled as shell history.

What 5b was supposed to investigate first:

* Inspect real cached Plaso `data_type` / parser values.
* Check whether `detectors/rules/timeline/suspicious_shell_history.yml` depends on the old, over-broad `shell_history_log_event` class.
* If the rule would break and needs rewriting, STOP and report instead of editing rules.

What 5b was supposed to change if safe:

* In Plaso:

  * map genuine shell-history evidence to `shell_history_log_event`;
  * use Plaso’s own `data_type` as `artifact_class` for fallback/non-known events instead of inventing a new taxonomy;
  * strip `TYPE:` prefixes such as `OS:/path` when falling back to `display_name`, so normalized path identity is not broken.
* In bodyfile:

  * remove the `/var/log/` and history-file branch from `_artifact_class`;
  * bodyfile rows under `/var/log/` become ordinary file metadata, not log events;
  * event-ness belongs to timeline evidence, not disk metadata.

Expected effect:

* Generic syslog/auth/cron events stop pretending to be shell history.
* Only real shell-history events keep `shell_history_log_event`.
* Unknown Plaso classes remain inert for closed is-a matching, which is conservative.
* Any changed supported/identified outcomes must be explained line by line.

Step 5c — path-classification deduplication

Purpose:
Deduplicate filesystem path classification logic after 5b lands.

What 5c was supposed to change:

* Add one simple shared helper in `orchestrator/adapters/common.py`, likely `classify_fs_path(path) -> str`.
* The helper should return only the §5 vocabulary:

  * `shared_object`
  * `preload_configuration`
  * `service_unit_file`
  * `file`
* Make bodyfile and Plaso use this helper where path classification is still needed.
* In Volatility3:

  * use the helper only for path-like mappings;
  * map `shared_object` to `library_mapping` at the vol3 call site because memory mappings have memory semantics;
  * remove the old `_looks_like_shared_object` helper;
  * fix the drift where any path containing `"preload"` could be treated as a shared-object mapping.

Expected effect:

* Same emitted `(source_type, artifact_class)` pairs as before, except the intentional Vol3 `"preload"` drift fix.
* Lower duplication and less adapter divergence.
* No matcher/detector/scenario changes.
* Handoff should explicitly note that this duplication shows the rule/detection layer is still thin and should be revisited later, but not fixed here.

Step 5d — final adapter/common/canonical cleanup

Purpose:
Final cleanup pass for bloat and dead fields after 5a–5c are merged.

What 5d was supposed to delete or simplify:

* In Volatility3:

  * remove `provenance["row"]`;
  * remove `_jsonable_row`;
  * rely on `raw_ref` for plugin row identity instead of duplicating the full raw row.
* In common adapter code:

  * remove `UNKNOWN_TIME = "unknown"`;
  * emit `None` for unknown/missing time, consistent with the nullable time model;
  * replace the dead initial SHA1 id in `make_tool_finding`, since final IDs are overwritten by `write_tool_findings`.
* In canonical models:

  * delete `temporal_quality` entirely if greps confirm it is write-only;
  * remove the `TemporalQuality` enum;
  * remove adapter arguments/tests that only exist for `temporal_quality`;
  * make IO tolerate/drop stale `temporal_quality` if old JSONL/YAML contains it, without editing scenario files.
* Consider deleting `EvidenceSource.LOG` only if grep proves there is no live usage. If uncertain, leave it and report why.

Expected effect:

* Smaller adapter code.
* No outcome or RQ4 changes.
* Deletion-only cleanup, no replacement abstraction or config.
* Final handoff should report grep evidence, files changed, validation output, LOC delta, and anything intentionally left for Step 6.

Validation expected across steps

Each step should run the focused adapter/canonical/matcher/detector tests relevant to the change. The cached run should be reprocessed through detector generation and `python cli.py match-canonical`. The key acceptance constraint is that identified/supported/missed outcomes should remain stable unless the step intentionally exposes a prior incorrect classification. For 5a, raw finding counts and RQ4 offsets may change because timestamp kinds are no longer collapsed. For 5d, outcomes and RQ4 values should remain unchanged.

Important boundaries

Do not redesign matcher, detectors, scenarios, or rules during Step 5 unless a step explicitly says to stop and report a rule-side follow-up. Step 5 is adapter correctness and simplification, not a detection-methodology rewrite. Keep the implementation small, local, and auditable. Deletion and simpler behavior are preferred over new abstractions.
