# codex-prompts.md — executor prompts for steps 6.0–6.5

Implementation is delegated to Codex (executor). Every design decision is
pre-made here; where a decision depends on data, the prompt gives a decision
*procedure*, not judgment. Paste the COMMON PREAMBLE first, then exactly one
step prompt per session, in order. Disposable once the refactor lands.

---

## COMMON PREAMBLE (paste at the top of every Codex session)

```
You are implementing one step of a planned refactor in forensic-lab.
Follow the instructions exactly. Where reality differs from an instruction
(file moved, line renumbered, unexpected rg hit, failing precondition),
STOP and report instead of improvising.

Read fully before editing: AGENTS.md, PROJECT_CONTEXT.md, plus the
METHODOLOGY.md sections named by the step. Obey AGENTS.md hard invariants;
the ones that most commonly regress:
- GT-blindness: adapters, detectors, rules never read ground truth,
  expectations, step_id, seeds, target paths/hashes.
- Never put a scenario instance value (planted path, filename, hash, IP)
  into a detector rule or matcher alias; detectors/tests/test_rule_leakage.py
  enforces this.
- Headline metrics score matched reconstruction, never raw findings.
- Never tune matcher/detector/rules to reproduce historical numbers; the
  artifact expectations are provisional. Outcome changes are explained,
  not corrected.

Working rules:
- Smallest possible diff. Do not reformat untouched lines, do not rename
  anything not named here, no new dependencies, no new files except those
  named, no drive-by refactors or comment rewrites.
- Work directly on main (main-only policy). Commit with the repository's
  configured git identity. No Co-Authored-By trailers, no AI mentions.
- Test command: python -m pytest orchestrator/ detectors/ matcher/ -q
  (must end green). Activate venv before running python commands.
- Shell variables used below:
  RUN=shared/experiments/ubuntu-22.04_userland_father_ldpreload_20260703-115003
  BASE=shared/baselines/lab-ubuntu-22.04-baseline-c94f1200087a

End the session with this handoff block:
  files changed / commands run + their real output / per-AE outcome deltas
  with one-line cause each / risks / anything left for the next step.
```

---

## Prompt 6.0 — delete write-only ArtifactExpectation fields

```
Spec: METHODOLOGY.md §3, §10.2. Scope: exactly these files —
orchestrator/canonical/models.py, orchestrator/scenarios/run_context.py,
scenarios/scenarios/userland_father_ldpreload/expected_observables.yml,
orchestrator/canonical/tests/test_canonical_records.py,
matcher/tests/test_matcher.py. Nothing else.

Task: delete four write-only ArtifactExpectation fields: observable_kind,
persistence, observability, critical.

Step 1 — verify consumers (STOP if unexpected hits appear):
  rg -n "observable_kind|observability" --type py
  rg -n "persistence=|\.persistence\b" --type py
  rg -n "critical=|\.critical\b" --type py orchestrator/canonical orchestrator/scenarios matcher detectors
Expected hits ONLY in: models.py (field + required_fields declarations),
run_context.py (the ArtifactExpectation(...) authoring call around lines
111–125), and the two test files (fixture constructors). Hits on unrelated
words (e.g. the rule id flab.filesystem.userland_persistence in YAML) are
not consumers — ignore non-Python or non-attribute hits.

Step 2 — models.py: in class ArtifactExpectation remove the four dataclass
fields AND their entries in the required_fields tuple. Touch nothing else
in the file. Do NOT add tolerance code: CanonicalRecord.from_dict already
drops unknown keys generically (proven by
test_loading_drops_historical_temporal_quality_key), so old JSONL with the
deleted keys keeps loading.

Step 3 — run_context.py: remove the four keyword arguments from the
ArtifactExpectation(...) call in _artifact_record. Remove any now-unused
local reads of rendered["observable_kind"] etc.

Step 4 — expected_observables.yml: delete the keys observable_kind,
persistence, observability, critical from every artifact_expectations
entry. Do NOT touch capability, evidence_role, indicator_strength (they are
authoring annotations with no code consumers, owned by a later AE review).
Do NOT touch instance_constraints or any other key.

Step 5 — tests: remove the four kwargs from _expectation() in
test_canonical_records.py and _exp() in matcher/tests/test_matcher.py.
Add no new tests.

Verification (all must pass; paste real output in the handoff):
  python -m pytest orchestrator/ detectors/ matcher/ -q
  mkdir -p /tmp/step60
  python cli.py run-detectors --findings $RUN/analysis/tool_findings.jsonl \
    --baseline-findings $BASE/tool_findings.jsonl \
    --baseline-identity lab-ubuntu-22.04:baseline --out /tmp/step60/claims.jsonl
  python cli.py match-canonical \
    --expectations $RUN/dumps/artifact_expectations.jsonl \
    --tool-findings $RUN/analysis/tool_findings.jsonl \
    --detection-claims /tmp/step60/claims.jsonl \
    --execution-truth $RUN/dumps/execution_truth.jsonl \
    --out-dir /tmp/step60/out
  python3 -c "import json;m=json.load(open('/tmp/step60/out/metrics.json'));print(m['expectations'],m['coverage']['identified'],m['coverage']['supported'],m['coverage']['missed'])"
Expected: scored 7 / contextual 7, then 4 1 2. Any other numbers: STOP,
report, do not adjust code to force them.

Commit (one commit): "canonical: drop write-only ArtifactExpectation fields
(observable_kind, persistence, observability, critical)"
```

---

## Prompt 6.1a — offline `run-adapters` command + pipeline smoke test

```
Spec: METHODOLOGY.md §4, §10.6, §10.7, §10.8. Scope: cli.py,
orchestrator/adapters/common.py, orchestrator/core/orchestrator.py (one
delegation edit only), orchestrator/adapters/__init__.py (exports only),
ONE new test file matcher/tests/test_pipeline_offline.py. Nothing else.

Goal: the full evaluation chain must run offline from cached raw tool
outputs: run-adapters -> run-detectors -> match-canonical.

Step 1 — move the case-window helper (mechanical move, no redesign):
In orchestrator/core/orchestrator.py find _case_window_from_command_log
(derives [start,end] from command_log.jsonl step times, 600s margin).
Create in orchestrator/adapters/common.py:
  def case_window_from_command_log(log_path, margin_s: float = 600.0)
      -> tuple[str, str] | None
Move the method body VERBATIM, replacing the self.dumper path lookup with
the log_path parameter. Add the imports common.py is missing (datetime,
timezone, iso_utc_ms from orchestrator.forensics.timeutil — parse_iso_utc
is already imported). Rewrite the orchestrator method as a 3-line
delegation: resolve log_path via self.dumper.run_dir(run_id), return
case_window_from_command_log(log_path, margin_s). Export the new function
from orchestrator/adapters/__init__.py.

Step 2 — cli.py subcommand run-adapters (target <= 50 LOC total):
Flags: --bodyfile PATH, --vol3-json PATH, --plaso-jsonl PATH (each
optional; error out if none given), --run-id required, --out required,
--command-log PATH optional, --margin-s float default 600.
Handler logic, exactly this and no more:
  findings = []
  if bodyfile:  findings += adapt_bodyfile_file(path, run_id=run_id)
  if vol3:      findings += adapt_volatility_json_file(path, run_id=run_id)
  if plaso:     findings += adapt_plaso_jsonl_file(path, run_id=run_id)
  if command_log: window = case_window_from_command_log(...); if window:
      findings = filter_findings_to_window(findings, *window)
      (memory findings are auto-kept: always_keep default — do not
      special-case them)
  write_tool_findings(out, findings)
  print counts per tool, total, and the window used (or "no window").
GT-blindness: the command reads ONLY the three raw outputs and
command_log.jsonl. It must not open artifact_expectations.jsonl,
execution_truth.jsonl, or reference_context.json.

Step 3 — smoke test matcher/tests/test_pipeline_offline.py (ONE test
function; the cross-layer drift guard; no fixture files, no VM, no mocks):
Build inline raw inputs:
  - bodyfile lines (fls -m format, 11 pipe-separated columns) containing
    /tmp/x/rk.so with plausible epoch times;
  - vol3 renderer dict: {"linux.pslist": [{"PID": 7, "COMM": "payload"}],
    "linux.proc.Maps": [{"PID": 7, "Path": "/tmp/x/rk.so"}]}
  - one plaso event dict: filename "/tmp/x/rk.so", parser "filestat",
    data_type "fs:stat", timestamp in epoch microseconds,
    timestamp_desc "crtime".
Chain: adapt_bodyfile + adapt_plugin_rows + adapt_plaso_events ->
write_tool_findings to tmp_path -> load_jsonl -> run_detectors(findings)
-> run_matcher with ONE inline scored ArtifactExpectation
(artifact_class "shared_object", instance_constraints {"path":
"/tmp/x/rk.so"}, source_eligibility [disk, timeline, memory], attck
["T1574.006"], required_for_scoring True) -> assert:
  - the AE outcome is "identified"
  - at least two sources appear for it
  - metrics["expectations"]["scored"] == 1
Look at matcher/tests/test_matcher.py for constructor signatures. If no
detector rule fires on these inputs, inspect
detectors/rules/filesystem/suspicious_shared_object.yml and ADJUST THE
INLINE INPUT PATHS so an existing rule genuinely fires. NEVER edit rules,
detectors, matcher, or adapters to make the test pass — if impossible,
STOP and report why.

Step 4 — re-adapt the cached run and explain deltas (the real deliverable):
  RUNID=$(python3 -c "import json;print(json.load(open('$RUN/dumps/reference_context.json'))['run_id'])")
  mkdir -p /tmp/step61a
  python cli.py run-adapters --bodyfile $RUN/analysis/bodyfile \
    --vol3-json $RUN/analysis/vol3.json --plaso-jsonl $RUN/analysis/timeline.jsonl \
    --run-id $RUNID --command-log $RUN/dumps/command_log.jsonl \
    --out /tmp/step61a/tool_findings.jsonl
  python cli.py run-detectors --findings /tmp/step61a/tool_findings.jsonl \
    --baseline-findings $BASE/tool_findings.jsonl \
    --baseline-identity lab-ubuntu-22.04:baseline --out /tmp/step61a/claims.jsonl
  python cli.py match-canonical --expectations $RUN/dumps/artifact_expectations.jsonl \
    --tool-findings /tmp/step61a/tool_findings.jsonl \
    --detection-claims /tmp/step61a/claims.jsonl \
    --execution-truth $RUN/dumps/execution_truth.jsonl --out-dir /tmp/step61a/out
Compare per-AE outcomes against the reference (4 identified / 1 supported /
2 missed over 7 scored, from the pre-step-5 cached findings). Produce a
table: ae_id | old outcome | new outcome | cause. Legitimate causes are the
step-5 adapter changes: bodyfile /var/log and history files are now class
"file" not shell_history_log_event; plaso unknown events now carry their
data_type as class; bodyfile rows are untimed object findings. Every delta
must be attributed to one of these (or another concrete adapter diff you
can cite by commit). An unexplainable delta: STOP and report.

Verification: pytest green including the new test; paste the delta table.
Commit 1: "cli: offline run-adapters command; window helper moved to adapters.common"
Commit 2: "tests: offline pipeline smoke test (adapters -> detectors -> matcher)"
```

---

## Prompt 6.1b — baseline cache rebuild, live re-run, legacy deletions

```
Spec: METHODOLOGY.md §6. Precondition: 6.1a merged and its delta table
exists. Scope: regenerated artifacts under $BASE (data, not source),
matcher/engine.py (one guard deletion at the very end), the live run.
Code edits beyond the single guard line: NONE without stopping to report.

Step 1 — inspect before touching: read orchestrator/core/baseline_cache.py
fully. Identify every manifest field that is derived from
tool_findings.jsonl (e.g. comparable_path_count) and how reuse validation
checks identity/compatibility. Report the list before proceeding.

Step 2 — rebuild the baseline findings with the new adapters:
  cp $BASE/tool_findings.jsonl $BASE/tool_findings.jsonl.pre5
  python cli.py run-adapters --bodyfile $BASE/analysis/bodyfile \
    --vol3-json $BASE/analysis/vol3.json \
    --run-id <the baseline identity string from $BASE/manifest.json> \
    --out $BASE/tool_findings.jsonl
No --command-log: baseline extraction is intentionally unscoped (the live
path calls _collect_tool_findings with scope_to_case_window=False — verify
at orchestrator/core/orchestrator.py around line 456). No plaso input: the
current cache never included timeline findings; keep it that way.
Update the derived manifest fields found in Step 1 using the existing
baseline_cache.py functions where possible (prefer calling
write_cache_manifest over hand-editing JSON). If the manifest embeds
something you cannot regenerate offline (a hash of acquisition state,
etc.), STOP and report.

Step 3 — offline check of baseline differencing (block C):
re-run the 6.1a detector command against the rebuilt baseline; compare
downgraded-claim counts old vs new baseline; explain movement (same
legitimate-cause list as 6.1a).

Step 4 — live validation (the first real execution of the step-5 adapters):
  python cli.py run --help   # learn the exact invocation first
  python cli.py run ... userland_father_ldpreload ...
Preconditions: lab VM provisioned (cli.py setup already done historically).
If libvirt/the lab is unavailable or the run fails on infrastructure, STOP
and report the exact error — never simulate, never mock, never edit
acquisition code. The VM power contract (memory=ON, disk=OFF) lives in the
orchestrator; do not work around it.
After the run: read analysis/metrics.json of the new run dir; produce the
final attribution table: offline-6.1a numbers vs live numbers, each delta
attributed to (a) adapter change, (b) baseline rebuild, (c) fresh-run
variance. 

Step 5 — legacy deletions, ONLY after step 4 is green:
  a. rg '"unknown"' shared/ --include='*.jsonl' -l   # expect: no hits in
     artifacts that are still consumed (the new run + rebuilt baseline)
  b. In matcher/engine.py (~line 323) change
       if f is None or not f.time or f.time == "unknown":
     to
       if f is None or not f.time:
  c. Delete the pre-step-5 cached run directory $RUN and the backup
     $BASE/tool_findings.jsonl.pre5.
  d. python -m pytest orchestrator/ detectors/ matcher/ -q  -> green.

Commit 1 (after step 3): "baseline: rebuild clean-baseline findings with step-5 adapters"
Commit 2 (after step 5): "matcher: drop legacy unknown-time guard; retire pre-step-5 cached run"
```

---

## Prompt 6.2 — plaso fallback crash edge + RQ4 decision procedure

```
Spec: METHODOLOGY.md §5, §6.D, §10.4, §10.6. Scope:
orchestrator/adapters/plaso/jsonl.py, METHODOLOGY.md (§6.D wording only),
orchestrator/adapters/tests/test_tool_adapters.py (one new test),
matcher/engine.py (_temporal ONLY, and only if the procedure below selects
Branch B). Nothing else.

Task A — fallback crash edge (decision already made, implement exactly):
In _classify, the final fallback returns plaso's data_type as
artifact_class. An event with empty data_type and no path yields
artifact_class="" which fails ToolFinding validation and kills the whole
adapter run. Change the final return to:
  return (data_type or "timeline_event"), "log_line"
Add ONE test in test_tool_adapters.py: adapt_plaso_events([{"message":
"boot noise", "timestamp": 1751536194000000}], run_id="r") returns one
finding with artifact_class == "timeline_event" (and does not raise).
Unknown classes are inert for §5 is-a matching, which is the intended
conservative behavior — do not add them to any rule or table.

Task B — RQ4 evidence source (follow the procedure; do not decide by
opinion):
1. Reuse (or regenerate) the current offline outputs from the latest run
   available (after 6.1b this is the fresh live run; otherwise /tmp/step61a).
2. Inspect: python3 -c over outcomes.jsonl — for rows with outcome
   "identified" AND gt_time set, count how many have time_offset_s null vs
   non-null. Also report the distribution of parser/timestamp_desc for
   timeline findings:
   python3 - <<'EOF'
   import json,collections
   c=collections.Counter()
   for line in open('<timeline tool_findings path>'):
       r=json.loads(line)
       if r['tool']=='plaso': c[(r['provenance'].get('parser'),r['entity'].get('time_kind'))]+=1
   print(c.most_common(15))
   EOF
3. Branch A — if at least one identified expectation with gt_time has a
   non-null time_offset_s: the design stands (timeline events supply RQ4;
   disk objects and memory findings supply none). Edit METHODOLOGY.md §6.D
   to state exactly that: offsets come from event findings (plaso
   timestamp_desc, including filestat MACB kinds); bodyfile object findings
   (entity["timestamps"]) and memory findings contribute no offsets.
   No matcher change.
4. Branch B — if ALL identified expectations with gt_time have null
   offsets: extend _temporal in matcher/engine.py so that, in the loop over
   claim source findings, after the scalar f.time check it also considers:
     for kind, value in (f.entity.get("timestamps") or {}).items():
         parse value; offset = parsed - gt_epoch
         compare into `best` exactly like the scalar branch, with `kind`
         as the kind label
   (~8 lines; ValueError continues; no other changes). Update the §6.D
   wording to include disk-object MACB timestamps. Extend the EXISTING
   test_temporal_offset_only_from_identity_matching_truth_event in
   matcher/tests/test_matcher.py minimally (give one finding
   entity["timestamps"] instead of scalar time) — no new test file.
State in the handoff which branch fired and paste the step-2 evidence.

Hard constraints: §10.4 — timestamps never affect outcomes; only the RQ4
block may change. §10.6 — never fabricate or default a time.

Verification: pytest green; re-run match-canonical on the current artifacts;
outcomes identical to before this step; RQ4/temporal block consistent with
the chosen branch.
Commit: "plaso: non-empty fallback class; RQ4 source per §6.D (branch A|B)"
```

---

## Prompt 6.3 — console/report wiring + v2 vocabulary purge

```
Spec: METHODOLOGY.md §6 — the output surface is exactly: block A coverage,
block B sources, block C triage, block D temporal, plus the
per-expectation table (expectation | outcome | observed by | claimed by
(rules) | sources | time offset). Nothing else. §10.3: no
precision/F1/false-positive vocabulary anywhere in live output; a metric
that needs a disclaimer is deleted, not disclaimed.

Scope: matcher/engine.py (render_console_summary and the report.md
renderer only), cli.py (console output of run and match-canonical), TODO.md
(vocabulary only). Nothing else.

Step 1 — audit the renderer against the §6 checklist above, section by
section. Fix mismatches by DELETING extras and adding only missing §6
fields. Do not invent new metrics or formatting systems.

Step 2 — cli.py: both `run` and `match-canonical` must print the §6 summary
via render_console_summary. Any raw-finding or claim counts printed must be
labeled as diagnostics (e.g. "candidate stream (diagnostic)"), never as
detection quality.

Step 3 — v2 key purge (AUDIT_NOTES.md open question 2):
  rg -n "precision|\bf1\b|per_class|match_score|relation=.fp|matches\.jsonl|score_report" \
     --type py -g '!*/tests/*'
  rg -ln "precision|\bf1\b|score_report" scripts/ tools/ figures/ 2>/dev/null
For every hit in live code: fix it (v3 name) or, if unclear, STOP and
report it. Historical/reference files are exempt and must NOT be edited:
docs/father_ldpreload_walkthrough.md, docs/detection_rule_audit.md,
AUDIT_NOTES.md, refactor-5.md, METHODOLOGY.md (it names the banned terms).

Step 4 — TODO.md vocabulary pass (wording only, keep structure/content):
replace "candidate precision" framing with residual-claims/diagnostic
framing; "strong reconstruction" -> "identified"; "score_report.md" ->
"report.md". Do not add, remove, or reorder items.

Verification:
  python -m pytest orchestrator/ detectors/ matcher/ -q
  match-canonical over the current artifacts; paste the console output and
  check it shows the four blocks + the table;
  rg -in "precision|\bf1\b|false.positive" cli.py matcher/ detectors/ \
     README.md PROJECT_CONTEXT.md TODO.md   -> no live hits.
Commit: "report: §6 console/report surface; purge v2 metric vocabulary"
```

---

## Prompt 6.4 — detection layer: community/standard rules (RESEARCH-GATED)

PRECONDITION: the deep-research pass (query below) is done and its
conclusion is pasted into the [RESEARCH DECISION] slot. Without it, only
Phase 1 may run.

```
Spec: METHODOLOGY.md §5, §7, §10.5, §10.8. Context: the detection layer is
10 hand-written YAML rules over a closed artifact-class vocabulary with
hand-rolled path classification; it is the weakest layer and the step-5b
class narrowing changed what timeline rules can see. Goal: replace
hand-rolled classification and bespoke rule content with
community/standard equivalents where they genuinely apply, keep custom
rules only where nothing standard exists (memory correlation, bodyfile
object heuristics).

Phase 1 — rule audit (report only, no edits):
For each rule under detectors/rules/**: one table row —
id | source_types | artifact_classes | tokens/params | still fires after
the 5b reclassification? (check against the current tool_findings) |
community equivalent exists? (Sigma rule id/name if known) | verdict
(keep custom / replace / tighten / delete).
Also verify flab.timeline.suspicious_shell_history against the new plaso
classes: it previously matched /var/log lines classed as
shell_history_log_event; after 5b those carry data_type classes. Report
whether the rule is now dead weight on timeline evidence.

Phase 2 — implement the research decision:
[RESEARCH DECISION — paste here: chosen engine/format (e.g. pySigma+SQLite
hybrid, Zircolite-style SQLite matching, plaso tagging), which rule corpus,
which of our rules it replaces, integration point]
Constraints regardless of decision:
- Claims keep the DetectionClaim schema (rule_id, artifact_class, entity,
  source_findings, attck) — the matcher must not change in this step.
- GT-blind: no instance values in rules; test_rule_leakage.py must stay
  green and must cover the new rule corpus location too.
- Every rule (imported or custom) carries ATT&CK technique tags; a rule
  without attck cannot produce `supported` outcomes (§10.5) — imported
  rules missing tags get them added or are excluded.
- Per-run toggles are CLI flags; no scenarios.yaml/config mutation.
- Stay lightweight: no Timesketch, no SIEM, no daemon, no heavy framework.
  New pip deps only if the research decision names them explicitly.
Acceptance: offline chain (run-adapters -> run-detectors -> match-canonical)
over the current run; per-AE outcomes explained vs before; residual claims
per rule reported; leakage test green; detectors/rules/README.md updated to
describe the new rule sourcing.
Commit per phase.
```

### Deep-research query for 6.4 (paste into the research tool)

```
Context: I maintain a small academic Linux post-mortem forensics lab
(thesis project). A controlled attack scenario (currently LD_PRELOAD
userland rootkit persistence; later timestomping-style scenarios) runs in a
VM; afterwards the pipeline acquires a disk image and a RAM dump and
normalizes tool output into JSONL "findings": Sleuth Kit `fls -m` bodyfile
rows (filesystem objects with MACB timestamps, deleted-inode flags),
Volatility 3 plugin output (processes, memory mappings, sockets, bash
history), and Plaso/psort timeline events (log2timeline; note psort's
native storage is already a SQLite .plaso file). There is NO live telemetry:
no auditd, no execve logging, no EDR events — only what a post-mortem disk
image, a memory dump, and a filesystem timeline contain.

Current state: detection is 10 hand-written YAML rules (token/path/class
matching plus small process↔library and process↔socket correlations over
memory findings), with hand-rolled filesystem path classification. This is
brittle and hard to defend academically. Rules must stay ground-truth-blind
(no scenario-specific paths/hashes) and must carry MITRE ATT&CK technique
tags, because downstream scoring uses technique overlap.

Question: what existing, maintained, lightweight technology could
realistically replace or back this detection layer, given that the evidence
is post-mortem artifacts rather than live event logs? Please evaluate at
least these directions, with their real limitations, and propose others:

1. Sigma rules via pySigma with a SQLite backend: how mature is the SQLite
   backend; which rule features are unsupported (e.g. keyword/full-text
   rules, `|contains|all` modifiers); could SQLite FTS5 cover the keyword
   gap in a hybrid setup; and crucially, which part of the public Sigma
   Linux rule corpus is even applicable to post-mortem filesystem/timeline
   evidence rather than auditd/process-creation telemetry?
2. Querying Plaso's own SQLite storage directly (psort filters, SQL over
   the .plaso database) — is there prior art for rule packs at that layer?
3. Plaso analysis/tagging plugins (tag_linux.txt style): expressiveness,
   community rule availability, ATT&CK mapping support.
4. Zircolite or similar "Sigma on SQLite/JSONL" engines: do they work on
   arbitrary JSONL like bodyfile/Volatility output, or are they
   EVTX/Windows-bound in practice?
5. Keeping a small custom engine but adopting a standard rule format and
   taxonomy (Sigma YAML syntax, Plaso data_types as the field vocabulary)
   so community rules can be imported selectively.

Constraints: offline/batch execution, Python-friendly, minimal
dependencies, no Timesketch, no SIEM/EDR platforms, no external services;
the lab already auto-produces the SQLite .plaso timeline. Memory-forensics
correlation rules (process↔library↔socket) probably stay custom — confirm
whether any community rule format covers memory-forensics findings at all.

Deliverable: a comparison of the viable options (coverage of my evidence
types, rule-corpus applicability to post-mortem Linux, maturity,
integration effort), a recommendation for a thesis-defensible setup, and a
concrete integration sketch (what runs where in a
findings-JSONL -> claims-JSONL pipeline, and how many community rules would
realistically fire on LD_PRELOAD-style persistence evidence).
```

---

## Prompt 6.5 — test-suite design review (REPORT ONLY, no edits)

```
Context: every test in this repo was AI-authored and has never been read by
the maintainer. Produce the review that lets the maintainer decide what to
keep without reading everything cold. THIS SESSION MAKES NO EDITS — no
test changes, no source changes, no formatting. Output is a report.

Read: every file under orchestrator/adapters/tests/,
orchestrator/canonical/tests/, orchestrator/core/tests/, detectors/tests/,
matcher/tests/, scenarios/**/tests/ (and any test file elsewhere:
rg -l "^def test_|^class Test" --type py). Read source files only as needed
to judge what a test actually protects. Run the suite once:
python -m pytest orchestrator/ detectors/ matcher/ -q (record runtime too).

For EVERY test function produce one table row:
file | test name | LOC | what real behavior it protects (one line, concrete
— name the invariant or bug class, e.g. "§10.1 many-to-one, claim not
consumed") | failure value: would a real regression plausibly trip it? |
over-specification (pinned strings/ids/counts that break on harmless
change) | redundancy (another test already covers it — name it) |
verdict: KEEP / REWRITE (say what) / MERGE (into what) / MOVE (where) /
DELETE (why safe).

Then four summary lists:
1. Load-bearing tests — the ones that directly pin AGENTS.md invariants or
   METHODOLOGY §10 guardrails (expect at least: rule-leakage lint,
   GT-import lints, matcher §10 tests, required_for_scoring fail-safe).
2. Deletion candidates ranked by (LOC saved x confidence nothing is lost).
3. Structural issues: wrong directory, cross-package fixture reach,
   fixture files that could be inline, subprocess tests that could be
   in-process (or are justified — say which).
4. Missing high-value coverage — MAXIMUM 3 items, each justified by a
   plausible real regression, not completeness.

Grading bias: this repo prefers few, behavior-level tests (AGENTS.md: at
most one focused test per behavior change; no fixtures/matrices). A test
that re-asserts dataclass field lists or mirrors implementation line by
line is bloat even if green. Do NOT propose new test frameworks, coverage
tooling, or parametrized suites.

Deliverable: the report pasted in full, plus the same content written to
/tmp/test-review.md. No commits.
```
