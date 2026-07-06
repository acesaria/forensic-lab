# REFACTOR_PLAN.md — v2 → v3 evaluation rewrite

Working plan for the heavy refactor of the detection / matching / metrics /
adapter layers. **METHODOLOGY.md (§1–§10) is the spec; §10 is the "must not
regress" guardrail list.** This file is disposable once the refactor lands.

## Status (2026-07-06, post step-5 closeout audit)

- Steps 1–5 are DONE. Step 5 ran as sub-steps 5a–5d (handoff: refactor-5.md);
  5a merged as PR #6, 5b–5d committed on main (15deabaf).
- Offline parity holds on the cached run: 4 identified / 1 supported /
  2 missed over 7 scored, metrics byte-identical before/after 5d.
- NOT yet validated end-to-end: the new adapter output. The cached
  tool_findings.jsonl (run 20260703-115003) and the clean-baseline cache
  under shared/baselines/ both predate 5a; adapters have unit-fixture
  coverage only until the live re-run (6.1).
- Branch policy: main only. All other branches, worktrees, and the stash
  were deleted 2026-07-06; old experiment dirs pruned to the acceptance
  run + the clean-baseline acquisition run (its dumps can regenerate the
  baseline cache without a VM acquisition).
- Step 6 re-scoped below ("Remaining work"); the original Step 6 section is
  superseded by it.

## Remaining work (re-scoped 2026-07-06; ordered)

- **6.0 AE model prune** (first after tree clean). Delete the write-only
  `ArtifactExpectation` fields (`observable_kind`, `persistence`,
  `observability`, `critical`) from models.py, run_context authoring, the
  scenario YAML, and tests. Offline check: `run-scenario` re-emits
  expectations; matcher parity unchanged.
- **6.1 Live re-run + cache refresh.** `python cli.py run` on the live lab —
  the first real execution of the 5a–5d adapters. Regenerate the clean
  baseline cache from the new adapters (the cached clean-baseline dumps
  allow this offline; otherwise re-acquire). Explain any outcome changes
  line by line (the 5b reclassification will move claim counts). Then
  delete the pre-5 cached run and the matcher's legacy
  `f.time == "unknown"` guard (matcher/engine.py:323), which exists only
  for that cache.
- **6.2 Temporal/classification review** (audit findings 3+4, one session).
  Plaso data_type fallback is the decided design, but close the crash edge
  (empty data_type → artifact_class="" → ValueError kills the adapter run);
  one focused test. Verify plaso actually supplies the MACB events
  (filestat timestamp_desc) that RQ4 relies on now that bodyfile emits
  untimed object findings; if it does not, decide matcher-side
  entity["timestamps"] consumption. Align §6.D wording with the decision.
- **6.3 Wire, report, docs** (the original Step 6). match-canonical console
  summary, §6 report renderer check, figures; check figure scripts for v2
  metrics keys (AUDIT_NOTES open question 2). PROJECT_CONTEXT/README v3
  vocabulary already fixed 2026-07-06; TODO.md still needs the same pass.
- **6.4 Rule/classification review** (audit findings 5+9 — the detection
  layer is thin and possibly broken). Prefer standard taxonomies over
  hand-rolled path classification (plaso parser/data_type; community Sigma
  rules via the planned pySigma+SQLite path). Re-review
  suspicious_shell_history after the 5b class narrowing. AEs + rules are
  placeholders by decision — this is where they stop being placeholders.
  docs/detection_rule_audit.md is the input document.
- **6.5 Test-design review** (bounded, report-first). The suites are
  AI-authored and unreviewed. One session, report only: per test file —
  what it protects, over-specification/bloat, right directory,
  keep/rewrite/delete. Then apply the minimal cut.

## Strategy (read once)

- **Delete-and-rewrite, don't patch.** The v2 matcher (`matcher/engine.py`,
  1219 LOC) is condemned. Write a new ~300-LOC matcher from §5/§6/§10; never
  load the old one to "reconcile" it. Same for redundant metric blocks.
- **The methodology is the plan.** Don't run heavyweight planning. Each prompt
  points at METHODOLOGY.md + the 1–2 files in scope. No session reads the whole
  tree.
- **Validate offline, not on the VM.** The matcher/detector/adapter changes are
  validated with the offline CLI (`run-detectors`, `match-canonical`) over the
  cached run under `shared/experiments/…20260703-115003`. Full `cli.py run` on
  the live VM happens only once at the very end to regenerate figures.
- **Acceptance anchor (provisional, do not overfit).** On the cached Father
  run the current scored set is 7 attack-core AEs → **4 identified / 1 supported
  / 2 missed** as of the v3 matcher (Step 3): accept-hook-session = supported
  (detection gap), hooked-listener-process = missed (detection gap),
  shell-session-process = missed (acquisition gap — never observed in raw
  findings). Step 4 reproduced this exactly (claim-for-claim parity with the
  cached v2-engine claims). This is a *mechanics* check, not a target: the AEs
  and detection rules are **custom-written placeholders that will be
  reviewed/refactored later** (better rules, possibly community-accepted
  rules — deferred). So the real acceptance is that each of the 7 outcomes is
  *individually explainable* by §5 and that the funnel/corroboration machinery
  behaves; the split is what today's AEs+rules happen to yield and will
  change when they do. Never tune the matcher to reproduce the number.

## Token discipline

- Point each prompt at specific files. Delete-before-read where possible (no
  need to read a file you're deleting).
- One work unit = one session. Don't chain units in a single session.
- Keep diffs small; run the offline validation at the end of each unit.
- Do **not** run broad parallel reviewer/auditor commands inside the same Fable
  session that did the implementation. They repeatedly exhaust the session
  before the review can be acted on. Fable should do only a bounded local
  self-check: `git diff -- <scope>`, targeted `rg`, focused tests, and the
  offline acceptance command.
- Full code review is a separate work unit. Prefer handing the diff to Codex or
  another fresh reviewer session with the exact step scope and the 2-3 invariants
  most likely to regress. No 8-agent fan-out unless the task is a report-only
  audit with enough budget to finish.

## Session / context discipline

- Start a fresh Fable session for each numbered step, plus a fresh session for
  review if review is not delegated. Do not carry the whole previous chat.
- Handoff context per session is only: `AGENTS.md`, `PROJECT_CONTEXT.md`, the
  relevant `METHODOLOGY.md` sections, the single step from this file, and the
  files named by that step. If the session needs more files, it must name why.
- End each implementation session with a short handoff block: files changed,
  validation commands and outputs, known risks, and what must be reviewed next.
- For review sessions, inspect the diff and named files only. Do not reread the
  whole repository and do not spawn parallel review agents by default.

## Tooling per step

| Step | Model/session | Skill to invoke | Delegate to Codex? |
|---|---|---|---|
| 1 Audit | strong, report-only | bounded audit prompt; no fan-out unless budgeted | n/a (report only) |
| 2 Model+authoring | strong | `/simplify` after, bounded self-check | ok (mechanical) |
| 3 Matcher rewrite | strong, keep in-session | `/plan` optional; external/fresh review after | **NO — design-critical** |
| 4 Detection/baseline | strong | `/simplify`, bounded self-check; external/fresh review | partial |
| 5 Adapters | strong + DFIR lens | `/simplify` | ok (once audit says what to cut) |
| 6 Wire+validate | strong | `/verify`, bounded self-check; external/fresh review | no |

**Fable → Codex split:** delegate only *mechanical* units where the guidelines
can be exhaustive (adapter deletions, test rewrites, wiring). Never delegate the
matcher rewrite or the model semantics — an executor drifts on design calls and
you burn more tokens reconciling than you saved.

**DFIR-expert lens** matters only for Step 5 (are the adapters forensically
complete/correct: MACB kinds, deleted-inode detection, artifact_class labels).
Everything else is architecture/laziness, not forensics.

## Reusable prompt template

```
Role: senior dev refactoring forensic-lab. Spec = METHODOLOGY.md §<N>.
Scope: <exact files>. Do NOT touch anything else.
Task: <one sentence>.
Hard constraints:
  - Obey METHODOLOGY.md §10 guardrails (name the relevant ones).
  - Delete, don't patch. No new abstractions, no config for constants,
    no interface with one impl. Target <= <LOC> lines.
  - GT-blind layers never read GT/expectations/step_id/seeds.
Out of scope: <what to leave alone>.
Acceptance: <concrete: numbers / tests / LOC>. Validate offline with
  `python cli.py <cmd>` over shared/experiments/<cached run>.
Output: the diff + <=3 lines on what was cut.
```

---

## Step 1 — Audit (report only, no edits)

Run a bounded audit prompt. Focus the report on `orchestrator/adapters/`,
`detectors/`, `orchestrator/canonical/`, and confirm `matcher/engine.py` is a
full delete. Produce a ranked delete/simplify list with LOC-reduction targets.
This is the map for Steps 4–5. No code changes. Do not launch parallel audit
agents unless the session is dedicated to audit only and has enough budget to
finish the report.

## Step 2 — Canonical model + authoring foundation

Spec: METHODOLOGY.md §3, §10.2, §10.6, §10.9. Files:
`orchestrator/canonical/models.py`, `orchestrator/scenarios/run_context.py`,
scenario `expected_observables.yml` authoring.

- Add `required_for_scoring: bool` to `ArtifactExpectation`; thread it through
  `_artifact_record` (run_context.py:111). **Fail safe: missing/None ⇒ contextual
  (not scored), never scored.**
- Establish the `time_kind` entity convention (crtime/mtime/ctime /
  plaso `timestamp_desc`) for adapters to fill in Step 5.
- Remove `log` from any authored `source_eligibility` until an adapter emits it.
- `/simplify` the reflection helpers in models.py only if the audit flags them;
  otherwise leave (contained, works).

Acceptance: model round-trips the flag; `run-scenario` re-emits expectations
with `required_for_scoring` preserved.

## Step 3 — Matcher greenfield rewrite (the core; keep in one session)

Spec: METHODOLOGY.md §5, §6, §10. **Delete `matcher/engine.py` and
`matcher/tests/test_matcher_engine.py` first**, then write a new matcher.

Target shape (~250–350 LOC, no more):

```
run_matcher(expectations, findings, claims) ->
  scored = [e for e in expectations if e.required_for_scoring]
  for e in scored:
    observed  = any identity-field hit over raw findings        (rule-independent)
    claimed   = any claim whose source_findings observed e
    identified= any claim with an exact identity-field match     (§5, §10.4)
    supported = else: any claim, class via §5 is-a table + source
                eligible + NON-EMPTY attck overlap               (§10.5)
    outcome   = identified | supported | missed
    sources   = union of matching claims' sources
  metrics = 4 blocks (§6 A coverage / B sources / C triage / D temporal)
  table   = per-expectation (§6): expectation|outcome|observed|claimed|sources|offset
  write outcomes.jsonl + metrics.json + report.md
```

Hard constraints (§10): many-to-one, no `used_cand`/priority-sort/score; no
`relation="fp"`, no precision/F1/micro/per-class-F1 — unmatched claims are
**residual claims counted per rule** only; basename/time never establish
identity; exact identity ⇒ identified regardless of attck.

Acceptance (mechanics, not a score target — AEs are provisional): every scored
AE gets an outcome *explainable by §5*; on today's cached run that is 4/2/1, but
correctness = the reasoning per AE, not the number; corroboration is non-zero
where disk+timeline both match; `match-canonical` runs clean. Hand the diff to a
fresh/external review after validation; do not run a parallel `/code-review` in
the implementation session.

## Step 4 — Detection engine + baseline conformance

Spec: METHODOLOGY.md §7, §10.3, §10.8. Files: `detectors/engine.py`,
`detectors/baseline.py`, rules. Apply Step 1 audit findings.

- Confirm GT-blindness: no `step_id`/seeds/target paths/hashes in claim entities.
- Ensure claims carry what the v3 matcher needs: identity fields in `entity`,
  `attck`, `source_findings`. Drop dead fields (e.g. `confidence` if v3 uses
  only the baseline downgrade flag — replace with a boolean if so).
- Keep `baseline.py` semantics (conservative, non-leaking); shrink per audit.
- Prune, don't add. Target LOC cut from the audit.

Acceptance: `run-detectors` over cached findings produces claims the Step 3
matcher scores to the acceptance numbers.

## Step 5 — Adapters: DFIR review + simplify

Spec: METHODOLOGY.md §5 (artifact classes / is-a), §10.6. Files: all of
`orchestrator/adapters/` (bodyfile, plaso, volatility3, yara, common).
Apply Step 1 audit findings. **Use a Linux-DFIR-examiner lens here.**

- Forensic correctness: bodyfile emits `time_kind` + keeps MAC components (stop
  the crtime||mtime||ctime collapse at bodyfile.py:86); deleted-inode detection;
  `artifact_class` labels match the §5 is-a table exactly (no classes the
  matcher can't use).
- Laziness: collapse duplication in `common.py`; kill per-row provenance bloat
  if the audit flags it; drop unused `TemporalQuality` levels / `EvidenceSource`
  members no adapter produces.
- Target a large LOC cut across the dir; `/simplify` to finish.

Acceptance: adapters still produce the ToolFindings the matcher needs; offline
pipeline reproduces acceptance numbers.

## Step 6 — Wire, report, validate

Spec: METHODOLOGY.md §6. Files: `cli.py` (`match-canonical` console summary),
matcher report renderer, minimal new matcher tests, `PROJECT_CONTEXT.md`,
`README.md`.

- Report = §6 four blocks + per-expectation table. Delete v2 report sections.
- Update `PROJECT_CONTEXT.md` / `README.md` to v3 vocabulary (drop
  "strong/candidate/final reconstruction", "schema v2", MatchResult framing).
- Minimal regression tests: one pinning many-to-one + identity rules, one
  pinning the acceptance numbers.
- `/verify` the offline pipeline end-to-end; then one live `cli.py run` to
  regenerate figures.

Acceptance: end-to-end offline run green; live run reproduces the numbers;
`metrics.json` matches METHODOLOGY §6 exactly (nothing else).

## Deferred risks (revisit after Step 6; all fail conservative — offsets go absent, never fabricated)

From the temporal-identity fix (matcher `_temporal`/`_truth_entity`):

- GT action time is found by identity across *all* truth events (earliest
  match), not step-keyed. If a scenario ever records two truth events for the
  same object where the earliest is not the intended action time, the RQ4
  offset shifts. Fine for Father; recheck when authoring a second scenario.
- A `process`-type truth event matches only an expectation that pins `pid`;
  expectations pinned solely by name/argv fragments get no GT time from it
  (offset absent, outcome unaffected).
