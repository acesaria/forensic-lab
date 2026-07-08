# METHODOLOGY.md

Normative evaluation semantics for forensic-lab. The matcher, metrics, and
report code must implement this page literally; if code and this page
disagree, this page wins. Behavioral rules for contributors stay in
AGENTS.md; repo facts in PROJECT_CONTEXT.md.

## 1. Research questions

- **RQ1 — Reconstruction coverage.** How much of a known attack can a
  GT-blind analysis pipeline reconstruct from post-mortem evidence, and why
  do misses happen?
- **RQ2 — Combined-source value.** What do disk, memory, and timeline
  analysis each contribute, and what does combining them add, across
  different attack scenarios?
- **RQ3 — Triage cost.** How large is the evidence haystack an analyst must
  review at each pipeline stage?
- **RQ4 — Temporal placement (lite).** When an artifact is identified, how
  accurately does the evidence place it in time?

RQ1 and RQ2 are co-headlines; RQ3 and RQ4 are secondary blocks.

## 2. Evaluation unit and matrix

One **run** = (scenario, VM profile, rule profile). Metrics are computed per
run and never pooled across runs.

- Scenarios (classic, documented techniques): `userland_father_ldpreload`
  (LD_PRELOAD rootkit), LKM rootkit, ptrace injection, CopyFail (2026),
  optionally an eBPF proof-of-concept.
- VM profiles: 2× Ubuntu, 1× Fedora.
- Rule profile: the detection ruleset version (§7), declared in the metrics
  output.

Aggregation is presentation-only: scenario-level coverage = plain average of
the per-VM run coverages (macro average); cross-scenario results are shown
side by side, never averaged into a single number. Hardened guests
(auditd + SELinux/AppArmor) are future work and out of scope here.

## 3. Vocabulary (normative)

- **Ground truth (GT)** — the answer key a scenario writes about itself at
  execution time: `execution_truth.jsonl` (timed actions) and
  `artifact_expectations.jsonl` (expected traces).
- **Expectation** — one answer-key entry: "this attack leaves trace X".
  - **Scored** expectation (`required_for_scoring: true`): a trace of the
    attack itself. Only scored expectations enter metric denominators.
  - **Contextual** expectation: lab bookkeeping / provenance (run logs,
    source archives). Listed in reports for context, never scored.
- **ToolFinding** — one normalized row of raw forensic tool output (bodyfile
  row, plaso event, Volatility row). A neutral observation, never a result.
- **DetectionClaim** — a GT-blind rule flagged one or more findings as worth
  an analyst's attention. A shortlist entry modeling triage, not a verdict.
  Claims carry no maliciousness ground truth, so detection-theoretic
  vocabulary (false positive, precision, F1) does not apply to them.
- **Identity field** — a field capable of pinning the one specific object an
  expectation refers to: full path, sha256, pid, socket endpoint
  (address:port), process name+argv.
- **Outcome** — every scored expectation gets exactly one of:
  - **identified** — some claim matches on ≥1 identity field;
  - **supported** — claims of the right artifact class from an eligible
    source with overlapping ATT&CK technique exist, but none pins the
    specific object;
  - **missed** — neither.
- **Funnel** — three per-expectation questions that locate a miss:
  1. **observed?** the object appears in some ToolFinding (identity-field
     search over raw findings; rule-independent);
  2. **claimed?** some GT-blind rule shortlisted such a finding;
  3. **identified?** as above.
  Gap names: not observed = **acquisition/tool gap**; observed but not
  claimed = **detection gap**; claimed but not identified = **specificity
  gap**.
- **Residual claims** — claims matching no expectation: the analyst's triage
  burden. Not false positives.
- **Corroboration** — ≥2 distinct evidence sources (disk / memory /
  timeline) contribute matching claims to the same expectation.

## 4. Pipeline and GT-blindness contract

scenario execution → GT written → acquisition (memory VM ON, disk VM OFF) →
extraction → ToolFindings (adapters) → clean-baseline known-good filtering
(GT-blind, per evidence source, never on memory) → DetectionClaims (GT-blind
rules) → matching + metrics + report (GT-aware).

Detectors, adapters, and rules never read GT, expectations, target
paths/hashes, step names, or seeds; rules never contain scenario instance
values. Only the matching/metrics/report layer is GT-aware.

**Time invariant:** all timestamps are ISO-8601 UTC (`Z` suffix,
millisecond precision) end to end; guests run with UTC clocks (recorded in
`reference_context.json`); comparisons happen on epoch values. Adapters must
never emit local time. Memory evidence is point-in-time and carries no event
timestamps.

**Clean-baseline known-good filtering.** This is *known-file filtering*
(NSRL/RDS and EnCase/Autopsy "known good" hash sets) combined with *attribute
differencing* (the Tripwire/AIDE integrity-monitor model), specialised to a
purpose-built lab baseline instead of a shared reference set. A run finding is
dropped only when an identical baseline finding exists in the **same evidence
source**; families are never merged. Per-source signatures:

- **Disk (TSK bodyfile):** `(artifact_class, type, value, inode, mode, size,
  deleted, reallocated, mtime, ctime, crtime)`. **atime is stored but excluded
  from the key on purpose.** Baseline and scenario are two separate boots from
  the same snapshot, taken minutes apart; booting and running *reads* files,
  which under `relatime` bumps atime to each boot's wall-clock while
  mtime/ctime/crtime stay at the snapshot values. Keying on atime would leave
  every merely-read baseline file unmatched (empirically ~5,000 of ~6,600
  in-window disk rows), collapsing the filter to noise. The exclusion loses no
  attacker signal: any *deliberate* atime change also updates ctime (which is
  keyed), and genuine read events survive as timeline findings (below), not as
  disk objects. No SHA-256 is computed, so this is attribute differencing, not
  hash integrity — same-size in-place edits with unchanged mtime/ctime evade it
  (§9).
- **Timeline (Plaso):** `(artifact_class, type, value, time, time_kind)`.
- **Memory (Volatility):** never filtered — a different boot means pids,
  addresses, and sockets all differ, so cross-boot row equality is meaningless.

**Division of labour, TSK vs. Plaso.** The two overlap on filesystem MACB
stamps by nature (Plaso's filestat parser re-emits them as events); the split
is **state vs. events**, not "which timestamps". The disk family answers *which
objects differ from known-good state* (inode, deleted/reallocated flags,
low-level attributes; no scalar event time is claimed for a bodyfile row). The
timeline family answers *what happened, when, in what order*. Consequently the
disk filter does nearly all the reduction work (baseline files read at boot are
byte-identical objects); the timeline filter removes almost nothing, because
**case-window scoping already discards pre-scenario events before the baseline
filter runs**. The timeline branch is kept as a cheap invariant that becomes
load-bearing only if the window is widened.

## 5. Matching semantics (normative)

- Only scored expectations are matched and scored.
- Matching is **many-to-one**: each expectation collects *all* claims that
  describe it. There is no one-to-one assignment, no priority ordering, and
  no match score; a claim may support multiple expectations.
- **Identified** requires an exact identity-field match:
  - paths: equality after normalization (strip "(deleted)" markers, ensure
    leading `/`, `normpath`), or anchored-suffix equality when the
    expectation path is relative. Basename-only equality is never identity.
  - sha256 / pid / socket endpoint: exact equality.
  - process: expected name/argv fragment contained in the claim's process
    name, path, or argv.
- **Timestamps never establish identity.** A time within the case window
  may corroborate an identity match (reported in RQ4) but contributes no
  outcome on its own.
- **Supported** requires all of: artifact-class compatibility via the is-a
  table below, source eligibility (claim's evidence source ∈ expectation's
  `source_eligibility`), and ATT&CK technique overlap between rule and
  expectation.
- Artifact-class is-a table (only true subtype relations):
  `shared_object`, `service_unit_file`, `preload_configuration`,
  `deleted_file_candidate` ⊂ `file`; `library_mapping` ≈ `shared_object`.
  No other aliases.
- **Observed** (funnel level 1) uses the same identity-field comparison
  applied directly to raw ToolFindings; it is independent of the rule
  profile.

## 6. Metrics (schema v3)

Per run, four blocks plus one table. Nothing else.

- **A. Coverage (RQ1):** counts of identified / supported / missed over
  scored expectations; `coverage_identified = identified / scored`;
  `coverage_any = (identified + supported) / scored`; funnel gap counts.
- **B. Sources (RQ2):** per source — expectations observed, claimed,
  identified; **unique contribution** (expectations identified by claims
  from that source only); corroboration rate (identified expectations with
  ≥2 sources); **combination gain** = `coverage_identified(all sources)` −
  `max over single sources of coverage_identified(that source alone)`.
- **C. Triage (RQ3):** raw finding count → claim count (reduction ratio);
  residual claims per rule; baseline-differencing effect (per-source
  ToolFinding counts before/after clean-baseline known-good filtering).
- **D. Temporal (RQ4, lite):** for each identified expectation having both a
  GT action time and an event-finding timestamp: signed offset in seconds and
  the timestamp kind that supplied it (Plaso `timestamp_desc`, including
  filestat MACB kinds such as crtime/mtime/ctime); summary = median and
  maximum absolute offset. When several findings supply a timestamp, the
  smallest absolute offset is reported (best evidence placement). Bodyfile
  object `entity["timestamps"]` metadata and memory findings do not contribute
  offsets.

**Per-expectation table** (the report's core):
`expectation | outcome | observed by | claimed by (rules) | sources | time offset`.

Explicitly dropped from the previous schema (and from the vocabulary):
claim-level tp/fp/fn, precision/recall/F1 (micro and macro), per-class and
per-source F1, match scores, "strong/candidate/final reconstruction"
terminology, methodology-warning blocks.

## 7. Detection rule profile

Hybrid policy:

- **Timeline/log:** Sigma rules compiled via pySigma (+ SQLite FTS5 for
  keyword rules) — community-standard content.
- **Disk:** filesystem heuristics limited to documented techniques; YARA
  content-scanning optional where community rules exist.
- **Memory:** custom correlation only (process↔library, process↔socket by
  pid); no community standard exists for correlating Volatility output.
- Every custom rule cites a documented technique (ATT&CK detection notes,
  vendor/DFIR write-ups) in its YAML `description`/reference field.
- The profile is named and versioned; the version string is embedded in
  `metrics.json`.

Rule-independence: blocks A/B/C/D are defined over outcomes, not rules.
Level "observed" and the identified-given-claimed grading do not change when
rules change; iterating on rule content moves only the "claimed" funnel
level and block C. Metrics therefore stay valid while the rule profile
evolves.

## 8. Standards alignment

- **NIST SP 800-86** phases: collection = acquisition (§4, power-state
  contract); examination = extraction + adapters; analysis = detection +
  matching; reporting = metrics + score report.
- **ISO/IEC 27037-style handling:** analysis operates on acquired images and
  cached artifacts only; the original VM evidence is never modified
  post-acquisition.
- **MITRE ATT&CK** labels expectations and rules; technique overlap is part
  of the "supported" definition (§5).
- Community detection standards (Sigma, YARA) supply rule content (§7).
- **Known-file filtering / integrity monitoring:** the clean-baseline filter
  (§4) is the lab-scale analogue of NSRL/RDS known-good hash sets and the
  Tripwire/AIDE attribute-differencing model; it uses a purpose-built baseline
  rather than a shared reference set, and attribute tuples rather than hashes.

## 9. Limitations and non-goals

- Claims have no per-claim maliciousness ground truth; therefore no
  precision/false-positive-rate is reported at the claim level, by design.
- GT is authored by the scenario itself; expectations inherit its scope.
- Memory evidence cannot contribute temporal placement (point-in-time).
- Scenarios are scripted single-attacker runs on lab VMs; results are case
  studies, not population statistics — hence macro averages and side-by-side
  tables only.
- The framework is not a SIEM/EDR/live-response system and must not grow
  toward one; anti-forensics/evasion arms races are out of scope.
- The clean-baseline filter (§4) is **one-directional** (run minus baseline):
  it flags objects present or changed relative to known-good, but cannot by
  itself report an artifact that existed in the baseline and is now *gone*.
  Deleted inodes still surviving on disk are covered (they carry the
  `deleted`/`reallocated` flag and pass through); a fully wiped/reallocated
  file vanishes silently. A bidirectional diff emitting "missing-from-run"
  findings is a possible extension, not implemented — the current scenarios add
  or modify artifacts rather than erase baseline ones, so it would report
  nothing.
- No shared reference corpus (NSRL/RDS) and no cryptographic integrity baseline
  are used; filtering is attribute-level against a self-built baseline, chosen
  to keep the framework light. Memory state is not baseline-diffed; a known-good
  set over stable fields (module names, process names) is conceivable but
  unimplemented.

## 10. Implementation guardrails (normative — must not regress)

These restate consequences of §3–§6 as hard invariants. Each maps to a
defect in the retired schema-v2 matcher; none may be reintroduced.

1. **Matching is many-to-one, never greedy 1:1.** Each expectation
   independently collects *every* claim that matches it; a claim may match
   several expectations. Nothing is "consumed"; there is no priority sort,
   no assignment step, no `used_cand`/`used_exp` bookkeeping. Rationale:
   1:1 assignment structurally forces corroboration (§6.B) toward zero, and
   RQ2 is a co-headline.

2. **`required_for_scoring` round-trips and fails safe.** The flag is
   authored per expectation and carried through *every* canonical record
   unchanged (scenario writer → `ArtifactExpectation` → matcher). Denominators
   (§3, §6.A/B) count an expectation only when it is `true`. A missing or
   null flag is treated as **contextual (not scored)** — never defaulted to
   scored. Contextual expectations still appear in the per-expectation table
   marked `contextual`, and never in any coverage/funnel/source denominator.
   Rationale: silently scoring the lab's own droppings (run logs, source
   archives) inflates coverage and lets the pipeline congratulate itself for
   finding files it wrote.

3. **No claim-level false-positive / precision vocabulary anywhere.**
   Unmatched claims are **residual claims** (§3) and are reported only as
   counts per rule (§6.C). No `relation="fp"`, no precision, no F1, no
   per-class or per-source P/R/F1, no match score. A metric that needs a
   disclaimer is deleted, not disclaimed.

4. **Identity is exact and closed.** `identified` may be established only by:
   normalized-exact or anchored-suffix path equality; exact sha256; exact
   pid; exact socket endpoint; or process name/argv containment (§5). The
   following never establish identity, alone or combined: basename equality,
   a timestamp, `artifact_class`, `source_type`, ATT&CK technique. An exact
   identity match is `identified` **regardless of** technique overlap —
   technique overlap gates only `supported`, and a technique-label mismatch
   must never demote a genuine identity match.

5. **The is-a table is closed; ATT&CK overlap must be non-empty.** Class
   support uses only the subtype edges in §5 — no cross-domain aliases (no
   preload↔shell-history, no shell-history↔process, no socket↔process).
   `supported` additionally requires a **non-empty** technique intersection
   between rule and expectation; an empty technique set on either side is not
   overlap. Report support as "a rule for technique X fired and X was
   expected", not as reconstruction.

6. **Timestamps are optional and typed; findings without a time are normal.**
   Memory findings are point-in-time and carry no event time; some disk
   findings expose only partial MAC times. `time` may be null. A null time
   never affects observed/claimed/identified (those are identity-based) and
   only excludes the expectation from the RQ4 block. Adapters record the
   timestamp **kind** (crtime/mtime/ctime, plaso `timestamp_desc`) beside the
   value and never collapse MACB into one unlabelled timestamp; a fabricated
   or defaulted time is a defect.

7. **`observed` is computed over raw ToolFindings, rule-independent.** It is
   an identity-field search over the *unfiltered* finding stream (never the
   claim stream, never the baseline-filtered stream), so it stays valid as
   the rule profile (§7) changes and a baseline-filtered expectation still
   reads observed=yes / claimed=no — a detection gap, not an acquisition gap.

8. **No ground-truth fields in the GT-blind stream.** Claim and finding
   entities never carry `step_id`, seeds, target paths/hashes, or other GT,
   and the matcher must not read such fields (a class-context fallback keyed
   on `step_id` is both dead code and a GT-leak vector).

9. **Do not assert capabilities the pipeline lacks.** An `EvidenceSource`
   that no adapter emits (currently `log`) must not appear in any
   expectation's `source_eligibility`; a `TemporalQuality` level no adapter
   produces must not gate matching. Eligibility asserts a source that could
   actually match.
