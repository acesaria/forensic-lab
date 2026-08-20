# Deep research prompt: scientific evaluation of multi-source Linux DFIR investigations

## Role and objective

Act as a senior digital-forensics research methodologist. Research and design a
minimal, academically defensible evaluation method for this thesis's controlled
Linux DFIR investigations. The method must cover disk, memory, and timeline now,
remain extensible to network later, and fit the repository's ICM documentation
structure as an always-read investigation contract.

Do not implement code, edit notebooks, run scenarios, or invent experiment
results. Produce a decision-ready methodology with direct citations to standards,
official test programmes, and peer-reviewed primary research.

## Project boundary to preserve

The system under study is a reproducible laboratory workflow:

> deterministic scenario runner → manifest and command-log treatment record →
> disk/memory acquisition → source-specific, human-led investigation notebooks →
> structured findings → bounded metric calculation → manual cross-source
> interpretation.

This is not an automatic detector, matcher, scoring engine, or automatic
reconstruction system. Preserve the separation among scenario validation,
forensic observation, and analyst interpretation. Scenario ground truth may
validate findings but must not silently become discovery logic.

The selected starting position is:

- hybrid/two-pass examination;
- authoritative Father reference run `father-u22-20260819-03`;
- Father behaviour stays unchanged unless a minimal addition to runner-produced
  `manifest.json.facts` is required, in which case the disposable run may be
  recreated;
- a future deleted-content experiment may use two prospective arms: persisted
  write before deletion and naturalistic non-forced-flush write;
- acquisition/investigation validity are gates, not scientific outcome metrics;
- M1–M4 are provisional detection/reconstruction candidates, not accepted yet;
- a compact observation vocabulary and small human adjudication step are
  acceptable;
- one reusable disk, memory, and timeline notebook per scenario should emit the
  same findings/metrics across distribution runs; narrative depth may vary;
- network is deferred but the data model must be source-extensible;
- avoid overengineering: expand the existing manifest only where necessary.

## Repository evidence to read first

Read these in order and treat later explicit decisions as superseding earlier
exploratory recommendations:

1. `ai/ROUTING.md`
2. `ai/INDEX.md`
3. `ai/IDENTITY.md`
4. `ai/03_investigation/CONTEXT.md`
5. `ai/02_experiments/CONTEXT.md`
6. `ai/03_investigation/output/metrics-feasibility-discussion.md`
7. `ai/archive/METHODOLOGY.md`
8. `ai/03_investigation/references/investigation-guidelines.md`
9. `ai/03_investigation/output/disk-investigation-refactor-plan.md`
10. `scenarios/userland_father_ldpreload/runner.py`
11. `shared/experiments/father-u22-20260819-03/manifest.json`
12. current disk, memory, and timeline finding/metric examples referenced by the
    feasibility discussion.

If evidence conflicts or a file is missing, record the conflict/question instead
of guessing. Do not treat archived automatic-reconstruction designs as current
requirements.

## Research requirements

Use current versions of authoritative material where possible. Prioritize NIST
CFTT/CFReDS, SWGDE, OSAC, ASTM/ISO where accessible, and peer-reviewed digital
forensics papers. Distinguish clearly between:

1. forensic-tool validation;
2. controlled scenario/benchmark evaluation;
3. analyst proficiency or human performance;
4. evidential observability in a case study;
5. automated classification/retrieval accuracy.

Do not import precision, recall, accuracy, F1, false-positive rate, or a composite
quality score merely because they are common. For every proposed metric, prove
that this project has the required candidate universe, labels, independence,
unit, denominator, and decision rule. Identify metrics that are standard only in
a narrower task and explain why they do or do not transfer.

At minimum, study and cite:

- NIST CFTT's requirements → assertions → measurement method → dataset → test
  case traceability;
- CFReDS known-data versus realistic scenario datasets and deleted-file test
  design;
- SWGDE requirements for search, recovery/reconstruction, aggregation/timeline,
  operational verification, and dataset representativeness;
- peer-reviewed work measuring forensic extraction/retrieval with gold standards;
- comparable Linux rootkit/digital-forensics evaluations, including Nagy (2025)
  and Stuehn, Hilgert, and Lambertz (2024);
- any strong research on reconstruction completeness/correctness and temporal
  ordering that genuinely matches this project's level of analysis.

## Questions the research must resolve

### A. Study design and ground-truth access

Compare blind, fully ground-truth-informed, and hybrid/two-pass designs for this
single-analyst thesis. Assess internal validity, ecological realism,
reproducibility, confirmation bias, workload, and compatible claims. For the
recommended hybrid protocol, specify exactly:

- what the analyst may know in pass one (technique, OS, broad case question);
- what must remain hidden (exact planted paths, hashes, PIDs, ports, timestamps,
  and other locators, as applicable);
- when ground truth is revealed;
- which checks are allowed in pass two;
- how assisted findings are tagged;
- how all summaries are recomputed without assisted findings;
- how the same analyst can perform both passes without pretending to be blind
  after disclosure.

### B. Measurement unit and denominator

Compare at least these units: ground-truth action, atomic expected target/artifact,
candidate finding, and source-target pair. Define when each is appropriate and
which must never be pooled. Resolve whether the thesis needs one primary unit or
two separately reported views:

- detection/observability of atomic targets per source; and
- reconstruction/corroboration of scenario actions across sources.

Explain how applicability, negative controls, missing evidence, tool failures,
not-run checks, partial observations, duplicate traces, and source-exclusive
targets affect each denominator.

### C. Minimal metric set

Evaluate the existing contract and provisional M1–M4. Recommend the smallest
final set; for each metric give:

- research construct and exact name;
- unit of analysis;
- formula with numerator and denominator;
- admissible statuses and exclusions;
- required ground truth and finding fields;
- whether calculation is automatic or human-adjudicated-then-automatic;
- whether it supports within-run, cross-source, cross-distribution, or
  cross-scenario comparison;
- minimum replication and uncertainty reporting;
- invalid conditions and prohibited claims.

Explicitly decide whether to retain, rename, merge, or delete:

- `O/P/N/TF/--`, `Found/A`, and coverage;
- strict observation `O/A` versus inclusive `Found/A`;
- `U/C/S`, contradiction `X`, and union gain;
- rejected candidates and TTF;
- M1 source-conditioned observability;
- M2 action corroboration;
- M3 verified deleted-content recovery;
- M4 timestamp displacement.

Validity gates such as acquisition integrity and procedure completion may be
defined, but keep them outside the scientific outcome metric set.

### D. Reconstruction and deleted-content recovery

Define “reconstruction” at distinct levels: identity/name, metadata, content,
partial content, event/action, and ordered timeline. Do not count journal
directory-name evidence as recovered file content. Determine a simple,
thesis-sized method for verifying complete and partial recovery (hash, byte
agreement, semantic/openability checks, or another justified rule).

Assess whether the Father case is a reconstruction evaluation, an observability
case, or a documented limitation. If a dedicated recovery treatment is needed,
specify the minimal ground truth and controls for the persisted and
non-forced-flush arms. Discuss fragmentation, partial overwrite, post-deletion
activity, acquisition timing, filesystem/version, and whether SWGDE/CFTT recovery
test cases are requirements for this thesis or merely design guidance.

### E. Ground truth, findings, and notebook contract

Design the minimum information model, preferably by extending existing
`manifest.json.facts`. Separate:

1. prospectively frozen scenario facts/measurement assertions;
2. observations emitted by a source notebook;
3. post-reveal ground-truth matches/adjudications;
4. calculated metric results;
5. analyst interpretation.

Use a limited standard vocabulary. Observation, method execution, applicability,
and ground-truth access mode must be separate dimensions. Define one atomic
finding record usable by disk, memory, timeline, and future network sources,
while allowing source-specific observed fields. Every result must carry a durable
raw-evidence locator and bounded limitation.

Define a reusable notebook contract: fixed inputs, checks, raw outputs, atomic
findings, optional adjudication, metrics, and narrative. Explain which steps can
be automatic and which require a small recorded human decision. Ensure the first
richly explained run and later terse runs remain methodologically equivalent.

## Required output

Produce one concise, decision-ready Markdown report containing:

1. **Executive verdict** — recommended study design and metric family.
2. **Literature/standards matrix** — source, evaluated task, ground-truth model,
   metric/unit, and transferability to this thesis.
3. **Claim-to-measurement table** — each thesis claim mapped to unit, ground
   truth, procedure, metric, and limitation.
4. **Final minimal metrics** — definitions/formulas plus retain/rename/delete
   decisions for every existing/provisional field.
5. **Hybrid protocol** — operational pass-one/pass-two rules and sensitivity
   reporting.
6. **Minimal data contract** — manifest facts, finding/adjudication fields,
   statuses, and metric-result provenance; show compact illustrative records or
   tables, not implementation code.
7. **Notebook contract** — reusable disk/memory/timeline workflow and future
   network extension rule.
8. **Recovery subdesign** — whether it is needed and, if so, the two-arm
   prospective design.
9. **Threats to validity** — construct, internal, external, and conclusion
   validity, including single analyst and limited runs.
10. **Reconciliation/migration plan** — what in `ai/archive/METHODOLOGY.md` is
    retained, amended, or retired, and where the final always-read ICM reference
    should live.
11. **Human decisions remaining** — only consequential choices, each with 2–3
    options, trade-offs, and a recommendation.
12. **Evidence base** — every local file and external source actually read.

For every statement, label it as **[PROJECT FACT]**, **[EXTERNAL EVIDENCE]**,
**[INFERENCE]**, or **[RECOMMENDATION]**. Cite project facts by repository path
and external claims with direct links/DOIs. State search date and version/date of
standards. Do not turn absence of a published universal method into proof that
none exists; describe the search bounds.

The final design should be small enough that an examiner can understand and
defend every field and formula, and stable enough to be read before every future
experiment and investigation.
