# Methodology

This document defines the thesis and manual Linux DFIR investigation method for
**Linux Multi-Source DFIR Lab**. Verify mutable implementation details from the
current source and use `TODO.md` for current priorities.

## Thesis boundary

The thesis studies reproducible post-mortem examination of controlled Linux
compromises. Its contribution is the experimental infrastructure, acquisition
and provenance, source-aware manual investigation, cross-source interpretation,
and explicit treatment of tool limitations.

The method asks:

- whether a controlled scenario and evidence acquisition can be reproduced;
- what filesystem, Plaso timeline, and memory sources reveal independently;
- what becomes supportable only through cross-source interpretation; and
- where tools or available evidence produce ambiguity, failure, or valid
  negative observations.

It does not use an automatic detector, matcher, score, or reconstruction engine
to answer those questions.

## Experimental scope

Controlled scenarios execute only in isolated, disposable, authorized VMs.
Ubuntu 22.04 is the current deep-analysis platform. Additional distributions,
security profiles, scenarios, and tool integrations are optional only after the
minimum thesis evidence and writing are secure.

Passwordless sudo in the guest is a documented mechanism for deploying a
controlled treatment that requires root. It is not evidence of an initial
privilege escalation. Record the execution identity and distinguish laboratory
preconditions from scenario actions.

## Evidence and provenance

An accepted run retains a stable identity and enough provenance to reproduce and
review its acquisition and examination:

- repository revision, scenario, distro, timestamps, baseline identity, and
  workflow status;
- append-only command and terminal records;
- disk and memory acquisition commands, hashes, verification, and status;
- raw-tool versions, commands, output paths, hashes, zero results, and failures;
  and
- analyst records that cite exact run-relative evidence locations.

The run-root manifest is the lifecycle index. `dumps/acquisition.json` is the
acquisition authority, and `analysis/raw_extraction_status.json` is the raw-tool
authority. Do not duplicate their full contents into narrative reports.

Accepted disk and memory images and raw exports are immutable. Examination may
create a separate analyst workspace and derived views, each tied back to the
source run and command. The report is another layer: it cites evidence and
derived results but does not replace them.

## Epistemic separation

Keep three claims distinct:

1. **Scenario validation** uses execution records to establish whether the
   intended treatment occurred.
2. **Forensic observation** states what a named source and method exposed.
3. **Analyst interpretation** explains what the observations support, with
   uncertainty and alternatives.

Scenario facts are not forensic discoveries. A planted value may validate a
candidate after technique-led examination, but it must not silently select the
candidate or become reusable detection logic. Label ground-truth-guided checks
and causal inferences explicitly.

## Practical investigation workflow

1. Fix the case boundary: run ID, source revision, evidence paths, hashes,
   acquisition status, raw-tool status, and any known limitations.
2. State the forensic question, relevant source families, selection rationale,
   and stopping condition before broad examination.
3. Examine filesystem, timeline, and memory sources separately using
   technique-level and operating-system structure first.
4. Record the exact command and immutable-run locator for each material result,
   including rejected candidates and bounded negative searches.
5. Use disclosed scenario information only after candidate selection for
   clearly labelled validation or coverage review.
6. Correlate sources without flattening their different semantics, time bases,
   or failure modes.
7. Report observations, interpretations, contradictions, negative results, tool
   failures, limitations, and unresolved questions.

For large artifacts, measure size, aggregate, and filter before reading. Keep
complete raw timelines and exports unchanged; store reduced views separately
with the producing command and source reference. Stop when the stated question
and stopping condition are satisfied rather than searching until a desired fact
appears.

## Source-aware reporting

Use source-scoped language:

- **observed** or **partially observed** when cited evidence supports the claim;
- **not observed** only for the stated source, tool, query, and bounds;
- **tool failed** when examination did not produce a valid result;
- **not applicable** when the source cannot answer the question; and
- **prevented** only for scenario execution blocked by a control, not as an
  evidence status.

A useful report is concise and auditable. It identifies the case and acquisition,
separates scenario validation from findings, presents findings by source, gives
cross-source interpretation, and closes with limitations and conclusions. Every
material conclusion cites a path, row/line, inode/block, timestamp, PID/mapping,
or other durable locator appropriate to the source.

Do not turn manual coverage descriptions, candidate counts, or timing notes into
automatic pass conditions or a general scoring architecture. If a named study
uses such descriptors, define its inventory and procedure prospectively and
keep the result bound to that study.

## Fixed result-reporting contract

Each accepted `(scenario, distribution, profile)` case has one
`runme_case_summary.md` with exactly two summary tables. Source notebooks may
contain their own examination-output tables, but they do not duplicate the
case metrics.

The first table is the **artifact evidence matrix**, with one row per atomic
target fixed before the measured investigation:

```text
ID | Phase/category | Expected artifact or fact | Filesystem | Timeline |
Memory | Contribution | Principal method(s) | Accepted locator or limitation
```

The second table is the **source metric summary**:

```text
Source | O | P | N | TF | Found / A | Coverage | U / C / S |
X | Union gain | Rejected candidates | TTF | Principal methods
```

`COMPARATIVE_RESULTS.md` is the only cross-case metric table. It contains
exactly one row per accepted authoritative run, not one row per source family:

```text
Run | Case | Layer/technique | Filesystem | Timeline | Memory | Union |
Cross-source | Rejected candidates | TTF | Principal methods
```

Each source cell uses the compact form `O/P/N/TF; Found/A (Coverage)`. The
cross-source cell reports `U/C/S`, `X`, and union gain; rejected candidates and
TTF remain source-labelled inside their cells. Draft and superseded runs are
excluded.

The status and metric rules are fixed as follows:

- `O` is observed, `P` is partially observed, `N` is not observed within the
  stated source and bounds, `TF` is tool failed, and `--` is not applicable.
- Applicability is fixed from the declared target and source scope. A tool
  failure remains applicable and therefore remains in the denominator.
- `A = O + P + N + TF`, `Found = O + P`, and
  `Coverage = 100 * Found / A`. `P` remains visible and is not assigned an
  arbitrary fractional weight. Coverage rows with different applicability
  sets are descriptive and must not be used to rank the source families.
- `TF` is the target status when an applicable method produced no valid result
  because it failed. If another accepted method still supports `O`, `P`, or
  `N`, retain that target status and disclose the secondary tool failure in the
  matrix limitation rather than hiding it.
- A union target is `O` if any applicable source observed it, otherwise `P` if
  any source partially observed it, otherwise `TF` if an applicable method
  failed, and otherwise `N`. Each target is counted once in the union.
- `U` (unique) means a target applicable to at least two source families was
  found by exactly one; `C` (corroborated) means it was found by at least two
  independent source families; and `S` (specialized) means it was found by its
  only applicable source family. These three classes partition the found union
  targets. `X` separately counts targets with materially contradictory accepted
  observations and may overlap those classes.
- `Union gain = union Found - max(single-source Found)`. It is an absolute count
  of additional targets exposed by combining sources, not a percentage-point
  comparison between unlike denominators.
- `Rejected candidates` counts candidates selected as suspicious and then
  excluded from the case interpretation. It is `0` only when a declared
  candidate-generating method produced no rejected candidate, and `N/A` when
  no such method was used. It is not a false-positive count and is not used to
  calculate precision.
- `TTF` is the prospective wall-clock time from the recorded start of a
  source-specific examination to its first accepted forensic locator. It is
  `not measured` if either timestamp was not recorded prospectively or if the
  session was interrupted. It is descriptive analyst-workflow context, not
  evidence that multi-source analysis reduced total investigation time.
- `Principal methods` names the actual forensic tool and relevant command or
  plugin. A case matrix also cites a durable evidence locator and an explicit
  limitation for every partial, negative, or failed result.

No qualitative quality-of-result score is used. The observed/partial
distinction, source contribution, locator, and limitation carry that
information without an uncalibrated `High`/`Medium`/`Low` judgement. Precision,
recall, F1, and claims of reduced investigation time require a separate,
prospectively controlled evaluation and are outside these descriptive case
metrics.

This format supports the thesis questions at three different levels: the
artifact matrix exposes which userland or kernel artifacts each source and
method recovered; source coverage, tool failures, and named plugins describe
bounded tool capability; and corroboration, specialization, contradiction, and
union gain describe the value added by combining sources. It does not evaluate
a tool that was not run.

## Standards alignment

The workflow follows the useful separation in
[NIST SP 800-86](https://doi.org/10.6028/NIST.SP.800-86): acquisition,
examination, analysis, and reporting are different activities. The
[SWGDE report-writing requirements](https://www.swgde.org/documents/published-complete-listing/18-q-002-swgde-requirements-for-report-writing-in-digital-and-multimedia-forensics/)
likewise require clear results, supporting data, methods, and limitations while
leaving the report format to the examiner. The detailed-matrix plus compact
summary structure follows the reporting pattern used in recent Linux-rootkit
evaluations, including the target/technique/plugin matrix in
[Nagy (2025)](https://doi.org/10.1016/j.fsidi.2025.301928) and the
tool-to-rootkit capability tables in
[Stuehn, Hilgert, and Lambertz (2024)](https://doi.org/10.1145/3688808).

Evidence immutability, hashes, provenance, and separate derived outputs also
support ISO/IEC 27037-style handling. These alignments guide the method; they do
not substitute for documented commands and case-specific evidence.

## Historical boundary

Earlier automatic `ToolFinding`, `DetectionClaim`, canonical matching,
precision/recall, and reconstruction-metrics work is preserved only by the
immutable `automatic-reconstruction-v3-final` tag. It may be discussed as
history, but it is not the current thesis architecture or a future-work
requirement.
