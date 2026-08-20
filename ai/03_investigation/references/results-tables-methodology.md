# Investigation results and metrics methodology

Status: active, deliberately simple, and revisable if later investigations show
a concrete problem. This file is the investigation-stage authority for result
tables and descriptive metrics.

## Scope and decisions

The method covers four controlled attack scenarios on Ubuntu 22.04, Ubuntu
24.04, and Debian 13. Each `(scenario, distro)` run is a descriptive case. Rates
may be compared across distributions for the same scenario when the same
reconstruction-item list and notebook procedure are used. Rates from different
scenarios are not pooled into one accuracy score.

Current decisions:

- deleted-content recovery is a research question, but its final treatment
  design remains open;
- cross-distribution comparison is descriptive: one eligible run per
  scenario/distribution, with no claim that the distribution alone caused a
  difference;
- the primary analyst performs the investigation; a second reviewer checks
  partial results, recovery classifications, disputed or unresolved rows, and
  the final arithmetic;
- tables may be completed and calculated by hand in the notebooks; automation
  is optional and comes only after the method works in practice;
- current Father disk and recovery observations are provisional until that
  investigation is complete.

## Research questions

- **RQ1 — Reconstruction coverage.** How much of the predefined attack can a
  technique-led investigation reconstruct from post-mortem evidence before
  consulting exact ground truth, and why are some elements missed or only
  partially reconstructed?
- **RQ2 — Source contribution.** What do disk, memory, and timeline analysis
  contribute individually, and what additional attack elements become
  reconstructable when their results are combined?
- **RQ3 — Triage burden.** How many evidence records remain at each filtering
  stage before manual review?
- **RQ4 — Temporal placement.** For reconstructed elements with a comparable
  ground-truth time, how far is the forensic timestamp from the recorded
  scenario time?

Whether the attack executes successfully is an experimental result and a
precondition for the forensic questions, not a forensic finding.

## Result table 0: scenario execution

Keep one study-wide table with one row per run:

| Run ID | Scenario | Distro | Attack outcome | Bounded behaviour validated | Acquisition | Investigation |
|---|---|---|---|---|---|---|
| `<run_id>` | `<scenario>` | `<distro>` | `PASS/PARTIAL/FAIL/NOT RUN` | `<runner validation>` | `<complete/partial/failed>` | `<not started/in progress/complete>` |

`PASS` means that the runner completed and its explicitly bounded behaviour was
validated. It does not mean that the post-mortem investigation reconstructed
the attack.

If the attack or required acquisition fails, preserve that row as a result and
do not manufacture forensic coverage for unavailable evidence.

## Reconstruction items and evidence states

Before comparing a scenario across distributions, write a short list of its
expected **reconstruction items**. One item is an attack action or important
trace that the investigation is intended to reconstruct, for example preload
persistence, an implanted library, history clearing, a hidden process, a
connection, deleted content, or timestamp manipulation.

Use the same item list for that scenario on every distribution. New items may
be added only before the affected comparisons are calculated; record the list
revision when a justified change is necessary.

Use five evidence states:

| State | Meaning |
|---|---|
| `O` | Observed sufficiently to establish the reconstruction item. |
| `P` | Partially reconstructed; the missing part is stated. |
| `N` | Not observed after the planned check completed successfully. |
| `TF` | The required tool or check failed. |
| `--` | Not applicable to that source/view. |

Do not use one `F` value for absence and failure. A tool failure and a valid
negative result support different conclusions.

The investigation is technique-led before exact ground-truth consultation.
After the first-pass observations are written, exact scenario facts may be used
to validate classifications, explain misses, and calculate temporal error. Do
not describe a later investigation as blind when the analyst already knows the
scenario.

## Result table 1: reconstruction matrix

Each completed investigation produces this main table:

| Category | Reconstruction item | Disk | Memory | Timeline | Combined | Key evidence or reason for miss | Time error |
|---|---|---:|---:|---:|---:|---|---:|
| `<category>` | `<attack action or trace>` | `<state>` | `<state>` | `<state>` | `<state>` | `<locator, result, limitation>` | `<delta/range/-->` |

For the combined state:

- use `O` when at least one applicable view establishes the item;
- use `P` when no view establishes it completely but at least one provides
  partial support;
- use `N` when at least one applicable view completed with `N`, no view has
  `O` or `P`, and any additional `TF` limitation is disclosed;
- use `TF` when no usable result exists because all relevant checks failed;
- use `--` when the item is outside every current source/view.

The evidence cell carries the concise result plus a durable notebook/raw-output
locator. It also records why an item is partial or missed. Recommended simple
miss reasons are: not persisted, overwritten or deleted, acquisition
limitation, tool failure, query limitation, and unresolved.

### Recovery and temporal rows

`library_deletion_recovery` and `timestomp_detection` are investigation
questions, not artifact names. Represent them as ordinary reconstruction rows:

- category `Deleted content`, item `Deleted staged-library content`; report
  `complete`, `partial content`, `metadata/name only`, `not recovered`, `tool
  failure`, or `not attempted` in the evidence cell;
- category `Temporal evidence`, item `Installed-library timestamp
  manipulation`; report the timestamps, interpretation, and comparable time
  difference.

Metadata or a historical filename is not partial content recovery. Complete
content requires an exact hash/size match; partial content requires verified
byte agreement with the known original.

For RQ4, calculate a per-item absolute difference only when the forensic and
scenario timestamps refer to the same event and use compatible time semantics:

`time error = |forensic timestamp - scenario timestamp|`

Otherwise report `--` or an interval and explain the limitation. Do not average
unlike timestamp types into one temporal-accuracy score.

## Candidate findings and false positives

Candidate-generating methods such as `vol3 linux.malware.malfind.Malfind` may
surface benign or unrelated processes. These outputs belong to **RQ3 triage
burden**, not to the RQ1 reconstruction denominator.

Use the term **rejected candidate** when a method surfaces something for analyst
review and the analyst determines that it is benign, unrelated to the controlled
attack, or insufficiently supported. This is usually more accurate than “false
positive” because a triage plugin proposes suspicious regions; it does not by
itself assert that each region is malicious.

Use **false positive** only when a method has an explicit binary claim such as
“attack-related/malicious” and a known negative case proves that claim false. Do
not calculate a false-positive rate without a defined negative universe.

For every candidate-producing check, record:

- tool/check and candidate unit, such as process, memory region, file, or row;
- candidates reviewed;
- candidates retained as attack-related evidence;
- rejected candidates;
- unresolved candidates;
- a short rejection reason and durable locator for meaningful examples.

The accounting identity is:

`reviewed candidates = retained + rejected + unresolved`

Count a candidate once within its declared tool/check unit. Exact
ground-truth-guided path, PID, hash, or timestamp lookups are verification
checks, not candidate generators, and do not create rejected-candidate counts.

A rejected candidate never decreases reconstruction coverage. If a real
reconstruction item is found among candidates, that item affects RQ1 once;
other candidates affect only RQ3 burden.

Example reporting form, with placeholders rather than a project result:
`malfind: <reviewed> = <retained> retained + <rejected> rejected + <unresolved>
unresolved; rejected examples: unattended-upgrades (<reason and locator>)`.

## Result table 2: source contribution and triage

Each completed investigation also produces this summary table:

| Source/view | Reconstructed (`O+P`) | Applicable | Coverage | Found only here | Triage funnel | Rejected/unresolved examples | Main limitation |
|---|---:|---:|---:|---:|---|---|---|
| Disk | `<O count + P count>` | `<A>` | `<(O+P)/A>` | `<count>` | `<raw -> filtered -> reviewed = retained + rejected + unresolved>` | `<count; examples>` | `<limitation>` |
| Memory | `<...>` | `<...>` | `<...>` | `<...>` | `<...>` | `<...>` | `<...>` |
| Timeline | `<...>` | `<...>` | `<...>` | `<...>` | `<...>` | `<...>` | `<...>` |
| Combined | `<...>` | `<...>` | `<...>` | `--` | `--` | `--` | `<cross-view limitation>` |

For source/view `s`:

`coverage(s) = (O_s + P_s) / applicable_s`

`applicable_s` includes `O`, `P`, `N`, and `TF`; `--` is excluded. If the
entire required acquisition is unavailable, do not issue coverage for that
view.

Always show `O` and `P` separately beside the fraction. Do not weight `P` and
do not hide it inside a percentage without the count split.

`Found only here` counts reconstruction items with `O` or `P` in that view and
no `O` or `P` in another applicable view. Also state below the table how many
items were supported by two or more views. Timeline is normally derived from
disk evidence, so describe this as contribution from a different analytical
view rather than independent evidence.

For RQ3, define the funnel consistently in each notebook:

- `raw`: records produced by the initial source export or plugin;
- `filtered`: records remaining after the notebook's fixed broad filters;
- `reviewed`: candidate records actually examined manually;
- `retained`, `rejected`, and `unresolved`: the adjudicated reviewed candidates.

Raw counts from disk, memory, and timeline have different meanings. Compare
them within the same source/procedure across runs; do not add them into a single
case-wide “haystack size.” Manual entry is acceptable when the notebook records
the count and its source.

## Optional category summary

A category-level `reconstructed / expected / coverage` table is optional. Use
it only when a stable category contains enough reconstruction items to be
informative. Do not add a per-run category table when it would consist mainly
of trivial zero-or-one denominators.

## Review and reporting limits

The second reviewer does not repeat the investigation. The reviewer checks:

- every `P` classification;
- deleted-content recovery classifications;
- disputed or unresolved rows and material rejected candidates;
- the arithmetic in the final two tables.

Every result remains descriptive of the named run, scenario, distribution,
source, and notebook procedure. A miss is bounded by the executed checks; a
tool failure is reported separately; scenario validation is never presented as
a forensic observation.

## Practical workflow

1. Draft 6–12 reconstruction items for one scenario without assigning results.
2. Reuse that list across its distributions.
3. Run the source notebooks technique-led and save raw outputs.
4. Fill the reconstruction matrix manually.
5. Consult exact ground truth, validate the rows, and record miss reasons.
6. Fill the source/triage summary and perform the small reviewer check.
7. Automate only repeated counting or arithmetic that has proved useful.

Change a scenario only when its bounded behaviour cannot be validated, a
research question lacks the minimum required ground truth, or an intended
forensic condition such as deleted-content recovery is absent. Do not add
artifacts merely to improve a coverage percentage.
