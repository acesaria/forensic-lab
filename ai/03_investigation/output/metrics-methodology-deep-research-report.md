# Scientific evaluation method for multi-source Linux DFIR investigations

> **Status:** background research only. The active, simpler reporting method is
> `ai/03_investigation/references/results-tables-methodology.md`. The Father disk
> investigation and deleted-content recovery work are incomplete, so this
> report's Father-specific observations and recovery classification are not
> definitive results.

[PROJECT FACT] **Research cut-off:** 2026-08-20.

[PROJECT FACT] **Project reference:** `father-u22-20260819-03`.

[RECOMMENDATION] **Decision status:** methodology recommendation; no experiment results are created or reclassified here.

## 1. Executive verdict

[RECOMMENDATION] **VERDICT: REVISE, THEN ADOPT.** Use a prospectively frozen hybrid/two-pass investigation with two core outcome views: **M1 source-conditioned target observability** and **M2 independent-origin action corroboration**. Retain **M3 verified deleted-content recovery** only for a dedicated prospective recovery question, and remove **M4 timestamp displacement** from the outcome metric family while retaining it as a per-target descriptive measurement.

[RECOMMENDATION] Keep acquisition integrity and investigation completion as validity gates, not outcome scores. If a required source fails its acquisition gate, report its result as unavailable; do not turn unavailable evidence into `N`, zero coverage, or a smaller denominator.

[RECOMMENDATION] Preserve `O/P/N/TF/--` for human-readable tables, but calculate from separate applicability, execution, observation, and adjudication fields. Report both strict `O/A` and inclusive `(O+P)/A` observability as counts and fractions; never fractionally weight `P`.

[RECOMMENDATION] Treat the current Father case as an observability and action-corroboration case with a documented deleted-content limitation, not as a content-recovery experiment. Its journal evidence supports historical name/metadata mapping, while the bytes of the deleted `/tmp/rk.so` were not recovered and are not unique relative to the allocated implant library (`ai/03_investigation/output/disk-investigation-refactor-plan.md`; `shared/investigations/father-u22-20260819-03/derived/disk/findings.json`).

[PROJECT FACT] The repository's intended boundary is deterministic execution, manifest and append-only command log, acquisition, raw source exports, human-led source investigation, bounded arithmetic, and manual interpretation; the current runtime no longer contains the former automatic detector/matcher/scoring path (`ai/ROUTING.md`; `ai/03_investigation/CONTEXT.md`; `ai/archive/METHODOLOGY.md`).

[PROJECT FACT] `father-u22-20260819-03` is the selected reference run, but its manifest records `working_tree: modified`; its disk image has a completed SHA-256 verification, while its memory sidecar records `verified: false` (`shared/experiments/father-u22-20260819-03/manifest.json`; `shared/experiments/father-u22-20260819-03/dumps/acquisition.json`).

[PROJECT FACT] Only disk findings and metrics currently exist for the selected reference run; the inspected memory and timeline examples belong to `father-u22-20260818-02` and use different record shapes (`shared/investigations/father-u22-20260819-03/derived/disk/`; `shared/investigations/father-u22-20260818-02/derived/memory/`; `shared/investigations/father-u22-20260818-02/derived/timeline/`).

[INFERENCE] The selected run can anchor notebook refactoring and descriptive disk claims, but it cannot yet support an authoritative three-source score, an immutable-run claim, or independent-origin corroboration involving memory.

[RECOMMENDATION] Three human decisions remain before promotion: whether deleted-content recovery is a thesis research question, whether cross-condition claims merit repeated acquisitions, and whether a second reviewer will adjudicate all `P`, `X`, and unresolved matches. Section 11 gives bounded options.

## 2. Literature and standards matrix

| Source | Evaluated task | Ground-truth model and unit | Transferability to this thesis |
|---|---|---|---|
| [EXTERNAL EVIDENCE] [NIST, *Ten Years of Computer Forensic Tool Testing*](https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=909329) | Forensic-tool validation | Requirements are decomposed into assertions, measurement methods, datasets, and test cases; the unit is a tool assertion/test case. | [INFERENCE] Transfer the traceability discipline from assertion to test, but do not treat a human-led case investigation as a CFTT tool conformance test. |
| [EXTERNAL EVIDENCE] [NIST CFReDS](https://cfreds-archive.nist.gov/) | Tool tests, equipment checks, proficiency exercises, training, and realistic scenarios | Known-data images expose complete contents and locations for explicit tests; realistic scenario images support broader examination tasks. | [INFERENCE] Use known target identities for post-reveal adjudication and use the Father case for scenario-level investigation; do not assume that one dataset serves tool validation and ecological case study equally well. |
| [EXTERNAL EVIDENCE] [CFReDS deleted-file test images](https://cfreds-archive.nist.gov/dfr-test-images.html) | Deleted-file metadata recovery | The dataset records file properties and storage layout, deletes files under controlled steps, images a frozen state, and includes contiguous, fragmented, and overwritten cases. | [INFERENCE] Use its prospective characterization and state-freezing principles for a recovery subdesign; its full tool-test matrix is design guidance, not a mandatory thesis requirement unless tool-recovery validation is claimed. |
| [EXTERNAL EVIDENCE] [SWGDE, *Minimum Requirements for Testing Tools Used in Digital and Multimedia Forensics*, v2.1, 2024](https://www.swgde.org/wp-content/uploads/2024/04/2024-03-07-SWGDE-Minimum-Requirements-for-Testing-Tools-Used-in-Digital-and-Multimedia-Forensics-18-Q-001-2.1.pdf) | Search, recovery/reconstruction, aggregation/timeline, and operational verification of tools | Known datasets or comparison/manual checks are selected for the tool function; recovery datasets cover complete, fragmented, and partially overwritten content. | [INFERENCE] Use the known-data and operational-verification rules for bounded notebook checks, but do not call the thesis workflow a formal tool-validation programme. |
| [EXTERNAL EVIDENCE] [OSAC, *Guidelines for Dataset Development*, v2, 2022](https://www.nist.gov/document/guidelines-dataset-developmentoct2022) | Forensic dataset construction | A documented plan records actions, environment, versions, time zone, acquisition, volatile-data timing, baselines, and limitations. | [INFERENCE] Directly transferable to prospective scenario facts and recovery-arm controls. |
| [EXTERNAL EVIDENCE] [SWGDE, *Proficiency Test Guidelines*, v1.0, 2015](https://www.swgde.org/documents/published-complete-listing/swgde-proficiency-test-guidelines/) | Examiner proficiency | Open or blind representative exercises have independently approved expected results and evaluation criteria. | [INFERENCE] The present single-analyst case study is not a proficiency test; pass-one shielding controls contextual exposure but does not measure analyst competence. |
| [EXTERNAL EVIDENCE] [ISO/IEC 27037:2012](https://www.iso.org/standard/44381.html) | Identification, collection, acquisition, and preservation | Process requirements concern evidence handling and continuity rather than a detection score. | [INFERENCE] Supports acquisition gates and provenance, not an outcome numerator. The ISO page states that this edition is published but due for revision as of the search date. |
| [EXTERNAL EVIDENCE] [ISO/IEC 27041:2015](https://www.iso.org/standard/44405.html) | Assurance that investigative methods are fit for purpose | Method requirements address validation and suitability. | [INFERENCE] Supports prospective predicates and bounded methods, not a universal coverage formula. The ISO page lists the standard as published and under systematic review in 2026. |
| [EXTERNAL EVIDENCE] [ISO/IEC 27042:2015](https://www.iso.org/standard/44406.html) | Analysis and interpretation | Continuity, validity, reproducibility, repeatability, and sufficient recording for independent scrutiny are central. | [INFERENCE] Supports durable raw locators, recorded adjudication, and reproducible arithmetic. The ISO page lists the standard as published and under systematic review in 2026. |
| [EXTERNAL EVIDENCE] [ASTM E3016-18, *Standard Guide for Establishing Confidence in Digital and Multimedia Evidence Forensic Results by Error Mitigation Analysis*](https://store.astm.org/e3016-18.html) | Confidence through error mitigation | The standard focuses on recognizing and mitigating potential errors in changing technological environments. | [INFERENCE] Supports explicit validity gates and limitations rather than an unsupported universal error rate. |
| [EXTERNAL EVIDENCE] [SWGDE, *Requirements for Report Writing in Digital and Multimedia Forensics*, v1.0, 2018](https://www.swgde.org/documents/published-complete-listing/18-q-002-swgde-requirements-for-report-writing-in-digital-and-multimedia-forensics/) | Forensic reporting | Reports disclose methods, results, supporting material, opinions, and limitations without prescribing one fixed format. | [INFERENCE] Supports a stable finding/interpretation separation and bounded negative statements. |
| [EXTERNAL EVIDENCE] [NIST SP 800-86](https://doi.org/10.6028/NIST.SP.800-86) | Incident-response forensic process | Collection, examination, analysis, and reporting are separate process stages. | [INFERENCE] Supports the repository's epistemic separation; it does not prescribe M1–M4. |
| [EXTERNAL EVIDENCE] [James, Lopez-Fernandez, and Gladyshev, 2015](https://eudl.eu/doi/10.1007/978-3-319-14289-0_11) | Automated evidence extraction and categorization | Investigator-derived gold standards allow precision and recall over a defined retrieval universe. | [INFERENCE] Precision/recall transfers only to a closed candidate-retrieval task with complete labels; the current human-led open candidate process lacks that universe. |
| [EXTERNAL EVIDENCE] [Stühn, Hilgert, and Lambertz, 2024](https://doi.org/10.1145/3688808) | Automated Linux rootkit detection under multiple knowledge/configuration conditions | Known rootkit samples, tools, conditions, detections, non-runs, and false positives support detection-rate tables. | [INFERENCE] Knowledge-condition sensitivity is analogous to pass-one/pass-two reporting, but its detector/sample unit does not transfer as a whole-investigation accuracy metric. |
| [EXTERNAL EVIDENCE] [Nagy, 2025](https://doi.org/10.1016/j.fsidi.2025.301928) | Hidden Linux kernel-module detection in memory | Known infected dumps across kernel/rootkit sets support per-plugin detection counts and capability comparison. | [INFERENCE] The study supports prospective known-sample evaluation of an automated plugin, not target coverage for one human-led multi-source scenario. |
| [EXTERNAL EVIDENCE] [Sunde and Dror, 2019](https://doi.org/10.1016/j.diin.2019.03.011) and [Sunde and Dror, 2021](https://doi.org/10.1016/j.fsidi.2021.301175) | Human factors and examiner reliability in digital forensics | Controlled contextual-information conditions and examiner comparisons reveal risks of contextual bias and between-examiner variability. | [INFERENCE] Supports staged ground-truth disclosure, immutable pass-one records, and cautious single-analyst claims; it does not turn a two-pass self-comparison into an independent-examiner study. |
| [EXTERNAL EVIDENCE] [Sunde, 2022](https://doi.org/10.1016/j.fsidi.2021.301317) and [Dror et al., 2022, LSU-E](https://doi.org/10.1016/j.fsisyn.2022.100216) | Cognitive practice and linear sequential unmasking | Context should be managed by relevance, objectivity, and suggestiveness, with exposure recorded and sequenced. | [INFERENCE] Supports revealing exact scenario locators only after pass-one outputs are frozen. |
| [EXTERNAL EVIDENCE] [Dreier et al., 2024](https://doi.org/10.1016/j.fsidi.2024.301755) | Temporal reconstruction with heterogeneous forensic events | A partial-order model represents distinct time domains, implicit ordering, and inconsistencies. | [INFERENCE] Supports relationship/order assertions for timeline reconstruction and cautions against reducing temporal quality to an average timestamp displacement. |

[INFERENCE] The literature supports traceable, task-specific measurement, prospective known data, controlled context, and explicit limitations; it does not supply one universally accepted metric for a human-led multi-source Linux DFIR case study.

## 3. Claim-to-measurement table

| Thesis claim | Unit | Required ground truth | Procedure | Result | Principal limitation |
|---|---|---|---|---|---|
| [RECOMMENDATION] An eligible target was observable in a source view. | Atomic target × source view | Prospectively frozen target, applicability, and observation predicate | Execute the fixed source notebook, adjudicate the target after reveal, calculate by pass scope | M1 strict and inclusive counts/fractions | [INFERENCE] Measures designed-case observability, not universal detector sensitivity. |
| [RECOMMENDATION] An attack action was supported across sources. | Ground-truth action | Frozen action-to-target mapping and applicable evidence origins | Aggregate accepted target observations by action and independent origin | M2 action support table and independent-origin corroboration fraction | [INFERENCE] Same-origin parser agreement is reproducibility support, not independent corroboration. |
| [RECOMMENDATION] Combining source views contributed non-redundant evidence. | Target contribution plus action support | Frozen view/origin applicability | Report named `U/C/S` targets and M2 support vectors | Descriptive contribution partition; no union-gain score | [INFERENCE] Unique artifacts can reflect source specialization rather than superior performance. |
| [RECOMMENDATION] Deleted content was recovered. | Prospectively created deleted object | Pre-deletion bytes, SHA-256, size, identity tag, layout/context, and acquisition state | Run the dedicated recovery procedure and compare returned bytes with the original | M3 complete/partial per-target result and bounded family fractions | [INFERENCE] File name or journal metadata alone cannot support this claim. |
| [RECOMMENDATION] Timestamp manipulation was observed. | One timestamp assertion on one object | Expected temporal relation and trustworthy reference timestamp | Normalize to UTC, calculate the stated delta, and test the relation | Descriptive `delta_mtime` and relation status | [INFERENCE] One timestomp delta is not reconstruction accuracy and should not be averaged across heterogeneous timestamps. |
| [RECOMMENDATION] An event sequence was reconstructed. | Prospectively defined action relation | Required actions and expected partial-order relations | Link accepted findings, retain uncertainty/contradiction, compare supported relations | Ordered-relation table, not M4 | [INFERENCE] Filesystem times, logs, memory, and acquisition times may belong to different clocks and persistence mechanisms. |
| [RECOMMENDATION] The notebook is portable across distributions. | Complete run × distribution | Same plan, assertions, notebook revision, and equivalent acquisitions | Execute unchanged checks and contract; report deviations | Side-by-side M1/M2 rows and procedure-completion gate | [INFERENCE] One run per distribution is descriptive; observed differences cannot be attributed solely to the distribution. |
| [RECOMMENDATION] The workflow is reproducible. | Run package and method execution | Immutable revision, manifest, command log, hashes, tool versions, raw locators | Independent rerun or re-analysis using the recorded procedure | Gate evidence and agreement report | [INFERENCE] Reproducibility is a methodological property, not a weighted component of an outcome score. |

## 4. Final minimal metrics and status decisions

### 4.1 Measurement units and denominator rules

| Unit | Appropriate use | Pooling rule |
|---|---|---|
| [RECOMMENDATION] Ground-truth action | M2 action reconstruction/corroboration | Never pool distinct actions merely because they share an artifact or technique. |
| [RECOMMENDATION] Atomic expected target | Defines the smallest prospectively testable state, object, event, or relation | Split compound expectations when one component can be observed without the others. |
| [RECOMMENDATION] Candidate finding | Tracks analyst search and rejected/unresolved leads | Never use as a positive-target denominator or call rejections false positives without a closed candidate universe. |
| [RECOMMENDATION] Atomic target × source view | M1 per-view observability | Calculate per view; do not pool source-exclusive and multi-view targets into an undifferentiated cross-source score. |

[RECOMMENDATION] Use two primary units rather than force one: target-view pairs for M1 and actions for M2. Their denominators answer different research questions and must remain separately reported.

[RECOMMENDATION] Fix applicability before investigation. `--` is excluded only when the measurement plan says the view cannot, in principle, observe the target under the defined acquisition and method; an analyst's failure to find evidence is not non-applicability.

[RECOMMENDATION] Keep a required check that executes unsuccessfully as `TF` inside the M1 evaluable denominator. Keep `not_run` separate: if a required check is not run, G2 fails and M1 for that view is not issued rather than silently shrinking the denominator.

[RECOMMENDATION] If the source acquisition is absent or fails G1, report the source result as **not reportable**. Do not encode it as `N`, `TF`, or zero because no valid observation opportunity existed.

[RECOMMENDATION] Negative controls are assertion results outside the positive-target M1 denominator. Report whether each control stayed absent, was observed, or was unevaluable; do not call that result a false-positive rate without a complete negative universe.

[RECOMMENDATION] Collapse duplicate traces of the same target in the same view to one adjudicated target-view status while retaining every supporting raw locator. Duplicates strengthen support but do not increase the numerator.

### 4.2 Gates outside the outcome metric set

| Gate | Pass condition | Failure consequence |
|---|---|---|
| [RECOMMENDATION] G1 evidence eligibility | Required acquisition exists; integrity/provenance checks defined by the source pass; run and evidence identities are consistent | Source outcomes are not reported; evidence may still be discussed as a limitation. |
| [RECOMMENDATION] G2 investigation completeness | Every required plan check is `completed` or explicitly `failed`; pass-one freeze, reveal, adjudication, and metric steps are present | Outcomes are provisional/not reportable until completed; `not_run` is not removed from a denominator. |

[PROJECT FACT] For `father-u22-20260819-03`, disk verification completed successfully, but memory has `verified: false`; the manifest also records a modified working tree (`shared/experiments/father-u22-20260819-03/dumps/acquisition.json`; `shared/experiments/father-u22-20260819-03/manifest.json`).

[INFERENCE] Under the proposed rules, the disk source can proceed to G2 assessment, memory does not pass the proposed integrity gate, and a three-source result cannot be issued from the current reference package.

### 4.3 M1 — source-conditioned target observability

[RECOMMENDATION] **Construct:** whether prospectively specified target states are supported in a valid acquired source view under a fixed investigation procedure.

[RECOMMENDATION] **Unit:** one eligible atomic target × one source view.

[RECOMMENDATION] For view `s`, define `A_s = O_s + P_s + N_s + TF_s`, then report:

- [RECOMMENDATION] **Strict observability:** `M1_strict(s) = O_s / A_s`.
- [RECOMMENDATION] **Inclusive observability:** `M1_inclusive(s) = (O_s + P_s) / A_s`.
- [RECOMMENDATION] Always report raw counts as `O/P/N/TF/A` beside both fractions; when `A_s = 0`, report `N/A`, not zero.

[RECOMMENDATION] `O` requires the complete predeclared predicate, `P` requires a material proper subset with the missing component recorded, `N` is a bounded non-observation after a completed method, `TF` is method failure, and `--` is prospectively fixed non-applicability.

[RECOMMENDATION] Required fields are plan/target ID, view and origin IDs, applicability, execution state, observation status, predicate version, raw locator, method/tool provenance, pass scope, adjudication result, and limitation.

[RECOMMENDATION] Calculation is human-adjudicated-then-automatic: a person resolves semantic target matches and `P`; deterministic arithmetic follows the frozen registry.

[RECOMMENDATION] M1 supports within-run and per-view comparison. Cross-distribution or cross-scenario rows are admissible only when the same assertion registry, predicates, view boundaries, and procedure version apply; otherwise present separate case descriptions.

[RECOMMENDATION] One valid run supports a descriptive fraction only. For any condition-level repeatability claim, acquire at least three independent runs per condition and report all fractions plus median and range; do not add confidence intervals based on target rows because targets within one scripted scenario are not independent trials.

[RECOMMENDATION] Prohibited claims include tool sensitivity, universal detection rate, analyst accuracy, and distribution causality.

### 4.4 M2 — independent-origin action corroboration

[RECOMMENDATION] **Construct:** whether a prospectively defined scenario action is supported by accepted observations from distinct acquired evidence origins.

[RECOMMENDATION] **Unit:** one ground-truth action.

[RECOMMENDATION] Distinguish a **source view** such as disk filesystem, disk-derived timeline, memory, or network from an **evidence origin** such as the disk image, memory image, or packet capture.

[RECOMMENDATION] For action `a`, record its support vector across views and origins. Let `E_2` be actions prospectively applicable to at least two independent origins and `C_2` be members of `E_2` with accepted `O` or `P` support from at least two origins; report `M2_origin = C_2 / E_2`, the counts, and the named action IDs.

[RECOMMENDATION] If `E_2 = 0`, report `N/A`. Actions applicable to only one origin are **specialized actions** and stay outside this fraction while remaining visible in the action table.

[RECOMMENDATION] Disk filesystem and Plaso timeline observations derived from the same disk image can provide cross-view/parser agreement, but they count as one origin for `M2_origin`.

[RECOMMENDATION] Required fields are action ID, target-to-action links, applicable view/origin sets, accepted observation statuses, evidence origins, pass scope, adjudication, and limitations.

[RECOMMENDATION] M2 is human-adjudicated-then-automatic. It supports within-run action reconstruction and cross-run comparison only under a homologous action registry and equivalent valid origins.

[RECOMMENDATION] One valid run supports descriptive corroboration only; use the same minimum three independent runs per condition before making a repeatability or condition-effect claim, with all values, median, and range reported.

[RECOMMENDATION] Prohibited claims include statistical independence of sources, causal proof of an action from count alone, and corroboration when two parsers consume the same origin without that dependence being disclosed.

### 4.5 M3 — verified deleted-content recovery

[RECOMMENDATION] **Decision:** retain conditionally, outside the core Father metric set, and activate only for the prospective subdesign in Section 8.

[RECOMMENDATION] **Unit:** one uniquely identified deleted object for which the recovery procedure was completed on eligible evidence.

[RECOMMENDATION] Let `E_R` be eligible recovery targets, `C_R` complete content recoveries, and `P_R` verified partial recoveries; if a family result is useful, report `M3_complete = C_R/E_R` and `M3_any = (C_R+P_R)/E_R` with named targets and raw counts.

[RECOMMENDATION] Complete recovery requires exact size and SHA-256 agreement with the frozen original, plus successful open/parse when that operation is meaningful for the file type.

[RECOMMENDATION] Partial recovery requires target-specific byte agreement against the frozen original. Report matched unique original bytes divided by original size, offset mapping when available, gaps, extra bytes, and contamination; a filename, inode reference, hashless carved object, or journal record alone is not partial content.

[RECOMMENDATION] A failed recovery tool remains `TF`; a completed recovery method with no bytes is `N`; a target that was not uniquely frozen or whose method was not completed is ineligible/not reportable rather than a scored zero.

[RECOMMENDATION] M3 is human-adjudicated-then-automatic and supports within-arm descriptive results. Condition comparison requires repeated independent acquisitions under fixed controls; one object per arm is a pilot, not an estimate of recovery probability.

### 4.6 M4 — timestamp displacement

[RECOMMENDATION] **Decision:** delete M4 as a scientific outcome metric and retain its components as target-level descriptive measurements.

[RECOMMENDATION] For a target with a justified reference, record `delta_mtime = UTC(observed_mtime) - UTC(reference_time)` and the prospectively expected ordering relation. Preserve clock source, time zone conversion, precision, acquisition time, and any ambiguity.

[RECOMMENDATION] Do not average heterogeneous timestamp deltas, interpret a large delta as reconstruction quality, or compare values whose reference clocks/semantics differ.

### 4.7 Decisions on the existing vocabulary

| Existing item | Decision | Final use |
|---|---|---|
| [RECOMMENDATION] `O/P/N/TF/--` | Retain for display; normalize underlying dimensions | `O`, `P`, `N`, and `TF` form `A`; `--` is predeclared non-applicability. |
| [RECOMMENDATION] `Found/A` and “coverage” | Rename | Call `(O+P)/A` **inclusive observability**; always pair it with strict `O/A`. |
| [RECOMMENDATION] `O/A` | Retain | **Strict observability**; no fractional `P`. |
| [RECOMMENDATION] `U/C/S` | Retain as a descriptive target-contribution partition | `U`: one of at least two applicable views; `C`: at least two views, labelled same-origin or independent-origin; `S`: only one applicable view. |
| [RECOMMENDATION] Contradiction `X` | Retain as a flag/count, not a score | List incompatible claims, evidence, adjudication state, and resolution; do not place `X` in M1's denominator unless the underlying target status is separately set. |
| [RECOMMENDATION] Union gain | Delete from the final metric family | Replace with named `U/C/S` targets and the M2 action support table; source-exclusive targets and unequal denominators make a scalar gain easy to misread. |
| [RECOMMENDATION] Rejected candidates | Retain descriptively | Record reason and pass; do not call them false positives or calculate precision. |
| [RECOMMENDATION] Time to first finding (`TTF`) | Remove from core outcomes | Optional prospective workflow metadata only; report definition, start/stop events, interruptions, and pass. Never present it as effectiveness. |
| [RECOMMENDATION] M1 | Retain with the precise definition above | Core target-view outcome. |
| [RECOMMENDATION] M2 | Retain and rename to emphasize independent origins | Core action-level outcome. |
| [RECOMMENDATION] M3 | Retain conditionally | Dedicated recovery subdesign only. |
| [RECOMMENDATION] M4 | Delete as an outcome | Per-target timestamp attribute/order assertion only. |

[RECOMMENDATION] Do not introduce precision, recall, accuracy, F1, false-positive rate, or a composite quality score unless a future closed task defines a complete candidate universe, exhaustively labelled positives/negatives, stable decision rules, and an appropriate independent sampling unit.

## 5. Hybrid/two-pass protocol

### 5.1 Design comparison

| Design | Internal validity and bias | Ecological realism and reproducibility | Workload and compatible claim |
|---|---|---|---|
| [INFERENCE] Blind/fully ground-truth withheld | Best protects the initial search from exact-locator confirmation, but a miss can remain unexplained and one analyst cannot repeat the blind condition after disclosure. | Closest of the three to an unknown case, but exact completeness is difficult to adjudicate without a later reveal. | [INFERENCE] Lowest guided-check workload but high risk of unresolved misses; supports only bounded technique-led observability, not proof that the analyst was context-free. |
| [INFERENCE] Fully ground-truth informed | Makes target matching, denominator completion, and reproducible exact checks easiest, but can reduce investigation to verification and inflate apparent discovery. | Least case-realistic for a human investigation because planted locators direct attention. | [INFERENCE] Efficient for tool/assertion verification; supports whether known evidence can be verified, not whether it was independently found. |
| [RECOMMENDATION] Hybrid/two-pass | Freezes an initial technique-led record, then permits complete adjudication; residual bias and prior exposure remain explicit. | Preserves a bounded discovery view while producing auditable denominators and missed-target explanations. | [RECOMMENDATION] Adds one freeze/reveal/adjudication cycle; supports separate pass-one observability and all-pass verification, with their difference reported as ground-truth-assistance sensitivity. |

### 5.2 Pass one: technique-led examination

[RECOMMENDATION] Before opening evidence, freeze the measurement plan, target/action registry, required checks, applicability, observation predicates, negative controls, and stopping rule; exact ground-truth values should be runner-recorded or prepared by a non-examining reviewer and stored in a sealed/restricted section unavailable to the analyst during pass one.

[RECOMMENDATION] If the analyst authored or previously inspected the exact registry, scenario code, or prior Father findings, record `prior_scenario_exposure: true` and describe pass one only as procedurally withheld/technique-led. No file separation can make already known facts blind again.

[RECOMMENDATION] The analyst may know the operating system/distribution and kernel, source type, broad case question, public technique family, and ordinary forensic knowledge. For Father, this includes knowing that the case concerns an `LD_PRELOAD`-style userland rootkit and therefore checking standard mechanisms such as `/etc/ld.so.preload`.

[RECOMMENDATION] Hide scenario-specific filenames and temporary paths, hashes, inodes, PIDs, ports, exact timestamps, dwell intervals, command order, expected counts, and any locator that would directly select a planted object.

[RECOMMENDATION] Execute the fixed notebook checks, preserve raw outputs/hashes, register all candidates including rejected or unresolved leads, record bounded negatives and tool failures, and complete the pass-one narrative without consulting the manifest's exact facts or command log.

[RECOMMENDATION] Freeze pass one by recording completion time, notebook/procedure revision, candidate/finding record hashes, metric inputs, and the stopping-rule result. Never overwrite this record after disclosure.

### 5.3 Reveal and pass two: ground-truth-guided verification

[RECOMMENDATION] Reveal ground truth only after the pass-one freeze. The analyst may then inspect the complete manifest, command log, frozen assertion registry, and exact paths, hashes, PIDs, ports, timestamps, or other locators.

[RECOMMENDATION] Pass two may join candidates to targets, run exact path/hash/PID/port/time-window checks, resolve identity ambiguity, test missed frozen predicates, and document why a pass-one candidate matched, failed, or remained unresolved.

[RECOMMENDATION] Every new or upgraded observation attributable to the reveal must carry `ground_truth_access: pass2_guided`. Link it to a pass-one candidate when one existed; otherwise mark it as newly guided.

[RECOMMENDATION] The same analyst may perform both passes, but the report must call pass one **ground-truth withheld** or **technique-led**, not claim enduring blindness. After the analyst has seen a scenario once, later distribution runs must record `prior_scenario_exposure: true` and cannot be described as independent blind replications.

### 5.4 Sensitivity reporting

[RECOMMENDATION] Produce two deterministic result scopes from the same frozen applicability registry:

- [RECOMMENDATION] `pass1_only`: observations established without exact ground-truth access.
- [RECOMMENDATION] `all_passes`: accepted observations after guided verification.

[RECOMMENDATION] Recalculate M1, M2, `U/C/S`, contradiction lists, and recovery results for both scopes by excluding pass-two-guided observations from `pass1_only`; do not change target applicability or remove missed targets after reveal.

[RECOMMENDATION] Report the named targets/actions whose status changed between scopes. The difference is sensitivity to ground-truth assistance, not an estimate of analyst bias or population-level performance.

## 6. Minimal data contract

### 6.1 Separation of records

| Record | Frozen or created when | Minimum content |
|---|---|---|
| [RECOMMENDATION] Scenario measurement facts | Before investigation and preferably before execution | Schema/plan version, run/scenario revision, actions, atomic targets, predicates, applicability by view/origin, controls, acquisition conditions, and sealed exact values. |
| [RECOMMENDATION] Observation/finding | During either pass | Finding/candidate IDs, source view and origin, method execution, observation status, source-specific observed fields, raw locator/hash, pass/access mode, and limitation. |
| [RECOMMENDATION] Adjudication | After reveal | Finding-to-target match state, rule/basis, reviewer, time, assisted status, and contradiction resolution. |
| [RECOMMENDATION] Metric result | After adjudication | Metric/version, run/plan, pass scope, numerator/denominator, included IDs, excluded IDs/reasons, value, generator revision, and time. |
| [RECOMMENDATION] Interpretation | Last | Prose claim linked to action, finding, and metric IDs, with scope and alternative explanations; never used as arithmetic input. |

[PROJECT FACT] The current manifest field is `scenario_facts`, not `facts`, and presently contains only the backdoor connection fact for Father (`shared/experiments/father-u22-20260819-03/manifest.json`; `scenarios/userland_father_ldpreload/runner.py`).

[RECOMMENDATION] Extend the existing `scenario_facts` minimally rather than create a new framework. Add one versioned `measurement` object or a `measurement_plan_id` plus a small embedded registry; keep acquisition and raw-tool provenance in their existing sidecars.

[RECOMMENDATION] A compact prospective record should contain these logical fields:

| Object | Required fields |
|---|---|
| [RECOMMENDATION] Plan | `schema_version`, `plan_id`, `frozen_at`, `scenario_revision`, `question_ids`, `prior_scenario_exposure` |
| [RECOMMENDATION] Action | `action_id`, neutral description, scenario phase |
| [RECOMMENDATION] Target/assertion | `target_id`, `action_id`, dimension, expected state, predicate ID/version, applicable views, applicable origins, sealed exact identity/value |
| [RECOMMENDATION] Control | `control_id`, expected absence/state, predicate, applicable views/origins |
| [RECOMMENDATION] Acquisition condition | filesystem/kernel/distribution, time zone, source timing, shutdown/snapshot state, and recovery-specific write/delete controls |

[RECOMMENDATION] Use this limited dimension vocabulary: `identity`, `metadata`, `content_complete`, `content_partial`, `event_action`, `temporal_relation`, and `control`.

[RECOMMENDATION] One atomic finding record should contain:

| Dimension | Values or fields |
|---|---|
| [RECOMMENDATION] Identity/provenance | `finding_id`, optional `candidate_id`, `run_id`, `plan_id`, notebook/procedure revision |
| [RECOMMENDATION] Source | `source_view` (`disk`, `timeline`, `memory`, later `network`), `evidence_origin_id`, acquisition artifact/hash reference |
| [RECOMMENDATION] Context access | `pass1_withheld` or `pass2_guided`; `prior_scenario_exposure` |
| [RECOMMENDATION] Applicability | `applicable` or `not_applicable`, with prospective basis |
| [RECOMMENDATION] Execution | `completed`, `failed`, or `not_run`, with method ID, tool/version, command-log/raw-output reference, and search bounds |
| [RECOMMENDATION] Observation | `O`, `P`, `N`, or `none`; target dimension; structured source-specific `observed` object |
| [RECOMMENDATION] Evidence | Durable raw locator, source hash, supporting locators, and bounded limitation |
| [RECOMMENDATION] Adjudication link | `accepted`, `rejected`, or `unresolved` match to a target; rule, basis, reviewer, time |

[RECOMMENDATION] Do not collapse `failed`, `not_run`, `not_applicable`, and `N` into one status. Their distinction is necessary to decide whether a denominator exists and what a negative result means.

[RECOMMENDATION] Metric records must list included IDs and exclusion reasons, not only a decimal. Fractions should be serialized with integer numerator and denominator so results remain auditable.

[RECOMMENDATION] Exact ground-truth values required by the runner should remain minimal and factual. Research-only assertion metadata may be referenced by plan ID if embedding it would make `manifest.json` materially larger; this is a documentation decision, not a reason to add a runtime evaluation engine.

## 7. Reusable notebook contract

[RECOMMENDATION] Disk, memory, and timeline notebooks for one scenario must implement the same seven-stage contract:

1. [RECOMMENDATION] **Inputs and gates:** bind one run, plan, acquired source, source hash, notebook revision, tool versions, and G1 result.
2. [RECOMMENDATION] **Pass-one question and plan:** display allowed context, required checks, applicability, and stopping rule without exact locators.
3. [RECOMMENDATION] **Bounded examination:** run the frozen source checks and save raw outputs, commands, hashes, bounds, zero results, and failures.
4. [RECOMMENDATION] **Pass-one freeze:** emit atomic candidates/findings and a frozen narrative; record G2 inputs.
5. [RECOMMENDATION] **Reveal and guided verification:** load exact facts, run only labelled verification checks, and append rather than rewrite findings.
6. [RECOMMENDATION] **Adjudication and arithmetic:** record small human match decisions, then calculate pass-one-only and all-pass metric records deterministically.
7. [RECOMMENDATION] **Interpretation:** write source-specific meaning, contradictions, alternative explanations, and bounded limitations with finding/action references.

[RECOMMENDATION] Automation may execute fixed commands, preserve raw output, hash artifacts, normalize known fields, evaluate deterministic predicates, join already adjudicated IDs, and perform arithmetic.

[RECOMMENDATION] Human decisions remain necessary for candidate selection, ambiguous identity, semantic `O/P/N` adjudication, contradiction resolution, and cross-source interpretation. Each such decision must be small and recorded rather than hidden in prose.

[RECOMMENDATION] Methodological equivalence across distributions requires the same plan IDs, checks, predicates, field schema, pass rules, and metric code. The first notebook may explain each step richly and later notebooks may be terse, but they may differ only in narrative depth and explicitly declared environment-specific commands.

[RECOMMENDATION] A future network notebook adds `source_view: network` and a new `evidence_origin_id` for the capture. It must use the same finding, adjudication, pass-scope, gate, M1, and M2 rules; no formula redesign is needed.

[RECOMMENDATION] A reusable notebook must fail visibly when required inputs, plan versions, or gates disagree. It must not silently reuse findings from another run.

## 8. Recovery subdesign

### 8.1 Is it needed?

[RECOMMENDATION] A dedicated recovery treatment is needed only if the thesis asks whether deleted **content** can be recovered under controlled persistence conditions. It is not needed to substantiate the current Father observability narrative.

[PROJECT FACT] In the current Father evidence, the deleted `/tmp/rk.so` content was not recovered; the journal supported name/metadata history, and the bytes of the deleted temporary object were identical to an allocated installed implant copy (`ai/03_investigation/output/disk-investigation-refactor-plan.md`; `shared/investigations/father-u22-20260819-03/derived/disk/findings.json`).

[INFERENCE] Counting this as successful content reconstruction would conflate historical metadata with recovered bytes and would make the recovery denominator non-unique.

### 8.2 Reconstruction levels

| Level | Minimum support | Must not be called |
|---|---|---|
| [RECOMMENDATION] Identity/name | A target-specific name/path/inode association | Content recovery |
| [RECOMMENDATION] Metadata | Verified attributes such as size, mode, owner, timestamps, extents, or directory relationship | Recovered file bytes |
| [RECOMMENDATION] Complete content | Exact size and SHA-256 match, plus meaningful open/parse check | Merely “identified” or “carved” without verification |
| [RECOMMENDATION] Partial content | Target-specific byte agreement with offsets/coverage/gaps/extras recorded | Complete recovery |
| [RECOMMENDATION] Event/action | One or more accepted findings satisfy a frozen action predicate | Complete temporal reconstruction |
| [RECOMMENDATION] Ordered timeline | Required action nodes and prospectively defined order relations are supported, with uncertain/conflicting relations retained | A single timestamp list or average displacement |

### 8.3 Minimal two-arm treatment

[RECOMMENDATION] Create one uniquely tagged target per arm from the same generator, with a UUID/block-index pattern, frozen original bytes, SHA-256, size, type, creation/deletion times, and expected identity. Use different target IDs and content per arm to prevent accidental cross-match.

[RECOMMENDATION] **Persisted arm:** write the target, call file `fsync`, durably update the parent directory as required by the filesystem procedure, then delete it without adding a post-delete flush intended to improve recovery.

[RECOMMENDATION] **Naturalistic arm:** write and close the target, perform no explicit `fsync`/`sync`, then delete it under the same scripted timing.

[RECOMMENDATION] Hold constant the VM baseline, filesystem/mount options, distribution/kernel, file size/type, dwell times, deletion-to-acquisition interval, post-deletion workload, shutdown/snapshot method, acquisition method, recovery tool versions, and notebook procedure.

[RECOMMENDATION] Record actual extent/fragmentation layout before deletion when feasible, journal parameters/state, post-deletion writes, acquisition timing, and every failed or zero-result recovery method. Do not force a fragmentation or overwrite outcome and then describe it as naturalistic.

[RECOMMENDATION] Include at least one uniquely patterned distractor/negative control so that target-specific byte agreement can be distinguished from generic carved content.

[RECOMMENDATION] One independently acquired run per arm is a pilot that can demonstrate the procedure and observed outcomes. For a repeatability or persistence-condition comparison, use at least three independently reset and acquired runs per arm, report every target result, and summarize with counts plus median/range where byte coverage varies.

[EXTERNAL EVIDENCE] CFTT/CFReDS and SWGDE recovery tests deliberately include complete, fragmented, and partially overwritten cases and compare against known data ([CFReDS deleted-file tests](https://cfreds-archive.nist.gov/dfr-test-images.html); [SWGDE tool-testing requirements](https://www.swgde.org/wp-content/uploads/2024/04/2024-03-07-SWGDE-Minimum-Requirements-for-Testing-Tools-Used-in-Digital-and-Multimedia-Forensics-18-Q-001-2.1.pdf)).

[RECOMMENDATION] Treat those cases as design guidance for construct coverage. They become necessary only if the thesis claims general deleted-file recovery capability or validates a recovery tool; a narrow persisted-versus-naturalistic case study may explicitly limit itself to the layouts actually produced.

## 9. Threats to validity and claim limits

### 9.1 Construct validity

[INFERENCE] A scripted target registry measures observability of selected scenario assertions, not all traces of a rootkit or all evidence an investigator might find.

[INFERENCE] `P` involves judgement unless its missing components are predeclared; record the predicate and adjudication basis and subject `P` to review.

[INFERENCE] M2 can overstate corroboration if source views derived from one disk are treated as independent origins; the view/origin distinction is therefore mandatory.

[INFERENCE] Candidate rejection counts lack a complete candidate universe and cannot support precision or a false-positive rate.

### 9.2 Internal validity

[INFERENCE] Exact target knowledge can turn discovery into verification. The pass-one freeze, access-mode tag, and sensitivity recomputation mitigate but do not eliminate confirmation bias.

[INFERENCE] The same analyst's pass two is not independent of pass one, and later distribution runs are affected by prior scenario exposure.

[PROJECT FACT] The reference run records a modified working tree, the memory acquisition is not verified, and current source examples mix run IDs (`shared/experiments/father-u22-20260819-03/manifest.json`; `shared/experiments/father-u22-20260819-03/dumps/acquisition.json`; `shared/investigations/father-u22-20260818-02/`; `shared/investigations/father-u22-20260819-03/`).

[INFERENCE] These conditions prevent a clean causal or cross-source evaluation from the current artifacts; they do not erase the value of bounded descriptive disk observations.

[INFERENCE] Recovery is highly sensitive to filesystem state, caching, fragmentation, overwrite, shutdown, and acquisition timing; without the controls in Section 8, an observed recovery difference cannot be attributed to persistence treatment.

### 9.3 External validity

[INFERENCE] One Father implementation, one controlled VM, one filesystem/kernel profile, and one analyst do not represent Linux rootkits, operational environments, or analysts generally.

[INFERENCE] Cross-distribution execution improves case diversity but does not isolate “distribution” as the cause unless other environment and treatment factors are controlled and repeated.

[RECOMMENDATION] Phrase conclusions as “in the acquired run(s), under the stated procedure” and name the distributions, kernels, source origins, and scenario revision.

### 9.4 Conclusion validity and uncertainty

[INFERENCE] Targets and actions within one scenario are designed, clustered, and dependent. Treating them as independent samples for binomial confidence intervals would produce unjustified precision.

[RECOMMENDATION] For single runs, report exact counts, fractions, named IDs, contradictions, and limitations. For repeated conditions, report all run-level values plus median and range; reserve inferential statistics for a future design with a justified sampling model and adequate replication.

### 9.5 Reliability

[INFERENCE] Different notebook schemas, prose-only judgements, missing raw locators, and silent tool failures make independent scrutiny difficult.

[RECOMMENDATION] Freeze plan/procedure versions, retain raw hashes and locators, distinguish zero from failure, record human adjudication, and have a second reviewer examine `P`, `X`, and unresolved records when feasible.

## 10. Migration and documentation ownership

[RECOMMENDATION] Keep this report as the review artifact in `ai/03_investigation/output/`. After the three decisions in Section 11 are approved, promote a concise normative contract to `ai/03_investigation/references/investigation-measurement-contract.md` and add it to the always-read list in `ai/03_investigation/CONTEXT.md`.

[RECOMMENDATION] Update `ai/archive/METHODOLOGY.md` only after approval: preserve its epistemic boundary, fixed-table concept, negative/tool-failure reporting, and `O/P/N/TF/--` display; replace generic “coverage” with M1 strict/inclusive observability, qualify `C` by evidence origin, delete union gain from the core metric set, demote TTF to optional workflow metadata, and move M4 to descriptive timestamps.

[RECOMMENDATION] Resolve the documentation-path wording during promotion: `ai/INDEX.md` refers to a repository-root `archive/METHODOLOGY.md`, while the inspected file is `ai/archive/METHODOLOGY.md`, and `ai/03_investigation/CONTEXT.md` uses a relative wording that can be read ambiguously.

[RECOMMENDATION] Do not revive the archived detector/matcher schema, add a scoring service, or make notebooks discover ground truth automatically. The only justified automation is deterministic record production, predicate evaluation after the permitted reveal, and arithmetic over adjudicated IDs.

[RECOMMENDATION] Do not edit existing accepted findings in place during migration. Version the new plan/contract and regenerate derived metric records from eligible runs; retain old results as historical records with their schema and run IDs.

[RECOMMENDATION] Before calling a future run accepted for cross-source evaluation, require: clean/pinned scenario revision; complete manifest/command log; valid acquisition gates for every claimed origin; same-run disk, memory, and timeline outputs; frozen pass-one record; completed adjudication; and reproducible metric inputs.

## 11. Human decisions still required

### Decision 1 — Is deleted-content recovery a research question?

- [RECOMMENDATION] **Option A — no dedicated recovery claim (recommended for the minimal thesis):** keep Father as observability/action evidence and report the non-recovery limitation; do not calculate M3.
- [RECOMMENDATION] **Option B — two-arm pilot:** one persisted and one naturalistic acquisition; supports feasibility and case description only.
- [RECOMMENDATION] **Option C — repeated two-arm subdesign:** at least three independent acquisitions per arm; supports a bounded repeatability/condition comparison but adds substantial VM and analysis work.

### Decision 2 — What strength of cross-condition claim is needed?

- [RECOMMENDATION] **Option A — descriptive case comparison (recommended under thesis deadlines):** one eligible run per distribution/condition, identical contract, no causal attribution.
- [RECOMMENDATION] **Option B — repeatability/condition claim:** at least three independent runs per condition with all run-level results, median, range, and deviations.

### Decision 3 — Who adjudicates ambiguous findings?

- [RECOMMENDATION] **Option A — targeted second review (recommended):** the primary analyst decides all records; a second reviewer independently checks every `P`, `X`, and unresolved match before metrics are frozen.
- [RECOMMENDATION] **Option B — single analyst:** retain a complete audit trail and explicitly limit reliability claims.
- [RECOMMENDATION] **Option C — full dual independent examination:** strongest examiner-reliability design but disproportionate unless human performance becomes a research question.

## 12. Evidence base, search bounds, and unresolved project conflicts

### 12.1 Search scope

[EXTERNAL EVIDENCE] The external search was conducted through 2026-08-20 and prioritized current official pages/documents from NIST CFTT and CFReDS, SWGDE's current and published document listings, NIST/OSAC, ISO, ASTM, and DOI/publisher records for peer-reviewed digital-forensics research.

[INFERENCE] Search concepts included forensic tool testing, known-data and realistic scenario datasets, deleted-file recovery, reconstruction completeness, timeline/temporal reconstruction, Linux rootkit detection evaluation, ground-truth-assisted examination, cognitive bias, linear sequential unmasking, precision/recall, and examiner proficiency.

[INFERENCE] This was a targeted methodological search, not a preregistered systematic review with duplicate screening, database-exported search strings, and formal risk-of-bias appraisal.

[INFERENCE] No reviewed source established a universal metric for this exact human-led multi-source Linux DFIR design. This is a bounded search conclusion, not proof that no such method exists.

### 12.2 Project evidence used

[PROJECT FACT] Repository governance and boundary were established from `ai/ROUTING.md`, `ai/INDEX.md`, `ai/IDENTITY.md`, `ai/03_investigation/CONTEXT.md`, and `ai/02_experiments/CONTEXT.md`.

[PROJECT FACT] Later design decisions and open metric questions were taken from `ai/03_investigation/output/metrics-feasibility-discussion.md`; archived reporting rules and historical architecture were distinguished using `ai/archive/METHODOLOGY.md`.

[PROJECT FACT] Investigation practice and disk-specific evidence were checked against `ai/03_investigation/references/investigation-guidelines.md` and `ai/03_investigation/output/disk-investigation-refactor-plan.md`.

[PROJECT FACT] Scenario behaviour and current manifest facts were checked directly in `scenarios/userland_father_ldpreload/runner.py` and `shared/experiments/father-u22-20260819-03/manifest.json`.

[PROJECT FACT] Acquisition status was checked in `shared/experiments/father-u22-20260819-03/dumps/acquisition.json`; current disk, memory, and timeline record shapes were checked in the corresponding `shared/investigations/.../derived/{disk,memory,timeline}/{findings,metrics}.json` examples.

### 12.3 Recorded conflicts and limitations

- [PROJECT FACT] The prompt names `manifest.json.facts`, but the current schema uses `scenario_facts`; this report recommends extending the actual field rather than guessing a new root key.
- [PROJECT FACT] `ai/02_experiments/CONTEXT.md` names an earlier Father final run, while the later feasibility decision selects `father-u22-20260819-03`; this report follows the later explicit decision.
- [PROJECT FACT] The selected reference run is not a clean immutable revision because its manifest records `working_tree: modified`.
- [PROJECT FACT] Its disk acquisition has completed logical SHA-256 verification, whereas its memory image is recorded as unverified.
- [PROJECT FACT] Its investigation outputs currently contain disk records only; the inspected memory/timeline examples belong to the earlier run and cannot be pooled into a same-run metric.
- [PROJECT FACT] Current source-specific finding schemas are not yet one atomic cross-source contract; disk is nested and target-oriented, memory is plugin/prose-oriented, and timeline is aggregate-oriented.
- [INFERENCE] These conflicts require prospective contract migration and a new eligible same-run analysis before final M1/M2 numbers can be reported; they do not justify altering Father behaviour merely to create favourable evidence.

### 12.4 Final acceptance criteria for the methodology

[RECOMMENDATION] Accept the method after Decisions 1–3 are recorded, the normative contract is promoted, exact plan assertions are frozen before the next measured investigation, the pass-one record is immutable, and same-run eligible source outputs support auditable numerator/denominator reconstruction.

[RECOMMENDATION] Until those conditions are met, use the current Father materials for method development and bounded descriptive evidence only; do not publish provisional metric values as scientific results.
