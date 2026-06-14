# Research prompt: making the evaluation metrics forensically valid and scenario-ready

This is the third companion to the two detection prompts. Where
`docs/DETECTION_METHODS_RESEARCH_PROMPT.md` decides *which detection methods*
fit a vanilla disk+memory image and `docs/DETECTION_RESEARCH_PROMPT.md` sources
*specific rules* and calibrates their specificity, this prompt is about the
layer above detection: **how findings are turned into metrics, why the current
metrics are not yet forensically defensible, and the minimal changes that make
the project valid and "almost ready" to absorb new scenarios.** Use it with a
web-capable deep-research assistant. It must return both a **literature review
(how the field handles each problem)** and **concrete implementation
suggestions**, ending with a single **ordered task list**.

---

## Current state (ground the research in what actually exists)

Pipeline: acquire (E01 disk + raw memory) -> `extract/` (TSK bodyfile, Plaso
super-timeline JSON-L, Vol3 plugin JSON) -> `detect/` (GT-blind, emits
`Finding`s) -> `match/` (GT-aware, against a seeded `gt_manifest.json`) ->
`metrics/` (CSV + Markdown report). Three sources: **TSK** (`source_tool=tsk`,
filesystem, wallclock times), **Plaso** (`source_tool=plaso`, logs/timeline +
Sigma + tagging, wallclock), **Vol3** (`source_tool=vol3`, memory, *no* wallclock
-> `ts_quality="none"`). Everything is **flat files** under
`shared/experiments/<run_id>/{dumps,analysis}/` (JSONL/JSON/CSV); **no database,
no index**. Plaso's own `.plaso` is SQLite but is never queried directly.

How metrics are computed today (files: `match/matcher.py`,
`metrics/compute.py`, `metrics/report.py`, config `config/matching.yaml`):

- **Cluster (a "claim")**: findings are deduped into clusters keyed on
  `(source_tool, event_class, entity_key, time_bucket)` with `dedup_bucket_s=60`.
- **Match**: greedy 1:1 assignment of GT events to clusters, gated by an
  `event_class` equivalence table, by `entities_match` (path/process/socket/user
  normalization), and by a time window `tolerance_s=60` (timeless memory clusters
  matched last).
- **Corroboration**: an unmatched cluster folds into a matched GT as a multi-tool
  TP when it shares the *technique* but reports a *different entity type/channel*,
  within `corroboration_window_s=120`. The TP records `n_clusters` = primary +
  corroborators.
- **Scope + known-good**: clusters outside `[firstGT-1800s, lastGT+1800s]` are
  `background_noise` (excluded from precision); a hand-listed `known_good`
  allowlist (currently `vol3:malfind` on `networkd-dispatcher`) also demotes a
  cluster to background noise instead of FP.
- **Formulas**: `recall = tp / gt_n` (per expected event);
  `precision = true_claims / (true_claims + fp)` where
  `true_claims = sum(n_clusters over TP)` ("claim-cluster" unit, declared in
  `matching.yaml: precision_definition`); `f1`; `order_pairwise` and
  `kendall_tau` over wallclock TPs; `time_mae_s`. Legacy columns add a banded
  "QoR = f1 * order_pairwise".
- **Bias guards**: `tests/test_detect_blindness.py` forbids the `detect/` layer
  from importing GT/scenario/match; `tests/test_rule_leakage.py` forbids any
  seeded instance literal (paths with random tokens, IP:port, timestamps) from
  appearing verbatim in a rule. Rules carry `rule_layer` (`community` vs
  `custom`) and the report already shows **recall by rule layer**.

Ground truth (files: `scenario/manifest.py`, `contracts/gt_manifest.schema.json`,
fixture `tests/fixtures/scenario_01/`): a `GtManifestBuilder` records, at attack
execution time, one `GtEvent` per action: `{gt_id, ts_utc, technique,
event_class, entity:{type,value}, expected_sources:[disk_fs|disk_logs|memory]}`.
Instance values (paths, ports, FIFO names) come from a **seeded RNG** so they
differ per run and cannot be memorized by a rule.

Forensic operation coverage today: **timeline analysis** (Plaso) and **memory
analysis** (Vol3: pslist/psscan cross-view, malfind, maps, sockstat/netstat,
linux.bash) are implemented; **deleted-file listing** is partial (TSK `fls`
flags deleted entries, but there is no active recovery via `icat`/`tsk_recover`);
**string search**, **file carving**, and **YARA/IOC content scanning** are
absent (the `config/rules/yara/` slot and `yara_python` pin exist but nothing is
wired). There is no first-class notion of a "forensic operation" -- detectors
are organized only by source tool and ATT&CK technique.

### The known limits this research must address

1. **Ground-truth under-modeling causes false positives.** A GT event names ONE
   canonical `entity.value` and a small `expected_sources` set, but one action
   leaves the same artifact/string in *many* legitimate evidentiary loci. In the
   calibration scenario (`scenario_01`, LD_PRELOAD + reverse shell) the
   `/etc/ld.so.preload` write is independently observable as a filesystem entry
   (TSK, `path`), a journald/auth line (Plaso, `process` entity
   `sudo tee -a /etc/ld.so.preload`), and a Sigma `process_exec` hit -- none of
   which carry the path entity GT enumerated, so before the corroboration fix they
   scored as FPs. The current remedies (technique-anchored corroboration + a
   hand-curated `known_good` allowlist) work for this one scenario but are
   *post-hoc* and risk being a way to make FPs disappear by hand. We need a
   principled GT/observable model, not a growing allowlist.
2. **No operation vocabulary and no defined multi-source fusion.** Results are
   not expressed in standard forensic terms (String Search, Deleted File
   Recovery, File Carving, Timeline Analysis, Memory Analysis), and it is unclear
   how observations from different sources (tsk/plaso/vol3) AND different
   operations should be integrated into a single, interpretable metric.
3. **Over-custom implementation; weak storage.** Custom-coding every operation is
   over-engineering; mature specialized tools exist for several (carving,
   string/keyword indexing, IOC/YARA, timeline indexing). Storage is flat files
   with no DB, no indexing, no query layer -- poor for performance and for
   examiner-grade querying.
4. **Rule provisioning is manual and therefore biased.** Only two custom Sigma
   rules exist; the community Sigma set is not vendored and YARA is empty.
   Hand-authoring rules against a scenario we designed is a validity threat. We
   want to pull external rule corpora (Sigma, YARA, artifact catalogs) and plug
   them in mechanically so the detection layer is independent of the test set.

---

## Prompt

> I am building a reproducible Linux DFIR **evaluation** lab for an MSc thesis
> (architecture summarized above). It runs ATT&CK-derived attacks on a vanilla
> Ubuntu VM, acquires a disk image (E01) and a memory image (raw), runs a
> ground-truth-blind detection layer over The Sleuth Kit, Plaso, and Volatility 3,
> then matches findings to seeded ground truth to compute recall/precision/order/
> time metrics. I need to find the **actual limits of this evaluation design** and
> the **minimal changes to make it forensically valid and ready to absorb new
> scenarios**. For every theme below, give (a) a **literature review** of how the
> DFIR / detection-engineering / tool-testing community has handled the problem,
> with primary citations, and (b) **concrete implementation guidance** for my
> stack. Prefer primary sources (NIST, ISO/IEC, peer-reviewed DFIR, project docs,
> SANS, MITRE) over blog posts; flag licenses for anything I would redistribute.
>
> **Theme 1 - Ground-truth and observable modeling (the false-positive root
> cause).** One attacker action produces the same artifact/string in multiple
> valid places (filesystem inode, on-disk log line, in-memory mapping, process
> command line). My ground truth records one canonical entity per event, so a true
> observation in an unmodeled locus is scored as a false positive, which I am
> currently patching with technique-anchored "corroboration" and a hand-curated
> known-good allowlist.
> - How do forensic-evaluation datasets and tool-testing methodologies model
>   ground truth when an artifact has *many* legitimate evidentiary loci? Is the
>   right unit the *action/event* with a set of acceptable observables, the
>   *observable*, or the *technique*? Cite how existing labeled DFIR datasets
>   (e.g. attack-range / purple-team datasets, the DFIR Report datasets, academic
>   corpora, EVTX/Sigma test data, memory-forensics datasets) encode this.
> - What is the accepted way to separate a genuine **false positive** from an
>   **unmodeled true observation**, without leaking ground truth into detectors?
>   Is a known-good / allowlist baseline a recognized, defensible practice (NIST
>   SP 800-86, SANS), and what keeps it from silently inflating precision? What
>   should be pre-registered vs tuned?
> - Is my "corroboration" (fuse same-technique observations across entity
>   channels) an established evidence-fusion idea, and what is the citable framing
>   (multi-source corroboration, data fusion levels, provenance)?
>
> **Theme 2 - Forensic operation vocabulary and multi-source fusion into
> metrics.** My results are not expressed in standard examination terms and I have
> no defined way to integrate sources and operations into one metric.
> - Give the **canonical taxonomy and terminology** of forensic examination
>   operations for disk+memory analysis -- e.g. String/Keyword Search, Deleted
>   File Recovery, File Carving, Timeline Analysis, Memory Analysis, Hashing/IOC
>   matching. Anchor on **NIST CFTT** test specifications (which name exactly these
>   categories: Deleted File Recovery, String Search, Forensic File Carving,
>   Forensic Media Preparation, Hardware/Software Write Block), NIST SP 800-86,
>   SWGDE, and ISO/IEC 27037/27042. For each operation: what evidence domain it
>   targets, its standard tooling, and its standard *effectiveness metric*.
> - How should I model an **operation dimension** orthogonal to source tool and
>   ATT&CK technique, so metrics can be sliced per operation and per source and
>   then fused? How do multi-tool / multi-source studies report a fused result
>   (per-source recall, union recall, marginal/unique contribution of each tool,
>   inter-tool agreement)? Is there an accepted way to weight or combine tools of
>   differing reliability (e.g. memory findings that lack reliable timestamps)?
> - Are my metric definitions defensible and citable? Specifically critique
>   **"claim-cluster precision"** (`true_claims/(true_claims+fp)`,
>   `true_claims = sum of clusters folded into each TP`) versus standard IR
>   precision/recall and versus forensic **error-rate / false-discovery**
>   reporting. Comment on `order_pairwise` and Kendall's tau for timeline-order
>   accuracy and on time-MAE, and on whether memory findings (no wallclock) should
>   be excluded from temporal metrics.
>
> **Theme 3 - What to outsource vs build, and a real storage/index layer.**
> Custom-coding every operation is over-engineering and I store everything as flat
> JSON/CSV with no index.
> - For each operation in Theme 2, recommend whether to **outsource to a mature
>   tool** or keep a custom heuristic, with the trade-offs: string/keyword search
>   and indexing (bulk_extractor, Autopsy/Solr, ripgrep, dfVFS), deleted-file
>   recovery and carving (tsk_recover, PhotoRec, foremost, scalpel,
>   bulk_extractor), IOC/content scanning (YARA via yara-python, ClamAV, Loki/THOR),
>   timeline analysis and *indexed* storage (Plaso + **Timesketch** on
>   OpenSearch/Elasticsearch). Which are standard, scriptable, and license-clean
>   for an academic pipeline?
> - Recommend a **storage and indexing** design proportionate to a single-host
>   research lab: keep flat files as the immutable evidence record but add an
>   indexed query layer. Compare options -- SQLite/DuckDB over the findings and
>   timeline, vs. Timesketch/OpenSearch for the super-timeline, vs. dfVFS for
>   uniform image access. What gives examiner-grade query/performance with the
>   least operational weight? How do reproducibility frameworks want artifacts and
>   their hashes/provenance recorded (my pipeline already emits a `provenance.json`
>   with SHA-256 and pinned tool versions)?
>
> **Theme 4 - Provisioning detection rules at scale without author bias.** I have
> two hand-written Sigma rules; authoring rules against a scenario I designed is a
> validity threat (test-set leakage / circularity).
> - Where do I source detection content at scale, and under what licenses, for
>   *automatic* (not hand-written) ingestion: SigmaHQ `rules/linux`, Elastic
>   detection-rules, Splunk Security Content, Florian Roth `signature-base`
>   (YARA), Neo23x0, YARAify, and the **ForensicArtifacts/artifacts** catalog for
>   persistence-location enumeration?
> - How do I **mechanically plug** these in: pySigma + an appropriate backend to
>   run community Sigma unmodified against my Plaso super-timeline; a YARA scan
>   over `icat`-extracted / carved files; an artifacts-catalog-driven enumeration
>   of persistence paths. How do practitioners filter a large rule corpus down to
>   the logsources a *vanilla* host actually keeps (no auditd/Sysmon)?
> - What is the methodological literature on **evaluation validity and bias** I
>   should cite: detection-vs-test-set independence (analogous to ML data leakage
>   / train-test contamination), the value of an unmodified community-rule
>   baseline as the unbiased reference (my report already separates community vs
>   custom recall), and forensic-validation standards -- **NIST CFTT** validation
>   methodology, **ISO/IEC 27041/27042/27043**, **Daubert** admissibility (known
>   error rate, peer review, standards), and reproducibility.
>
> **Theme 5 - Minimality and scenario-readiness (the synthesis).** Given all of
> the above, what is the **minimal** set of changes that (i) removes the
> ground-truth-modeling false positives in a principled way, (ii) introduces the
> operation vocabulary and a defined source/operation fusion into the metrics,
> (iii) outsources the operations worth outsourcing and adds an indexed store, and
> (iv) provisions external rules mechanically -- such that **adding a new scenario
> becomes mostly declarative** (write the attack + its GT, reuse everything else)?
> Call out the smallest number of new abstractions, and explicitly what to NOT
> build.
>
> **Deliverables.** Return, in order:
> 1. A short **literature map** per theme (claim -> primary citation), including a
>    table of forensic operations (operation | evidence domain | standard tool |
>    standard effectiveness metric | NIST/ISO anchor).
> 2. A **GT/observable data model** proposal (how to represent one event with
>    multiple acceptable observables/loci, and how matching consumes it without
>    breaking detector blindness).
> 3. A **metrics critique + revised definitions** (verdict on claim-cluster
>    precision; recommended per-operation/per-source and fused reporting).
> 4. An **outsource-vs-build matrix** and a concrete **storage/index
>    recommendation** for this single-host lab.
> 5. A **rule-provisioning design** (sources, licenses, the pySigma/YARA/artifacts
>    wiring, the vanilla-logsource filter) and how to measure rule-source bias.
> 6. A final **ordered task list**: the minimal, sequenced changes to reach
>    forensic validity and scenario-readiness, each tagged effort (S/M/L), its
>    dependency, and the validity threat it closes. Separate "validity-critical"
>    from "nice-to-have".

---

## Anchor sources to verify first

- **NIST CFTT** (Computer Forensics Tool Testing) -- test specifications for
  *Deleted File Recovery*, *String Search*, *Forensic File Carving*, *Forensic
  Media Preparation*, write-blocking; their effectiveness/measure definitions.
- **NIST SP 800-86** (integrating forensic techniques; collection/examination/
  analysis/reporting) and **SP 800-101r1** (mobile, for method framing).
- **ISO/IEC 27037 / 27041 / 27042 / 27043** -- handling, assurance of
  investigative methods, analysis/interpretation, incident-investigation
  principles; and **Daubert** factors (known error rate).
- **SWGDE** best practices (examination, memory, archiving).
- **MITRE ATT&CK** technique pages for the in-scope IDs; **MITRE Engenuity**
  evaluation methodology (how ATT&CK evaluations score detections) as a model for
  detection scoring.
- **SigmaHQ/sigma** + **pySigma** backends; **elastic/detection-rules**; **Splunk
  security-content**; **Neo23x0/signature-base** and **YARA-Rules** (YARA);
  **ForensicArtifacts/artifacts** catalog. Note each license.
- **Plaso/log2timeline** + **Timesketch** (OpenSearch indexing), **dfVFS**;
  **bulk_extractor**, **PhotoRec**, **foremost**, **scalpel**, **tsk_recover**;
  **Volatility 3** docs.
- DFIR datasets for ground-truth encoding precedent: **Splunk attack_range**,
  **The DFIR Report**, **mordor/Security-Datasets (OTRF)**, **EVTX-ATTACK-SAMPLES**,
  and academic memory/disk forensic corpora.

## How to fold results back into this repo

- A richer GT/observable model -> extend `contracts/gt_manifest.schema.json` and
  `scenario/manifest.py` (e.g. an `observables` list per event) and teach
  `match/matcher.py` to accept any modeled observable; keep
  `tests/test_detect_blindness.py` / `test_rule_leakage.py` green. Replace the
  hand `known_good` list with a documented, pre-registered baseline mechanism.
- An operation dimension -> add a `forensic_operation` field to `Finding`
  (`detect/base.py`) and slice metrics by it in `metrics/compute.py` /
  `report.py`, alongside the existing per-tool `unique_contribution`.
- Outsourced operations -> thin runners under `orchestrator/forensics/` mirroring
  `vol_runner.py` / `sleuth_runner.py`, surfaced via `evaluation/extract/`
  adapters (string search / carving / YARA); an indexed store (SQLite/DuckDB or
  Timesketch) layered over the immutable `shared/experiments/<run_id>/` files.
  Note: a Timesketch ingestion skill already exists in this environment.
- Mechanical rule provisioning -> populate `config/rules/sigma` from SigmaHQ at
  the pinned `sigma_ref`, wire `config/rules/yara` to a YARA detector scanning
  extracted/carved files (`yara_python` is already pinned in `pipeline.yaml`),
  and keep the community-vs-custom `rule_layer` split so the report's
  recall-by-layer quantifies any author bias.
- See the companions `docs/DETECTION_METHODS_RESEARCH_PROMPT.md` (method
  selection) and `docs/DETECTION_RESEARCH_PROMPT.md` (rule sourcing/specificity);
  this prompt assumes those methods/rules and focuses on metrics, ground-truth
  modeling, fusion, storage, and validity.
