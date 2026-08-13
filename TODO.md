# Thesis finalization plan

Updated 2026-08-13. This is the sole active delivery plan. The immediate goal is
to give the supervisor a coherent, evidence-backed thesis package as soon as
possible, with the first administrative milestone on 2026-08-19 and final
delivery targeted for 2026-09-21.

## Definition of done

The thesis must make one defensible contribution clear:

> This thesis designs and evaluates a reproducible, provenance-preserving
> laboratory method for post-mortem Linux DFIR. Across four controlled
> compromise techniques, it examines what filesystem, timeline, and memory
> evidence can establish independently and through cautious cross-source
> interpretation.

The repository demonstrates repeatable environment preparation, controlled
scenario execution, memory and disk acquisition, and auditable provenance.
Forensic examination and conclusions remain manual. Ubuntu 22.04 is the
deep-analysis platform; Ubuntu 24.04 and Debian 13 demonstrate the broader
provisioning surface but are not grounds for an unsupported cross-distribution
evaluation claim.

The final thesis is acceptable when it:

- answers the four research questions below using four accepted Ubuntu 22.04
  cases;
- separates automated laboratory execution/acquisition from manual forensic
  interpretation;
- contains a coherent methodology, results, limitations, and conclusion;
- supports every material result with a durable evidence locator;
- removes stale experiments and unsupported quantitative claims from the
  manuscript; and
- leaves a clean, understandable public repository and an honest account of
  tool assistance.

No new scenario, framework, detector, distribution, or broad feature is needed
to satisfy this definition.

## Research questions

1. Can controlled Linux post-mortem cases be reproduced with sufficient
   provenance for independent examination and review?
2. For each selected compromise technique, what do filesystem, timeline, and
   memory sources reveal separately?
3. Which conclusions are strengthened or become supportable only when those
   sources are correlated, and which remain uncertain?
4. Which practical limitations arise from acquisition timing, kernel and
   version dependence, tool support, cleanup, and bounded examination?

Do not claim generalized malware detection, automatic attack reconstruction,
incident-response readiness, automatic attribution, or statistical
cross-distribution performance. Descriptive case coverage is not precision,
recall, F1, or a benchmark.

## Frozen experimental basis

Engineering is frozen at `2e5dadc`. The four final acquired Ubuntu 22.04 cases
are:

1. `ubuntu-22.04_userland_father_ldpreload_20260813-224442`;
2. `ubuntu-22.04_ptrace_fa_20260813-224646`;
3. `ubuntu-22.04_kernel_diamorphine_20260813-224854`; and
4. `ubuntu-22.04_kernel_ebpf_badbpf_20260813-225102`.

Their manifests, staged-input hashes, memory hashes, EWF segment hashes, and
EWF verification passed. All VMs were left off. These runs are the final case
matrix unless an investigation proves that an acquisition is invalid.

The preserved partial Father examination under
`shared/investigations/ubuntu-22.04_userland_father_ldpreload_20260813-224442/`
is derived work, not an accepted notebook. Reuse it after verifying its source
and hashes; do not repeat valid expensive extraction merely for uniformity.

## Final thesis structure

The manuscript will use this six-chapter argument. First repair the table of
contents and write the methodology; do not expand generic theory first.

1. **Introduction**
   - Linux post-mortem DFIR problem and motivation;
   - research gap, questions, scope, and exclusions;
   - contributions and thesis organization.
2. **Linux post-mortem DFIR foundations and related work**
   - acquisition, integrity, provenance, and forensic process;
   - ext4/filesystem examination and timeline semantics;
   - Linux memory structures and Volatility-based examination;
   - userland, `ptrace`, LKM, and eBPF compromise layers;
   - related work and the precise gap addressed by this thesis.
3. **Experimental methodology**
   - laboratory and authorization boundary;
   - case selection and Ubuntu 22.04 analysis scope;
   - three reproducibility layers: baseline, prebuilt input, immutable run;
   - memory-while-running and disk-after-shutdown acquisition lifecycle;
   - manual source-aware investigation protocol;
   - separation of validation, observation, interpretation, and conclusion;
   - result-reporting contract, valid negatives, and tool failures;
   - threats to validity and ethical limitations.
4. **Laboratory implementation and case design**
   - minimal architecture and lifecycle;
   - pinned images, builders, prebuilt inputs, manifests, and acquisition;
   - four bounded case designs and their expected evidence families;
   - reproducibility procedure and validation boundary.
5. **Results and cross-source discussion**
   - Father / LD_PRELOAD;
   - `ptrace` process manipulation;
   - Diamorphine LKM;
   - BadBPF/eBPF;
   - comparative evidence matrix, source complementarity, negative results,
     contradictions, and tool limitations;
   - discussion answering the research questions.
6. **Conclusions and future work**
   - direct answer to each research question;
   - demonstrated contribution and restrained limitations;
   - only realistic future work, clearly outside the evaluated results.

Appendices may hold the command sheet, evidence-to-notebook map, and compact
provenance material. Large command outputs and raw exports remain in the
repository rather than padding the thesis.

### Theory triage

Retain theory only when it supports a research question, tool choice, evidence
interpretation, or limitation. Compress general introductions. Remove or
rewrite obsolete implementation material concerning VMware/CAINE, email and
network investigations, ftrace, Meterpreter, automatic batch analysis,
automatic reconstruction, and precision/recall-style evaluation unless it is
briefly and accurately presented as excluded historical work.

Before writing Chapter 2, perform a bounded literature review using primary or
peer-reviewed sources. Use the Vergari thesis as a structural comparison, not
as methodological authority. Confirm the research gap against current work on
Linux memory/rootkit forensics, multi-source post-mortem analysis,
reproducibility, and forensic reporting. Do not write novelty claims until that
review supports them.

## Delivery sequence

Complete one bounded task at a time. Each task ends with a scoped review and a
commit decision. Claude is optional; use a cheaper Codex reviewer when Claude
is unavailable. Never push or send email without explicit instruction.

### Phase 1 — Freeze the academic contract

- [x] Fix the contribution statement, research questions, four-case matrix,
  exclusions, and six-chapter structure in this plan.
- [ ] Compare the proposed structure with recent relevant literature and the
  completed Vergari thesis; record only defensible differences and gaps.
- [ ] Turn the final structure into a section-level LaTeX outline without
  drafting unsupported results.
- [ ] Obtain human confirmation of the title, research questions, and scope
  before substantial prose rewriting.

Stop gate: any proposed new scenario, metric, framework, or distribution must
be rejected unless the existing four cases cannot answer a research question.

### Phase 2 — Supervisor-ready methodology package

- [ ] Rewrite the introduction around the problem, four research questions,
  contributions, and explicit exclusions.
- [ ] Make Chapter 3 a complete, citation-supported methodology derived from
  `METHODOLOGY.md`, including threats to validity.
- [ ] Replace the stale implementation structure with the Chapter 4 outline;
  retain only verified current behavior.
- [ ] Add one architecture/acquisition diagram and one case-to-source
  applicability table if they improve comprehension.
- [ ] Compile and visually inspect the changed chapters.

This phase is the first writing priority. It makes the real engineering work
legible to the supervisor before all four investigations are complete.

### Phase 3 — Investigate and write one case at a time

For every case: verify the immutable run, state the question and stopping
condition, complete only useful source examinations, independently review the
notebook, then immediately write the corresponding Results subsection and
comparative row. Do not postpone all thesis writing until after all tools run.

1. **Father / LD_PRELOAD — disk-led exemplar**
   - reuse and verify the preserved ext4/journal, recovered-object, log, and
     bounded memory outputs;
   - complete concise filesystem, timeline, and memory notebooks;
   - emphasize persistence, cleanup/recovery, provenance, and the difference
     between discovery and ground-truth validation;
   - write the first complete case subsection. This is the supervisor-package
     exemplar.
2. **ptrace — memory-led case**
   - examine process relationships, mappings, shell/socket evidence, and
     appropriate bounded disk/timeline observations or negatives;
   - do not force equal source depth where the technique is memory-dominant;
   - write and review its case subsection and comparative row.
3. **Diamorphine — kernel-memory case**
   - examine module visibility, hidden-state discrepancies, kernel structures,
     and only justified disk/timeline traces;
   - distinguish module loading from proven hook behavior;
   - state symbol/plugin/kernel limitations precisely.
4. **BadBPF — eBPF visibility case**
   - examine process-hiding and eBPF-related visibility through supported
     memory/kernel observations, with bounded filesystem/timeline context;
   - avoid inferring behavior merely from filenames, scenario logs, or planted
     values;
   - record unsupported tooling and valid negatives as results, not omissions.

Each accepted case produces exactly:

- source notebook(s) with commands, versions, hashes, outputs, and limitations;
- one `runme_case_summary.md` using the fixed two-table contract;
- one reviewed Results subsection;
- one row in `docs/investigations/COMPARATIVE_RESULTS.md`; and
- only figures that materially help the reader. Target two to four evidence
  figures across the entire Results chapter, not one screenshot per command.

### Phase 4 — Cross-case results and conclusion

- [ ] Complete the existing descriptive reporting contract. Do not add
  statistical performance metrics, scoring, precision/recall/F1, or cross-case
  rankings.
- [ ] Explain source-specific contribution, corroboration, parser-level
  replication, valid negatives, tool failures, and union gain cautiously.
- [ ] Add a direct research-question-to-result mapping.
- [ ] Write threats to validity across case selection, one-distribution deep
  analysis, analyst knowledge, acquisition timing, and tool/kernel support.
- [ ] Write Conclusions as answers to the four research questions, followed by
  limitations and bounded future work.
- [ ] Check that the text says “observed” or “supported,” not “detected,” unless
  an actual detection method justifies the word.

### Phase 5 — Authorship, academic-integrity, and public-surface gate

This is a quality and disclosure gate, not an AI-detector evasion exercise.
Automated authorship detectors are not acceptance criteria and must not drive
changes to accurate prose. Do not use a “humanizer,” fabricate drafting history,
or hide assistance that university or supervisor policy requires disclosing.

For every chapter:

- [ ] verify every factual and methodological claim against a citation,
  repository behavior, or accepted case evidence;
- [ ] delete generic filler, repetitive summaries, fake quotations, invented
  references, unsupported certainty, English-to-Italian calques, and templated
  AI-style transitions;
- [ ] make terminology, tense, and authorial voice consistent;
- [ ] ensure the author understands and can orally defend every paragraph;
- [ ] run citation, plagiarism, spelling, and layout checks;
- [ ] treat any AI-detector result only as a prompt for human rereading, never as
  a score to optimize; and
- [ ] add the factual tool-use acknowledgment or methods disclosure required by
  applicable university and supervisor policy.

Before any public push or supervisor repository link:

- [ ] inspect tracked agent instructions, `.claude/`, `CLAUDE.md`,
  `.github/copilot-instructions.md`, local settings, prompts, and machine paths;
- [ ] remove private/personal workflow files and secrets from the public
  surface, while retaining useful project-facing contributor guidance only if
  it is accurate and impersonal;
- [ ] scan tracked files and Git history for credentials, personal data,
  generated evidence, oversized files, and stale automatic-analysis claims;
- [ ] review README, license, citations, third-party attribution, `.gitignore`,
  installation steps, and the final command sheet;
- [x] configure the correct name and email for all future commits
  (`Antonio Cesaria <s290262@studenti.polito.it>` in this repository);
- [ ] preserve commits referenced by accepted evidence manifests. Do not rewrite
  those hashes to repair `YOUR_GITHUB_EMAIL`; use a transparent `.mailmap` or
  documented attribution correction after verifying hosting behavior; and
- [ ] perform a clean-clone reproducibility/readability review without running
  another acquisition by default.

### Phase 6 — Supervisor checkpoint, final submission, and slides

Prepare the supervisor checkpoint as soon as Phase 2 and the Father exemplar
are ready; do not wait for optional work. Target delivery before 2026-08-19.
The package contains:

- a concise status email draft for human approval;
- a compiled PDF with coherent introduction, methodology, implementation
  outline, and one complete evidence-backed result case;
- the frozen four-run matrix and honest completion schedule;
- a clean repository status/link only after the public-surface gate; and
- focused questions requesting scope confirmation and thesis-conclusion
  approval.

Then complete the remaining cases, final Results and Conclusions, abstract,
bibliography, appendices, full-PDF visual review, repository release hygiene,
and presentation slides before 2026-09-21.

## Execution and resource rules

- At a user-reported 10% ChatGPT allowance, stop beginning new work. Finish
  only the current safe atomic check, record exact status and next command, and
  leave VMs off.
- Prefer Codex for implementation, investigation, research, and review. Claude
  is an optional second opinion after quota reset, never a blocker.
- No new VM/scenario execution is expected. Rerun only if a named final
  acquisition is proven invalid.
- Preserve accepted evidence and unrelated work. Derived outputs remain tied to
  their exact source run.
- Keep changes bounded and sequential: plan or inspect, implement, review,
  validate, then commit. Do not push or send email without explicit approval.
- A substantive forensic failure is recorded as a limitation or `BLOCKED`; do
  not improvise until a desired result appears.

## Exact restart point

On the next work session, start with Phase 1's bounded academic-relevance
review. Produce a citation-backed research-gap note and a section-level LaTeX
outline. After human confirmation, begin Phase 2 and make the methodology
chapter supervisor-ready. Only then resume the Father investigation and write
its Results subsection as the first exemplar.

Intentionally deferred: new scenarios, broad compatibility experiments,
Diamorphine cleanup, ftrace, Meterpreter, CopyFail, ART, worms, timestomping,
Fedora/SELinux, live response, network capture, automatic detection/matching/
scoring/reconstruction, new metrics, architecture rewrites, and cosmetic CLI
work.
