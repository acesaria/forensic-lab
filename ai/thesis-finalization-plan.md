# Thesis finalization plan

> **Status:** historical planning snapshot. It contains completed older-run and
> Ubuntu-only assumptions that are not the current investigation authority.
> Current tasks are controlled by `ai/INDEX.md`, `ai/DECISIONS.md`, the selected
> stage `CONTEXT.md`, and the exact supervisor/task prompt. Load this file only
> when a task explicitly asks to reconcile the delivery plan.

Updated 2026-08-20.

**Schedule slip (2026-08-20):** the 2026-08-19 first administrative milestone /
supervisor checkpoint was **missed** — the supervisor package (Phase 6) was not
delivered in time. Root cause: Phase 5 (authorship/integrity/public-surface
gate) and the Phase 6 package were never started before the date, while effort
went to the investigation layer and repository/public-surface cleanup. No
acquisition or accepted-evidence work is blocked; the slip is in writing-gate
and packaging, not in the frozen four-case basis. Final delivery is still
targeted for **2026-09-21** but is now at risk until a new supervisor
checkpoint is agreed. Immediate goal is unchanged: give the supervisor a
coherent, evidence-backed thesis package as soon as possible.

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
- [x] Compare the proposed structure with recent relevant literature and the
  completed Vergari thesis; record only defensible differences and gaps.
  (Bounded comparison done against Vergari's six-chapter structure and the
  memory-forensics/rootkit literature already curated in biblio.bib and
  METHODOLOGY.md; no web access was available to verify additional citations.)
- [x] Turn the final structure into a section-level LaTeX outline without
  drafting unsupported results. (Six-chapter graph wired in main.tex; Results
  and Conclusions are structure-only with marked placeholders, no findings.)
- [ ] Obtain human confirmation of the title, research questions, and scope
  before substantial prose rewriting.

Stop gate: any proposed new scenario, metric, framework, or distribution must
be rejected unless the existing four cases cannot answer a research question.

### Phase 2 — Supervisor-ready methodology package

- [x] Rewrite the introduction around the problem, four research questions,
  contributions, and explicit exclusions.
  (tesi/src/chapters/01.introduzione/tesi_introduzione.tex)
- [x] Make Chapter 3 a complete, citation-supported methodology derived from
  `archive/METHODOLOGY.md`, including threats to validity.
  (tesi/src/chapters/3.progettazione/metodologia_tesi.tex)
- [x] Replace the stale implementation structure with the Chapter 4 outline;
  retain only verified current behavior.
  (tesi/src/chapters/4.implementazione/implementazione.tex)
- [x] Add one architecture/acquisition diagram and one case-to-source
  applicability table if they improve comprehension. (Chapter 4 now has a TikZ
  lifecycle/acquisition figure plus four tables: provenance records,
  case-to-source, four-case design comparison, automated-vs-manual boundary.)
- [x] Compile and visually inspect the changed chapters. (Done 2026-08-14:
  pdflatex -> bibtex -> pdflatex x2 from tesi/src, output ../build; 71 pages, no
  undefined references or citations. Encoding fixed: main.tex restored to
  ISO-8859-1 after a stray UTF-8 re-encode; all new chapter files are ASCII with
  accent macros. Rendered pages inspected: ToC, methodology, Ch4 figure/tables,
  all four Results cases, comparative table, conclusions, bibliography.)

This phase is the first writing priority. It makes the real engineering work
legible to the supervisor before all four investigations are complete.

### Phase 3 — Investigate and write one case at a time

Status 2026-08-14: all four frozen cases investigated and written. Each has a
memory (and, for Father, disk) notebook under
`docs/investigations/<scenario>/<run_id>/`, a `runme_case_summary.md` with the
two-table contract, a `COMPARATIVE_RESULTS.md` row, and a Chapter 5 subsection
with an evidence matrix. Volatility 3 (2.28.0) ran against the accepted memory
images using the local ISF `shared/isf/ubuntu_5.15.0-179-generic.json`; the
`derived/` outputs live in the ignored analyst workspace. Memory hashes were
re-verified against each acquisition sidecar before analysis. TTF was not
measured prospectively (offline reprocessing) and is recorded as not measured.

- [x] Father `…_20260813-224442`: disk-led; FS+memory notebooks, summary, row,
  Ch5 exemplar. Key: `/usr/lib/selinux.so.3` inode 74172 = manifest `rk.so` by
  hash, mapped in `sshd` PID 1054 / `sh` PID 1056, backdoor socket to :54321;
  `linux.bash` empty (valid negative); timeline = bounded on-disk log context
  (no full Plaso for this run).
- [x] ptrace `…_20260813-224646`: memory-led; injected anon r-x page
  0x7f5864d1d000 in PID 1044 `victim` (survived), child `sh` 1046, reverse shell
  to :4444; 2 rejected malfind candidates (PID 611, 659).
- [x] Diamorphine `…_20260813-224854`: kernel-memory; module hidden from lsmod
  but present via check_modules/hidden_modules/modxview (offset 0xffffc0b620c0);
  active hook NOT proven (syscall table clean, no ftrace) — recorded as bounded
  negative.
- [x] Bad-BPF `…_20260813-225102`: kernel-memory; hidden worker PID 1053
  (kworker/u8:2 mask, PPID 1, UID 1000, exe /a ≠ argv /usr/bin/uptime), three
  `handle_getdents` tracepoint eBPF programs enumerable, pool socket to :3333.

Original per-case guidance retained below for reference.

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

- [x] Complete the existing descriptive reporting contract. No statistical
  performance metrics, scoring, precision/recall/F1, or cross-case rankings were
  added. Comparative table (Ch5 Table 5.5) and `COMPARATIVE_RESULTS.md` carry
  one row per accepted run.
- [x] Explain source-specific contribution, corroboration, parser-level
  replication, valid negatives, tool failures, and union gain cautiously
  (Ch5 discussion, section 5.7). Note: the memory-dominant cases have no
  cross-source corroboration by construction; the one genuine corroboration is
  Father M05 (disk↔memory inode identity across independent acquisitions).
- [x] Add a direct research-question-to-result mapping (Ch6, section 6.1).
- [x] Write threats to validity (Ch3 section, `\ref{sec:threats_metodologia}`).
- [x] Write Conclusions as answers to the four research questions, followed by
  limitations and bounded future work (Ch6).
- [x] Language check: Results/Conclusions use “osservato”/”stabilito”/”non
  osservato”, not “detected”; no automatic-detection claims.

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
are ready; do not wait for optional work. Original target 2026-08-19 was
**missed** (not delivered); agree a new checkpoint date with the supervisor and
send the package immediately once the Phase 5 gate below is cleared. The package
contains:

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

Status 2026-08-20: the 2026-08-19 supervisor checkpoint was **missed** (see the
schedule-slip note at the top). Since 2026-08-14, effort went to repository
hygiene rather than the writing gate: on branch `public-surface-cleanup` the
reusable Father DFIR investigation layer was added, `GUIDELINES.md` was retired,
`README.md`/`archive/METHODOLOGY.md` pointers were tidied, and the local ICM workspace
(`ai/`) was reorganized (INDEX/STRUCTURE_MAP, migrated plan + guidelines). This
covers only the public-surface subset of Phase 5; the per-chapter
integrity/citation pass and the Phase 6 supervisor package are still not
started.

Revised outstanding, in priority order:

1. **Agree a new supervisor checkpoint date** (the 08-19 one is gone), then
   produce and send the Phase 6 package (compiled PDF + Father exemplar +
   frozen four-run matrix + honest revised schedule).
2. **Clear the Phase 5 gate** before any public push: finish the per-chapter
   claim/citation verification and the credential/personal-data/history scan
   (the public-surface file cleanup is partly done, see above).
3. Human confirmation of the title, four research questions, and scope
   (Phase 1 item still open) remains a blocker for substantial prose rewriting.
4. Optional strengthening (full Plaso timeline for the Father exemplar) stays
   optional and out of the critical path.

Historical status below (2026-08-14), retained for context.

Status 2026-08-14: Chapters 1-6 are drafted and the manuscript compiles to a
71-page PDF with no undefined references or citations. All four frozen cases are
investigated and written with evidence-backed Chapter 5 subsections, case
summaries, notebooks, and comparative rows. Chapters 1-2 were verified free of
obsolete material (no VMware/CAINE/Meterpreter/ftrace/email) and of active
placeholders.

Outstanding, in priority order:

1. Obtain human confirmation of the title, four research questions, and scope
   (Phase 1 item still open) and supervisor review of the Father exemplar and
   methodology.
2. Optional strengthening: regenerate a full Plaso timeline for the Father run
   (currently timeline = bounded on-disk log context) if an independent
   third-source is wanted for the exemplar; and a full disk/timeline pass for the
   three memory-dominant cases is deliberately out of scope, not missing.
3. Phase 5 (authorship/integrity/public-surface gate) and Phase 6 (supervisor
   package, slides) are not started.

Next concrete action: human scope confirmation, then a supervisor read of the
compiled PDF (tesi/build/main.pdf). No new acquisition is required; the four
frozen runs remain the authoritative matrix.

Phase 1 (structure/outline), Phase 2 (Introduction, Methodology, Implementation),
Phase 3 (four cases), and most of Phase 4 (comparative, discussion, conclusions,
threats) are complete in the thesis repository.

Intentionally deferred: new scenarios, broad compatibility experiments,
Diamorphine cleanup, ftrace, Meterpreter, CopyFail, ART, worms, timestomping,
Fedora/SELinux, live response, network capture, automatic detection/matching/
scoring/reconstruction, new metrics, architecture rewrites, and cosmetic CLI
work.
