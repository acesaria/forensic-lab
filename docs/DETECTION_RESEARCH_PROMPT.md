# Research prompt: sourcing trusted Linux DFIR detection heuristics

Use the prompt below (with a web-capable research assistant, or as a literature
checklist) to find authoritative, citable sources for the detection rules and
heuristics in `orchestrator/evaluation/detect/`. The goal is twofold: (1) import
or adapt vetted rules where licensing allows, and (2) calibrate *how specific*
each heuristic should be (which fields, which thresholds, what false-positive
controls) against community and academic standards, so the thesis can justify
each detector's design rather than inventing it.

---

## Prompt

> I am building a reproducible Linux digital-forensics evaluation lab for an MSc
> thesis. It runs ATT&CK-derived attacks on disposable VMs, acquires disk (E01)
> and memory (raw) images, and runs three open-source tools — **The Sleuth Kit**
> (bodyfile/timeline), **Plaso** (super-timeline + Sigma), and **Volatility 3**
> (memory) — through a *ground-truth-blind* detection layer whose findings are
> then matched against seeded ground truth to compute recall/precision.
>
> I need **trusted, citable sources** for the detection heuristics, and guidance
> on the **level of specificity** these heuristics normally have. For each item
> below, give: the canonical source(s) with links; whether rules can be imported
> directly (and under what license); the typical field set / thresholds used; and
> the known false-positive pitfalls and how practitioners control them.
>
> 1. **Sigma rules for Linux** (timeline/log detection): point me to the
>    authoritative SigmaHQ Linux ruleset and any high-quality third-party packs
>    (Elastic detection-rules, Splunk Security Content, Sigma community). For my
>    in-scope techniques specifically: T1574.006 (LD_PRELOAD / `ld.so.preload`),
>    T1059.004 (shell execution from world-writable temp dirs), T1053 (cron/
>    systemd persistence), T1070.003/004 (history/log clearing), T1071 (C2 /
>    reverse shell). What `logsource` and fields do these rules key on, and how
>    do they avoid firing on benign filesystem metadata?
>
> 2. **Volatility 3 memory heuristics**: what are the canonical/community ways to
>    detect, with their known false-positive behavior — hidden processes
>    (pslist vs psscan/pslist cross-view, psxview-style; how to exclude exited or
>    kernel-thread noise), injected code (malfind), suspicious memory mappings
>    from temp paths, deleted backing executables, and suspicious network sockets
>    (sockstat/netstat)? What distinguishes a true "hidden process" from pool
>    scan noise in practice?
>
> 3. **Filesystem / timeline heuristics (TSK + timeline analysis)**: what is the
>    standard, defensible way to flag suspicious file creation in `/tmp`,
>    `/var/tmp`, `/dev/shm`; deleted-but-recoverable artifacts; and timestamp
>    anomalies / timestomping (`crtime` vs `mtime`)? Specifically: on a freshly
>    built cloud image, `crtime > mtime` is extremely common (files unpacked with
>    preserved mtimes) — how do practitioners scope or threshold timestomp
>    detection so it isn't a near-universal false positive?
>
> 4. **Reverse-shell / outbound-C2 detection from a memory image**: on an
>    isolated lab network the C2 endpoint is a private (RFC1918) address, so an
>    "external IP" rule misses it. What behavioral signals do practitioners use
>    instead (outbound connection from an ephemeral local port to a non-service
>    remote port, owning process anomalies, etc.)?
>
> 5. **Specificity and false-positive control as a discipline**: what is the
>    accepted guidance on detector specificity vs. noise — e.g. known-good
>    baselining / allowlisting (NIST SP 800-86, SANS DFIR), the trade-off between
>    behavioral (class-level) and instance-level signatures, and how detection
>    engineering frameworks (Sigma, MITRE ATT&CK, Elastic, the DFIR Report)
>    describe "good" rule precision?
>
> Please return a **table**: source | what to import or adapt | license | typical
> specificity level (fields/thresholds) | FP pitfalls. Prefer primary sources
> (project repos and docs, NIST, peer-reviewed DFIR papers) over blog posts, and
> flag anything whose license forbids redistribution into my repo.

---

## Anchor sources to verify first

These are the load-bearing references the prompt should confirm and expand on;
they map directly onto the detectors in this repo.

- **SigmaHQ** — `github.com/SigmaHQ/sigma` (`rules/linux/`), Sigma specification
  (logsource/field-modifier semantics). License: DRL (check redistribution).
- **Elastic detection-rules** — `github.com/elastic/detection-rules` (Linux).
- **Volatility 3** docs + community plugins — `volatility3.readthedocs.io`;
  background on psxview / pslist-vs-psscan cross-view for hidden processes.
- **The Sleuth Kit** bodyfile format + `mactime`; **Plaso/log2timeline** docs.
- **MITRE ATT&CK** technique pages for the in-scope IDs (T1574.006, T1014,
  T1055, T1059.004, T1053, T1070.003/004, T1071).
- **NIST SP 800-86** (forensic technique integration) and **SANS DFIR** posters
  for baselining / known-good methodology.
- **The DFIR Report** for real-world reverse-shell / persistence detail.

## How to fold results back into this repo

- Sigma rules that pass the **rule-leakage lint** (no instance constants —
  behavioral classes only) can drop into
  `orchestrator/evaluation/config/rules/`.
- Memory/filesystem heuristics without a Sigma equivalent become Python
  detectors under `orchestrator/evaluation/detect/`, mirroring the existing
  `*_heuristics.py` shape (GT-blind, emit `Finding`s, never read ground truth).
- Record each detector's *specificity rationale* (the "why this threshold" from
  the sources) next to the rule, so examiners can trace the design to a citation.
