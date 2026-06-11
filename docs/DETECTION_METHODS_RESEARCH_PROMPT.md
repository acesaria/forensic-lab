# Research prompt: which detection *methods* fit GT-blind Linux disk + memory forensics

This is the higher-level companion to `docs/DETECTION_RESEARCH_PROMPT.md`. That
one sources specific rules and calibrates their specificity; this one decides,
before any rule is written, **which kinds of detection methods are appropriate**
for our goal and which are established and citable. Use it with a web-capable
research assistant or as a literature checklist. Fold the conclusions back per
the closing section.

---

## Prompt

> I am building a reproducible Linux DFIR evaluation lab (MSc thesis). It runs
> ATT&CK-derived attacks on a **vanilla** Ubuntu VM (cloud image; **no auditd, no
> Sysmon-for-Linux, no extra logging**), then acquires a disk image (E01) and a
> memory image (raw) and runs a **ground-truth-blind** detection layer over three
> tools -- **The Sleuth Kit** (bodyfile/timeline), **Plaso** (super-timeline +
> Sigma), **Volatility 3** (memory). Findings are matched to seeded ground truth
> to compute recall/precision. In-scope techniques: T1574.006 (ld.so.preload),
> T1014 (rootkits), T1055 (injection), T1059.004 (shell), T1053 (cron/systemd),
> T1070.003/004 (history/log clearing), T1071 (C2/reverse shell), T1548.001
> (SUID), T1082 (discovery).
>
> Before sourcing individual rules, I need to decide **which KINDS of detection
> methods are appropriate for this goal**, and which are established/citable.
> Please answer rigorously, preferring primary sources (project docs, NIST,
> peer-reviewed DFIR, SANS), and for each method state whether it applies to a
> vanilla dead-disk + memory image (not live telemetry).
>
> 1. **Give the taxonomy of detection methods for dead-disk + memory Linux
>    forensics**, and for each say what it detects, which evidence domain
>    (filesystem / on-disk logs / memory), whether it is a signature, a heuristic,
>    or a temporal/anomaly method, and the canonical tooling:
>    - Log-signature detection (**Sigma**) over the logs a vanilla host actually
>      keeps (auth/sudo/cron/syslog/journal). Which logsource subset is usable
>      WITHOUT auditd/Sysmon, and which Sigma rules are inherently dead without
>      execve telemetry?
>    - Filesystem **timeline analysis** (TSK bodyfile/mactime, Plaso) -- temporal
>      anomaly, window scoping. Cite the standard method (NIST SP 800-86, SANS).
>    - **Forensic artifact-location catalogs** (ForensicArtifacts/artifacts, as
>      consumed by Plaso/GRR/Velociraptor) -- enumerating known persistence paths
>      (ld.so.preload, cron, systemd, rc files, authorized_keys, PAM).
>    - **Content signatures (YARA)** -- see question 3.
>    - **Memory forensics** (Volatility 3) -- pslist/psscan cross-view for hidden
>      processes, malfind, suspicious maps, sockets, in-memory bash history.
>    - **File integrity / baseline differencing** (AIDE, Tripwire, NSRL
>      allowlisting) -- and the methodological caveat of trusting a lab baseline.
>    - **IOC / hash matching.**
>
> 2. **Bash-history forensics on a VANILLA host.** Stock Ubuntu does not set
>    HISTTIMEFORMAT, so `~/.bash_history` is an **undated** command list. Plaso's
>    bash_history parser keys on `#<epoch>` lines and therefore emits nothing for
>    such a file. What is the established way to (a) RECOVER and (b) DETECT
>    malicious shell history in this case -- manual review, memory recovery
>    (Volatility `linux_bash`), mac_robber/timeline of the file mtime, or other?
>    Is "command-line content detection" even a recognized method on a dead disk
>    without execution logs, or is history purely corroborative?
>
> 3. **Is YARA warranted for these techniques?** Be explicit. YARA matches file
>    CONTENT signatures; our techniques are largely behavioral (a config write, a
>    shell, a socket). For which of our artifacts would YARA add real value (the
>    compiled malicious `.so`, known rootkit families for T1014, reverse-shell
>    payloads), and for which is it overkill or non-applicable? Is YARA standard
>    in DFIR triage of a Linux image, and what rulesets are citable (e.g.
>    YARA-Rules, Florian Roth's signature-base) and under what license?
>
> 4. **Per-technique method mapping.** For each in-scope technique, give the
>    PRIMARY established detection method(s) on a vanilla disk+memory image, the
>    rule KIND (Sigma / YARA / Python heuristic / timeline / artifact-catalog),
>    and a citable source.
>
> 5. **What NOT to do.** Which methods would bias or mislead this evaluation --
>    e.g. expecting process_creation Sigma to fire without telemetry, or leaning
>    entirely on baseline differencing in a lab where we built the baseline?
>
> Deliver a **method-selection matrix**: method | what it detects | evidence
> domain | established? (cite) | applies to our vanilla setup? | techniques it
> covers | tool in our stack (TSK/Plaso/Vol3/YARA) | false-positive profile |
> verdict (adopt / optional / skip). Then say how each adopted method folds back:
> Sigma rules into `config/rules/`, memory/filesystem heuristics into `detect/`,
> a YARA ruleset into `config/rules/yara` (already a configured slot), and which
> methods are explicitly out of scope.

---

## Anchor sources to verify first

- **Sigma** -- `github.com/SigmaHQ/sigma`, the specification (logsource/field
  modifiers), and which `logsource` products/services map to vanilla Linux logs.
- **ForensicArtifacts/artifacts** -- `github.com/ForensicArtifacts/artifacts`
  (the catalog Plaso/GRR/Velociraptor consume) for persistence-location coverage.
- **Volatility 3** -- `volatility3.readthedocs.io`; pslist-vs-psscan cross-view,
  malfind, `linux.bash`, sockets.
- **The Sleuth Kit / Plaso** docs -- bodyfile/mactime and the bash_history parser
  timestamp requirement.
- **YARA** -- `virustotal.github.io/yara`; citable rulesets (YARA-Rules,
  Neo23x0/signature-base) and their licenses.
- **NIST SP 800-86** and **SANS DFIR** -- timeline analysis and known-good
  baselining methodology; **AIDE/Tripwire** for file integrity.
- **MITRE ATT&CK** technique pages for the in-scope IDs.

## How to fold results back into this repo

- Methods that are log-signatures over vanilla logs -> Sigma rules under
  `orchestrator/evaluation/config/rules/` (must pass the rule-leakage lint).
- Memory/filesystem/artifact-catalog methods without a Sigma equivalent ->
  Python detectors under `orchestrator/evaluation/detect/` (GT-blind, emit
  `Finding`s, never read ground truth).
- Content-signature methods, if adopted -> a YARA ruleset under
  `orchestrator/evaluation/config/rules/yara` (already a configured slot in
  `pipeline.yaml`), scanning icat-extracted files.
- Record each adopted method's rationale next to its rule/detector, citing the
  source, so examiners can trace the design. Then run
  `docs/DETECTION_RESEARCH_PROMPT.md` to source the specific rules for the
  methods chosen here.
