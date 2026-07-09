# Detection Rule Provenance and Evidence-Strength Audit

> Historical/partially stale: verify against TODO.md, METHODOLOGY.md,
> docs/repo_map.md, and latest metrics before using.

Date: 2026-06-27
Scope: GT-blind detector rules under `detectors/rules/**` and their semantics in
`detectors/engine.py`. This is a review document. No rule behavior is changed
here.

Reference inputs: `detectors/rules/README.md`, `detectors/engine.py`,
`docs/metrics_methodology.md`, `docs/canonical_pipeline_review.md`,
`docs/canonical_pipeline_schema.md`, `docs/architecture/canonical_pipeline_gap_analysis.md`,
`AGENTS.md`, `PROJECT_CONTEXT.md`, and the Father expectations in
`scenarios/scenarios/userland_father_ldpreload/expected_observables.yml`.

## 1. Executive Verdict

**Are the current rules acceptable as candidate-evidence rules?**
Yes, with conditions. They are legitimate GT-blind *candidate generators* feeding
a GT-aware instance matcher. The pipeline never lets a rule decide reconstruction
on its own; strong reconstruction is decided by `MatchResult` instance-level
matches against `ArtifactExpectation` paths. In that role the rule set is
defensible, **once two problems are fixed**: scenario-flavored token leakage
(`father`) and the silent contribution of over-broad rules to the candidate
stream.

**Are they acceptable as final / standalone detection rules?**
No. They must not be presented as "detections". On the cached Father run the
candidate stream is ~255 claims for 10 expected artifacts (candidate precision
~0.04). Two rules (`suspicious_temp_path`, `userland_persistence`) produce 176 of
255 candidates and fire almost entirely on stock OS content (every `/tmp` file,
every baseline systemd unit). A rule that flags the whole baseline is a triage
filter, not a detection. The thesis must call these **post-mortem candidate
evidence**, not detections.

**What must change before thesis reporting?**

1. Remove the `father` token from `suspicious_shared_object.yml` and
   `process_library_correlation.yml`. A handcrafted rule that contains the
   scenario's own codename is not a methodology; it is an answer key. The strong
   Father matches do **not** depend on it (they come from temp-path / PID-correlation
   predicates plus GT instance matching), so removal should not lower strong
   recall.
2. Stop over-broad rules from being read as reconstruction signal. The new
   reconstruction-over-expectations metric already protects the *headline*
   numbers, but the rules themselves should be labelled `triage_only` so the
   report and any future claim-precision work treat them as diagnostic.
3. Document each rule's standard basis (ATT&CK technique + post-mortem evidence
   source) and its baseline dependency. Several rules are only defensible *with*
   baseline comparison, which is not yet implemented.
4. Acknowledge one coincidence honestly: `ld_preload_configuration` carries a
   bare `preload` token, and the lab working directory is named
   `father_ldpreload`. The substring `preload` therefore matches every file under
   that directory. Some "strong" file reconstructions are carried by this
   accidental substring plus exact-path GT matching, not by genuine preload-config
   detection. This is acceptable for candidate generation but must not be sold as
   "the rule detected the preload configuration".

## 2. Rule Inventory

Source type: disk / memory / timeline / baseline / mixed (declared `source_types`).
Evidence strength: `strong_candidate` / `support_only` / `triage_only` /
`invalid_or_leaky`. Thesis use: strong-reconstruction-capable / class-only-context
/ diagnostic-only / remove-or-deprecate.

| rule id | file | source | current behavior | standard basis / inspiration | post-mortem applicability | evidence strength | thesis use | recommended action |
|---|---|---|---|---|---|---|---|---|
| `flab.filesystem.ld_preload_configuration` | `filesystem/ld_preload_configuration.yml` | disk, timeline | emits if `artifact_class==preload_configuration` OR path/value contains `ld.so.preload`/`LD_PRELOAD`/`preload`; reclasses to `preload_configuration` | T1574.006 dynamic linker hijack; classic DFIR inspection of `/etc/ld.so.preload` | High — config is persistent on disk and in timeline | strong_candidate (with leaky `preload` substring) | strong-reconstruction-capable | keep `ld.so.preload`/`LD_PRELOAD` + artifact_class; drop bare `preload`; require baseline (non-empty/modified) |
| `flab.filesystem.suspicious_shared_object` | `filesystem/suspicious_shared_object.yml` | disk, timeline | flags `.so`/`.so.*` under `/tmp`,`/var/tmp`,`/dev/shm` OR tokens `preload`,`father`,`rootkit` | T1574.006 / T1036; `.so` staged in world-writable dir | High on disk; stronger with memory map corroboration | strong_candidate; token list `invalid_or_leaky` | strong-reconstruction-capable | **remove `father`**; reconsider `rootkit`; keep temp-path+`.so`; add baseline `new_vs_baseline` |
| `flab.filesystem.suspicious_temp_path` | `filesystem/suspicious_temp_path.yml` | disk, timeline | flags any `file`/`deleted_file_candidate` under temp prefixes; exec/deleted only *raises confidence*, not required | T1105 / T1059.004 world-writable staging | Low precision — flags every temp file | triage_only (too broad: 95/255 Father claims) | diagnostic-only | require executable-mode OR deleted OR baseline-new; otherwise diagnostic |
| `flab.filesystem.userland_persistence` | `filesystem/userland_persistence.yml` | disk, timeline | flags cron / systemd unit paths (`.service`,`.timer`,…) | T1053.003 cron, T1543.002/003 systemd persistence | Sound concept, but fires on stock units | triage_only (81/255 Father claims, 0 TP) | diagnostic-only | require baseline new/changed unit; not part of Father reconstruction |
| `flab.filesystem.deleted_artifact_cleanup` | `filesystem/deleted_artifact_cleanup.yml` | disk, timeline | flags any `deleted_file_candidate` not explicitly `deleted==False` | T1070.004 indicator removal | Moderate — deleted entries are common | support_only | class-only-context | keep as support; instance-match on path + corroborate with timeline delete event |
| `flab.filesystem.ebpf_kernel_like_object` | `filesystem/ebpf_kernel_like_object.yml` | disk, timeline | flags paths containing `bpf`/`ebpf`/`/sys/fs/bpf`; confidence 0.35, benign scope | T1014 / T1547 (eBPF rootkit telemetry) | N/A to Father (future scenario; 0 Father claims) | triage_only | diagnostic-only | move to a future eBPF rule pack or keep low-confidence; not a Father rule |
| `flab.memory.process_from_unusual_path` | `memory/process_from_unusual_path.yml` | memory | flags memory process/file backed by temp path or `(deleted)` marker | T1036 masquerading; deleted-binary-still-running (memory forensics staple) | High when it fires; 0 Father claims (sleep runs from `/usr/bin`) | strong_candidate (concept) | strong-reconstruction-capable | keep; defensible post-mortem adaptation; no Father change |
| `flab.memory.process_library_correlation` | `memory/process_library_correlation.yml` | memory | correlates process+library sharing PID where lib path under temp prefix OR tokens `preload`,`father`,`rootkit`; `require_pid` | T1574.006; RAM confirmation that the suspect `.so` is mapped into a live process | High — strongest Father signal (RAM ↔ disk corroboration) | strong_candidate; token list `invalid_or_leaky` | strong-reconstruction-capable | **remove `father`**; keep PID correlation + temp prefix |
| `flab.memory.process_socket_correlation` | `memory/process_socket_correlation.yml` | memory | correlates process+socket sharing PID; `_is_remote_connection` rejects loopback/unix/netlink/listening; `require_pid` | T1071 / T1059.004 C2 channel | Well-guarded; but Father has no C2 expectation | strong_candidate (concept) / for Father: triage_only | diagnostic-only (for Father) | keep guarded logic; tighten class matching so it does not class-match the benign `process` expectation |
| `flab.timeline.suspicious_shell_history` | `timeline/suspicious_shell_history.yml` | memory, timeline, disk | flags shell/log lines containing tokens `curl`,`wget`,`bash`,`sh -c`,`chmod`,`rm -f`,`crontab`,`systemctl`,`ld.so.preload` | T1059.004 / classic shell-history IOC grep | Broad keyword grep; 0 Father claims in current run | triage_only | diagnostic-only | narrow tokens (drop `bash`/`sh -c`/`systemctl`/`chmod`); treat as triage/support |

### Per-rule notes worth flagging to the committee

- **`ld_preload_configuration` substring coincidence.** `preload` matches
  `father_ldpreload` in the lab path, so this rule emits a `preload_configuration`
  candidate for *every* file in the working directory (≈69 claims). The
  `hiding-marker` file expectation is reconstructed through one of these claims by
  exact-path GT matching. The candidate is not wrong, but the rule did not
  "recognise a preload config" — it matched a directory name. Drop the bare token.
- **Broad rules carry the headline by accident.** The 4 generic `file`
  expectations (source-file, source-metadata, upstream-archive, hiding-marker)
  become strong instance matches because a broad rule (`suspicious_temp_path` /
  `ld_preload_configuration`) happened to emit a candidate whose path equals the
  expected path. The *strength* is supplied by the GT instance matcher, not by
  rule specificity. This is exactly why the rules are candidate evidence, not
  detections, and why candidate precision is the wrong headline number.
- **`process_socket_correlation` false comfort.** It is the best-engineered rule
  (real routable-peer guard), yet on Father it only produces a misleading
  class-only match against the benign `sleep` process. The fix is matcher class
  compatibility, not the rule.

## 3. Father_LDPRELOAD Rule Critique

Mapping the expected attack behavior to current logic:

| expected behavior | current rule(s) | evidence today | gap |
|---|---|---|---|
| `/etc/ld.so.preload` (or lab preload config) modified / non-empty | `ld_preload_configuration` | matches lab preload config by artifact_class — **strong candidate** | cannot assert "modified/non-empty vs baseline" without baseline diff |
| referenced `.so` exists on disk | `suspicious_shared_object` | `.so` under lab temp dir — **support/strong candidate** | existence ≠ maliciousness without baseline |
| referenced `.so` is non-baseline | none | **not implemented** | needs baseline path/hash inventory |
| process memory maps the same `.so` | `process_library_correlation` | RAM map of the `.so` into the live process — **strong corroboration** | none of substance; remove `father` token |
| timeline shows modify/create events | filesystem rules with `timeline` source | timeline create/modify of lab files — **support** | broad; many baseline timeline events too |

**Which rules are good (strong for Father):** `process_library_correlation`
(RAM↔disk corroboration of the mapped `.so` — the single strongest signal),
`suspicious_shared_object` temp-path branch, and `ld_preload_configuration` via
the `preload_configuration` artifact class.

**Which are too broad:** `suspicious_temp_path` (flags every `/tmp` file),
`userland_persistence` (flags every baseline systemd unit; 0 TP / 81 FP),
`suspicious_shell_history` (keyword grep), `deleted_artifact_cleanup` (every
deleted entry).

**Which should require baseline:** `suspicious_shared_object` (non-baseline
`.so`), `userland_persistence` (new/changed unit), `suspicious_temp_path`
(new file), and `ld_preload_configuration` (config non-empty/modified relative to
a baseline empty/absent config).

**Which should require memory/timeline corroboration to count as strong:**
shared-object existence should be corroborated by `process_library_correlation`
(memory) and by a timeline create/modify event before it is presented as strong
reconstruction rather than mere presence.

**Which should be removed or moved to scenario ground truth / fixtures:** the
`father` token in `suspicious_shared_object` and `process_library_correlation`.
Any Father-specific string belongs in `expected_observables.yml`, the reference
context, or detector test fixtures — never in a production rule pack. `rootkit`
should also be reconsidered as scenario-flavored.

**Strong vs support vs triage for Father:**
- Strong evidence: `.so` present on disk **and** mapped in RAM by the benign
  process (disk+memory corroboration); the preload configuration artifact.
- Support evidence: deleted cleanup marker, the `LD_PRELOAD` shell/log line,
  timeline create/modify events.
- Weak triage: generic `/tmp` files, baseline systemd units, shell-history
  keyword hits.

## 4. Standard-Rule Discussion

**Sigma.** Useful as a reference taxonomy and for ATT&CK mapping, but not blindly
importable. The large majority of Linux Sigma rules target `process_creation`,
auditd, or syslog **live telemetry** that this post-mortem pipeline does not
collect. Sigma can legitimately apply only where Plaso/timeline or on-disk logs
expose equivalent events (e.g. recovered auditd/syslog/shell history). Importing
Linux Sigma wholesale would silently assume an event-logging substrate we do not
have. Sigma's value here is conceptual (rule logic, field names, technique
coverage), and at most directly usable for the log/timeline-derived slice — never
for disk/RAM artifact reconstruction.

**YARA.** Useful for file/memory **signature support**: confirming that a carved
`.so` or a memory region matches a known string/pattern. But a YARA hit on a `.so`
does not reconstruct LD_PRELOAD persistence by itself — it asserts content
identity, not the structural relationship `ld.so.preload → .so → process map`.
YARA therefore belongs as corroborating/support evidence composed *with* the
structural reconstruction, not as a replacement for the correlation rules.

**Custom post-mortem adaptations.** Acceptable, and arguably necessary for a
disk+RAM+timeline framework, **iff** each rule explicitly states: (a) the known
technique it adapts (ATT&CK id — already present), (b) the post-mortem evidence
source it reads, and (c) why the live-telemetry detection is unavailable
post-mortem. The current rules satisfy (a) but under-document (b)/(c) and hide
their baseline dependency. The gap is documentation and labelling, not (mostly)
behavior. A custom rule mapped to T1574.006 over disk+RAM artifacts is defensible;
a custom rule that contains the scenario codename is not.

## 5. Next Implementation Recommendations (3, in order)

1. **De-leak the rule packs.** Remove the `father` token (and reconsider
   `rootkit`) from `suspicious_shared_object.yml` and
   `process_library_correlation.yml`; relocate any Father-specific strings to
   fixtures / GT. Re-run the cached Father matcher and confirm strong-instance
   recall is unchanged (it should be — those matches come from temp-path / PID
   correlation + GT instance matching). Smallest change, highest thesis-integrity
   payoff. (This is the "generic rule cleanup" step of the PROJECT_CONTEXT
   delivery sequence.)

2. **Label rule evidence strength (metadata only, no matching change).** Add a
   non-behavioral `evidence_strength` field (`strong_candidate` / `support_only` /
   `triage_only`) to each rule YAML and surface it in `score_report.md`, so
   `suspicious_temp_path`, `userland_persistence`, and `suspicious_shell_history`
   are shown as diagnostic-only and can never be mistaken for headline
   reconstruction contributors.

3. **Introduce one baseline disk diff channel.** Compare the run's disk/bodyfile
   path inventory against a cached clean-baseline inventory and annotate
   `ToolFinding` records as `new_vs_baseline` (no new tools, no Sigma/YARA). Then
   the temp-path / shared-object / persistence rules can gate "strong" on
   baseline-new candidates, which is the single largest precision win and the
   prerequisite the Father critique keeps returning to. (This is step 2 of the
   delivery sequence; it should follow, not precede, the cleanup in #1.)
