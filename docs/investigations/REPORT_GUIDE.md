# Investigation report guide

How to write the per-run investigation report under `docs/investigations/`.
The report is an educational experiment record, not a professional
incident-response notebook. Target 1,200–1,800 words of prose, at most five
main sections.

## Where material belongs

Three layers, strictly ordered:

1. **Immutable outputs** (run directory): acquired images, raw TSK/Plaso/
   Volatility exports, manifests, command logs, provenance sidecars. Never
   edited after acquisition; everything else cites them.
2. **Analyst workspace** (`shared/investigations/`): may contain accepted
   derived or reprocessed outputs with their own commands, versions, hashes,
   statuses and provenance, alongside analyst worklogs, diagnostics and
   retained historical attempts (command ledgers, retries, timing files,
   benchmark detail, dead ends). Original experimental outputs remain
   immutable.
3. **The report** (`docs/investigations/`): what was found, what it means,
   what it does not mean, and where to verify it. If a detail does not change
   interpretation, it goes in the worklog, not the report.

## Scenario validation vs. forensic discovery

Keep them separated and labelled. Scenario validation (manifest, command log)
proves the controlled compromise executed as intended — it is ground truth,
summarised in one small table. Ground truth may define the frozen atomic
inventory, and disclosed ground-truth-guided manual triage is permitted; but
every forensic observation must still be supported by an accepted evidence
locator, and ground-truth-guided work must never be described as blind
discovery. State the discovery path (e.g. "from `/etc/ld.so.preload`
outward", "from an anomalous mapping"). No forensic conclusion may rest on
validation facts alone.

## Negative observations

Report a negative only when it changes interpretation (an empty
`linux.bash`, a missing filestat row, a parser that produced nothing), and
scope it precisely: say what the tool did not produce and why, never "no
evidence exists". Explain unexpected negatives before accepting them — the
cause may be a format precondition, a filter defect, or a tool limitation,
and each reads differently. Do not silently "fix" an unexpected negative by
adding parsers, filters, or scenario-specific rules; a change is justified
only by a demonstrated, measured, scenario-blind gap.

## Evidence locators

One compact locator per finding, enough to re-find it without rerunning
anything. Each locator identifies the accepted output or reprocessing
revision it points into, plus the row, line, PID, inode or object needed to
find it: inode + bodyfile row for filesystem, JSONL line number for
timeline, plugin + PID/object for memory. Full command records and hashes
stay in the worklog and `SHA256SUMS`.

## Structure and limits

- At most five main sections: case/evidence, scenario validation, findings
  by source, cross-source reconstruction, limitations/conclusion.
- One small scenario-validation table, one compact cross-source matrix, and
  one short temporal sequence grouped into phases. No other large tables.
- State each conclusion once, where it belongs.
- Omit: command ledgers, derived-output inventories, routine failures and
  retries, repeated qualifications, and benchmark detail already in the
  worklog.

## The timeline stays complete

The Plaso store and the canonical JSONL export are produced with no
scenario-time restriction and no knowledge of ground truth, and they stay
that way — restricting them would bake the answer into the evidence. Note
that psort deduplicates by default, so the store event count and the JSONL
line count legitimately differ; report both.

For triage, a **derived analyst view** may be exported with an explicit
psort date filter around the scenario interval plus a small stated buffer:

    psort -q -o json_line -w <view>.jsonl <store> \
      "date >= datetime('<start>') and date <= datetime('<end>')"

Save it in the investigation workspace beside a provenance record (exact
expression, bounds, buffer, timezone provenance, complete and filtered
counts), never overwriting another output. Describe it as
ground-truth-guided manual triage, not blind detection. The report's
timeline section states the complete event count, the view's interval,
buffer and count, and that the complete outputs were preserved.

## Coverage metrics

Simple, professor-facing, descriptive. Never precision/recall/F1, weighted
scores, or automatic expectation matching. The metric describes what manual
post-mortem recovered — not detection accuracy.

- **Freeze the inventory first.** Every run or variant freezes its own atomic
  target list *before* mapping any evidence, and records that it was frozen.
  Existing base targets may be reused only when still applicable; cleanup- and
  prevention-specific targets must be added before mapping. Comparability is
  never preserved by forcing an artificial denominator. Each target is one
  minimal, independent ground-truth fact derived only from scenario design,
  manifest and command log — never from what a tool happened to return. Byte
  equality, extra timestamps, multiple VMAs of one mapping and multiple FDs of
  one socket are supporting evidence, not separate targets.
- **Applicability per source.** Decide from experimental design and source
  capability, not from tool success, which targets each source could
  reasonably observe. Use `n/a` when a source cannot (e.g. a shell that exited
  before capture, or a config file whose only memory trace is a separate
  mapping target). Applicability sets each source's denominator.
- **Found and partial.** Found = at least one accepted forensic locator
  supports the target's central identity/occurrence. Scenario-validation and
  command-log facts justify expectations but are never locators. A timeline
  `filestat` that proves occurrence/modification but not file contents is
  `partial` and may count as Found with a stated limitation and conservative
  per-target QoR.
- **DR = Found / Total applicable**, per source, labelled *manual
  evidence-recovery coverage*. Compute **union coverage** once — unique targets
  found in ≥1 source over unique targets expected in ≥1 source. Never average
  or weight the per-source rates. High coverage is an observed result, not a
  pass/acceptance condition; low coverage is a valid result.
- **FP** is a count of candidates a candidate-generating tool/query surfaced as
  suspicious and the investigation then rejected as unrelated (cite each one's
  locator and rejection reason). `0` means candidate generation was applied and
  no rejected unrelated candidates remain; `N/A` means no candidate-generating
  method was applied (broad enumeration rows and targeted lookups generate no
  candidates).
- **TTD** is prospective wall-clock from starting a source to its first
  supported locator. If not recorded prospectively, report `not measured`;
  never reconstruct it from attack, acquisition, event or tool timestamps.
- **QoR** is `High`, `Medium`, `Low`, or `N/A` only, never numericised or
  averaged; no aggregate union QoR is assigned (the union row is `N/A`).

Put one auditable target-by-source table (target, per-source status, accepted
locators, partial limitations) and one summary row-set
(`Source | Found / Total | Coverage (DR) | FP | TTD | QoR`) in the report's
cross-source section, and append the summary rows to
`COMPARATIVE_RESULTS.md`.
