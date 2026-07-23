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
2. **Private worklogs** (investigation workspace, `shared/investigations/`):
   command ledgers, retries, timing files, benchmark detail, derived working
   copies, diagnostic outputs, dead ends. Anything an analyst needed while
   working but a reader does not.
3. **The report** (`docs/investigations/`): what was found, what it means,
   what it does not mean, and where to verify it. If a detail does not change
   interpretation, it goes in the worklog, not the report.

## Scenario validation vs. forensic discovery

Keep them separated and labelled. Scenario validation (manifest, command log)
proves the controlled compromise executed as intended — it is ground truth,
summarised in one small table. Forensic findings must be discoverable from
the evidence alone; state the discovery path (e.g. "from `/etc/ld.so.preload`
outward", "from an anomalous mapping") so the reader can see no ground truth
leaked into it. No forensic conclusion may rest on validation facts alone.

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
anything: inode + bodyfile row for filesystem, JSONL line number for
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
