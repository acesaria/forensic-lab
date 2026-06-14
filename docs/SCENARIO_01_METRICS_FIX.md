# Scenario 01 (LD_PRELOAD) — confusion-matrix correction

Scenario 01 stages an LD_PRELOAD persistence plus a reverse shell. In the
**no-cleanup** variant every primary artifact is still on the medium, so the
correct result is **recall = 1.0** (each ground-truth event is recoverable) and,
once benign noise is accounted for, **precision = 1.0**. The pipeline previously
under-reported both. The cause was four independent logic defects, not the
numbers; each was fixed by a methodological change, never by tuning a threshold
to a target.

The fixture that exercises this end to end is
`orchestrator/evaluation/tests/fixtures/scenario_01/` (the six seeded GT events,
plus a GT-blind finding set with three cross-channel preload corroborators and
one benign known-good hit), locked by
`orchestrator/evaluation/tests/test_scenario_01_golden.py` and the detector unit
tests in `tests/test_detectors.py`.

## Before / after (no-cleanup, end to end)

| metric | before | after |
| --- | --- | --- |
| recall | 0.50 (3/6 events) | **1.00 (6/6 events)** |
| precision | 0.43 (3/7) | **1.00 (9/9 claims)** |
| tp / fp / fn | 3 / 4 / 3 | 6 / 0 / 0 |
| false negatives | G1 (`/tmp/T1082.txt`), G2 (`/etc/ld.so.preload`), G6 (FIFO) | none |
| false positives | 3 preload channels + benign malfind | none (folded / reclassified) |
| uniq tsk / plaso / vol3 | — | 3 / 0 / 2 |

"before" is the current detectors feeding the current matcher; "after" is the
corrected detectors feeding the corrected matcher. The recall loss is a detector
gap; the precision loss is a matcher/metrics gap. The two halves are validated at
their own layers (raw-bodyfile detector tests; the golden matcher fixture).

## Root causes (file:line at time of fix)

1. **Precision mixed units.** `metrics/compute.py` computed
   `precision = len(tp) / (len(tp) + len(fp))`: the numerator counted GT events
   while `fp` counted finding *clusters*. Once corroborators fold into a TP, the
   extra true claims silently vanish from the numerator while every false claim
   still counts one. Fixed: count both sides in claim (cluster) units.
2. **Corroboration anchored on entity identity.** `match/matcher.py` set the
   `compat` flag, and therefore attached a leftover cluster to a matched GT, only
   where `entities_match` had already passed. A corroborator that observes the
   same action through a *different* entity (an `auth.log` line about the preload
   write carries a process entity, not the `/etc/ld.so.preload` path) never
   attached and fell through to FP. Fixed: corroboration is anchored on
   `technique` within a window, through a different entity channel.
3. **No known-good allowlist.** `match/matcher.py` split leftover clusters into
   FP vs background solely by the `scope_margin_s` time window. A benign-but-real
   detector hit inside the window (`vol3 malfind` on `networkd-dispatcher`, a
   documented stock-Ubuntu false positive) was therefore a FP. Fixed: a
   `known_good` allowlist routes such clusters to background noise.
4. **Detector under-coverage.** `detect/tsk_heuristics.py`
   `detect_temp_or_persistence_exec` gated temp files on
   `_is_regular_file AND _is_executable`, so a non-exec discovery drop and the
   reverse-shell FIFO were skipped; `_PERSIST_PREFIXES` omitted
   `/etc/ld.so.preload`, so the preload write was never flagged as persistence.
   Fixed: any non-directory created in a temp dir within the case window is a
   `file_created` (the exec bit becomes a confidence/technique signal, not a
   gate), and `/etc/ld.so.preload` is a persistence location. The GT-blind
   boundary is unchanged — the detector still reads no manifest and no scenario.

## Precision-unit decision

Recall and precision answer different questions and are reported in different,
internally-consistent units:

- **recall = matched_GT_events / N** — per expected event. Recall asks "how many
  of the things that happened did we recover", so the denominator must be the
  count of ground-truth events.
- **precision = true_claim_clusters / (true_claim_clusters + in_scope_fp_clusters)**
  — per claim. Precision asks "of the distinct claims the tooling made in scope,
  how many were true". A *claim* is a deduplicated finding cluster.
  `true_claim_clusters` is every cluster folded into a matched GT (primary +
  corroborators); `in_scope_fp_clusters` is `matches.fp`.

When a TP carries a single cluster (no corroboration) `true_claims == len(tp)`
and the formula reduces to the old ratio, so the existing `fixture-basic` golden
numbers (precision 0.714) are unchanged. The choice is recorded as
`precision_definition: claim_clusters` in `matching.yaml` (hashed into every
output) and surfaced in `report.md` as `N/N claims`.

## New `matching.yaml` keys

- `corroboration_window_s: 120` — a leftover cluster folds into a matched GT when
  it shares the technique and lands within this window, through a different
  entity channel. Anchored on technique, not entity identity.
- `precision_definition: claim_clusters` — records the precision unit above.
- `known_good:` — documented benign baselines (detector + optional entity
  substring) scored as background noise instead of FP. A benign baseline is never
  a planted instance value, so it is not a circularity leak.
