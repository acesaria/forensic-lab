# Refactor: detector -> matcher -> metrics

Status: completed. The detector -> matcher -> metrics pipeline lives under
`orchestrator/evaluation/`; the original GT-lookup path
(`orchestrator/forensics/{artifact_specs,evaluator,metrics}.py` and
`orchestrator/forensics/ioc_detector/`) has been deleted, the duplicated time
helper is unified into `orchestrator/forensics/timeutil.py`, the two CLIs are
converged on the repo-root `cli.py` (`score`/`pipeline`/`verify` subcommands),
and the dangling `scripts/report_metrics.py` is retired. The dependency
direction is one-way: `core -> evaluation -> forensics`.

This document records how the old evaluation code maps onto that architecture
and the circularity leaks the refactor removed.

## Why the current design is circular

The current pipeline resolves ground-truth values INTO the detection queries
before any tool output is searched:

1. `artifact_specs.py` declares specs whose `query` values are
   `{"$ref": "<step>.<locator_key>"}` placeholders.
2. `orchestrator._evaluate_run_iocs()` calls `resolve_specs(specs, ground_truth)`,
   substituting the exact planted path/port/value the scenario recorded.
3. `ioc_detector/{sleuthkit,volatility,plaso}.py` then searches each tool's
   output for that exact value.

Because the thing searched for IS the ground truth, recall is trivially inflated
(a tool either "finds" the planted value or not) and false positives are
undefined (nothing that is not ground truth is ever scored). The new design
splits the layer that decides "this is suspicious" (GT-blind `detect/`) from the
layer that decides "this matches a seeded event" (GT-aware `match/`).

## Module mapping (existing -> target)

| Existing module | Target layer | Disposition |
| --- | --- | --- |
| `orchestrator/attacks/scenario_01_ldpreload.py`, `helpers.py` | `orchestrator/evaluation/scenario/` | Keep semantics; add `gt_manifest.json` emission + seeded parameter randomization. Existing `ground_truth["steps"]` shape is wrapped, not replaced. |
| `orchestrator/forensics/plaso_runner.py` | `orchestrator/evaluation/extract/plaso.py` | Reused as-is for `log2timeline`/`psort -o json_line`. |
| `orchestrator/forensics/vol_runner.py` | `orchestrator/evaluation/extract/vol3.py` | Reused for pinned-plugin JSON output. |
| `orchestrator/forensics/sleuth_runner.py` | `orchestrator/evaluation/extract/tsk.py` | Reused for `fls -m` bodyfile (plus `icat`/`istat`). |
| `orchestrator/forensics/ioc_detector/{volatility,plaso,sleuthkit}.py` | **split** | The *heuristic* halves (what looks suspicious) move to `detect/` as GT-blind detectors. The *value-matching* halves (does this row equal the planted value) move to `match/`. |
| `orchestrator/forensics/artifact_specs.py` (`resolve_specs`, `$ref`) | `orchestrator/evaluation/match/` | The `$ref`-resolution + entity/port/path equality logic IS the matcher. Repurposed, not deleted. |
| `orchestrator/forensics/evaluator.py` (temporal_consistency, recovered, tool_hits) | `orchestrator/evaluation/match/` + `orchestrator/evaluation/metrics/` | Ordering check becomes `order_pairwise`/`kendall_tau`; `tool_hits` becomes per-tool unique contribution. |
| `orchestrator/forensics/metrics.py` (Table 1/2, DR%, QoR) | `orchestrator/evaluation/metrics/` | Replaced by Phase 2.4 columns. `--legacy-csv` re-derives the old columns from the new pipeline. |
| `orchestrator/forensics/timeutil.py` | `orchestrator/forensics/timeutil.py` (unified) | The two duplicated helpers collapsed into one; extended for ISO-8601 UTC ms. |
| `scripts/report_metrics.py` | DELETED | Retired: it consumed the removed `forensics.metrics` and the old `forensics_report.json` format. Per-run `metrics.csv` plus `cli.py score --legacy-csv` replace it. |

## The matcher is the repurposed GT-lookup

The code that today lives in `ioc_detector` + `artifact_specs.resolve_specs`
answers "does tool output contain the planted value?". That is exactly the
matcher's job, but moved AFTER a GT-blind detection pass:

- `_resolve_ref` / `resolve_specs` (artifact_specs.py) -> `match/` reads
  `gt_manifest.json` to know the planted entities.
- path equality (`detect_disk`: `r["path"] == path_equals`), port equality
  (`volatility._socket_port_match`), substring/message matching
  (`plaso.detect_timeline`) -> `match/entity.py` normalized entity comparison +
  `config/matching.yaml` equivalence table.
- `evaluator._temporal_consistency` ordering -> `metrics/` order metrics over the
  matched (TP) subset only.

## Hard boundary

Nothing under `orchestrator/evaluation/detect/` may import, open, or receive `gt_manifest`,
`ground_truth`, or a scenario module. Enforced by
`orchestrator/evaluation/tests/test_detect_blindness.py`. Only `match/` reads the manifest;
`metrics/` reads it only for the GT event count N.

## Hardcoded GT constants to eliminate (circularity leaks)

These are instance values that appear OUTSIDE scenario definitions today. In the
target design they must exist only in the per-run `gt_manifest.json` (emitted by
the scenario) and never in a detection rule. The rule-leakage lint
(`tests/test_rule_leakage.py`) fails if any appears verbatim in a rule file.

Found in `orchestrator/forensics/artifact_specs.py` (the matching layer, where
they leak):

- `"T1574006.so"` — basename of the planted `.so` (`ldpreload_so_timeline`,
  `ldpreload_so_disk` via `$ref`).
- `"ld.so.preload"` / `/etc/ld.so.preload` — preload config fragment
  (`ldpreload_config`, `ldpreload_sudo_authlog`, `ldpreload_so_timeline`).
- `"/var/log/auth.log"` — auth-log path literal (`ldpreload_sudo_authlog`).
- `"/tmp/.rs_fifo"` — reverse-shell FIFO path (`reverse_shell_timeline`).
- `"mkfifo"`, `" nc "` — reverse-shell command fragments (`reverse_shell_timeline`).
- `4444` — reverse-shell port, via `$ref reverse_shell.port` (planted in code).

Found in `orchestrator/attacks/scenario_01_ldpreload.py` as module constants
(these are the legitimate single-source-of-truth, but they are FIXED, not
randomized, so a rule could hardcode them and never break):

- `SO_PATH = "/tmp/T1574006.so"`
- `PRELOAD_PATH = "/etc/ld.so.preload"` (OS-mandated, not randomizable)
- `DISCOVERY_OUTPUT = "/tmp/T1082.txt"`
- `RS_FIFO = "/tmp/.rs_fifo"`
- `RS_PORT = 4444`

Anti-circularity remedy: the scenario draws the randomizable instance values
(`.so` basename, discovery output name, FIFO name, port) from a seeded RNG
(`orchestrator/evaluation/scenario/manifest.py`), writes them into `gt_manifest.json`, and
detection rules express only behavioral classes (e.g. "executable mapped from
`/tmp`", "write to `/etc/ld.so.preload`" — the mechanism path, which is intrinsic
to T1574.006 and therefore not an instance secret).

## Build order

1. Phase 2 contracts + JSON Schemas (everything conforms to these).
2. Phase 4 matcher + Phase 5 metrics (deterministic, fixture-testable).
3. Phase 7 golden fixture + boundary/lint/determinism/schema tests.
4. Phase 3 GT-blind detectors over already-extracted raw outputs.
5. Phase 6 reproducibility plumbing + the `cli.py` evaluation subcommands.
6. Wire scenario manifest emission alongside the existing orchestrator path.
