# Time normalization

All pipeline timestamps are normalized to **UTC, ISO-8601, millisecond
precision** (`YYYY-MM-DDThh:mm:ss.sssZ`). This is the contract enforced by the
JSON Schemas (`gt_manifest.schema.json` `ts_utc` pattern) and produced by
`orchestrator/forensics/timeutil.py`. Internally, matching and metrics convert to epoch
seconds (float) via `parse_iso_utc`; the string form is the only thing written
to disk.

## Per-source assumptions

| Source | Native time | Normalization | Quality |
| --- | --- | --- | --- |
| GT manifest | wall clock at action, captured by `now_utc_ms()` | already UTC ms | exact |
| Plaso (`psort -o json_line`) | `timestamp` = microseconds since Unix epoch, UTC | `epoch_us_to_iso_ms` | `wallclock` |
| TSK bodyfile (`fls -m`) | atime/mtime/ctime/crtime = epoch seconds, UTC | `epoch * 1e6 -> iso ms` | `wallclock` |
| Volatility 3 | memory snapshot has no reliable per-artifact wall clock | none emitted | `none` |

## Why `ts_quality`

A finding declares `ts_quality` ∈ {`wallclock`, `relative`, `none`}:

- `wallclock` — a trustworthy absolute UTC time (disk filesystem times, plaso
  log/filestat events). Participates in Order and Time-MAE.
- `relative` — an ordering is known but the absolute offset is not (reserved for
  future sources, e.g. uptime-relative kernel logs).
- `none` — no usable time. **Memory findings are `none`**: a RAM image is a
  single instant, so a recovered socket or mapped library has no per-artifact
  wall clock. These findings match on entity + event_class only and are excluded
  from `order_pairwise`, `kendall_tau`, and `time_mae_s`.

## Guest vs host clock

Lab VMs run with the host clock (qemu default) in UTC. Cloud images are
configured to UTC (`timezone: UTC` is recorded in the manifest). No DST or
local-offset conversion is applied anywhere; any future non-UTC source must be
converted at extraction time, before a `ts_utc` string is produced, never later.

## Tolerances

Matching tolerances live in `orchestrator/evaluation/config/matching.yaml` (default 60 s
pairing tolerance, 60 s dedup bucket, 30 min scope margin) and are hashed into
every metrics row. The 1 s Order tie threshold lives in
`orchestrator/evaluation/metrics/compute.py` and reflects that consecutive seeded steps can
land in the same second.
