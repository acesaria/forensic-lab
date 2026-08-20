# Artifacts — father-u22-20260818-01

Run directory: `shared/experiments/father-u22-20260818-01/`

## Top-level

| Path | Size | Notes |
|---|---|---|
| `manifest.json` | 1,665 B | run manifest (scenario_status, timestamps, hashes, backdoor connection facts) |
| `terminal_transcript.txt` | 3,379 B | full console transcript of the run |
| `command_log.jsonl` | 4,844 B | structured per-command log |

## Inputs (staged before execution)

| Path | Size | sha256 |
|---|---|---|
| `inputs/father/rk.so` | 32,784 B | `87fece49fc15a48372a1ba76cf424755f9cfab6cce7e8073002757f7db2f0711` |
| `inputs/father/build.json` | 997 B | `5d1cd7f3d340796fc57f864c7d1ad35fb03bbd4f3ab2ccf45df433b40a365343` |

## Acquisition — memory

| Field | Value |
|---|---|
| path | `dumps/memory/mem.raw` |
| tool | `virsh dump --memory-only` (libvirt 10.0.0) |
| size | 2,147,747,795 B (~2.0 GiB) |
| sha256 | `47f08e0cd6c845d9f2e7f23701faef73d19df9e14cd1a88d062541ee1e9c6483` |
| acquisition time | 2.09 s |
| status file | `dumps/memory/virsh_dump_status.json` |

## Acquisition — disk (offline)

| Field | Value |
|---|---|
| segments | `dumps/disk/evidence_disk.E01` (1,572,840,585 B), `dumps/disk/evidence_disk.E02` (333,495,157 B) |
| tool chain | `qemu-img convert -O raw` → `ewfacquire -u -c empty-block` → `ewfverify -d sha256` |
| virtual size | 10.0 GiB (10,737,418,240 B) |
| combined EWF size | ~1.8 GiB |
| sha256 (verified) | `d97efadbe5522d83ff936470d5892217835d1ae92758d8c23f13a5a3078cb550` |
| md5 (ewfacquire) | `e5b91dff6f05cf8aeab7b4553237e4ab` |
| acquisition time | 29.96 s |
| disk_acquisition_mode | `offline` (VM powered off before acquisition) |
| status files | `dumps/disk/ewfacquire_status.json`, `dumps/disk/ewfverify_status.json`, `dumps/disk/qemu_img_status.json` |

## Acquisition manifest

- `dumps/acquisition.json` (6,875 B) — full command records for memory and disk acquisition, including per-segment hashes and ewfverify output.

## In-guest artifacts observed during the run (not separately exported as files)

- `/tmp/rk.so` — staged implant binary (removed during cleanup; present in disk/memory image at acquisition time only if not yet cleaned — cleanup ran before acquisition per transcript order).
- `/lib/selinux.so.3` — installed implant (persistent location via `/etc/ld.so.preload`), timestomped to match `libc.so.6`.
- `/tmp/__malicious_recon` — recon staging file (hidden from post-activation `ls` by the hooked `readdir`).
- `/tmp/__malicious_harvest` — harvested `/etc/shadow` copy, mode 0600 (also hidden post-activation).
- `/etc/ld.so.preload` — persistence entry pointing at `/lib/selinux.so.3`.

These are recoverable from `dumps/disk/evidence_disk.E01`/`.E02` and `dumps/memory/mem.raw` via the existing DF investigation workflow (not run in this stage; only explicitly requested investigation runs are covered by `ai/02_experiments/CONTEXT.md`).
