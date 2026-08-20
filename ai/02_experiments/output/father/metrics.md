# Metrics — father-u22-20260818-01

## Timing

| Phase | Duration / timestamp |
|---|---|
| scenario execution (start → end) | 2026-08-18T15:00:13.062Z → 2026-08-18T15:01:44.330Z (~91.3 s) |
| memory acquisition | 2.09 s |
| disk acquisition (qemu-img + ewfacquire + ewfverify) | 29.96 s |
| total run (start → run_ended_at) | 2026-08-18T15:00:13.062Z → 2026-08-18T15:02:22.406Z (~129.3 s) |

## Acquisition sizes

| Item | Size |
|---|---|
| memory image | 2,147,747,795 B (~2.0 GiB) |
| disk image (virtual) | 10,737,418,240 B (10.0 GiB) |
| disk image (EWF, compressed, 2 segments) | 1,906,335,742 B (~1.78 GiB) |

## Throughput (as reported by tooling)

- ewfacquire: up to ~602 MiB/s sustained during acquisition
- ewfverify: up to ~1.1 GiB/s sustained during verification

## Functional outcome

| Check | Result |
|---|---|
| scenario_status | `completed` |
| implant install | success (`/lib/selinux.so.3`, timestomped) |
| persistence configured | success (`/etc/ld.so.preload`) |
| activation | success (`ssh.service` restarted) |
| backdoor validation (host-side connect-back check) | success — root shell obtained, `uid=0(root) gid=1337` |
| recon console-echo suppression (passwd) | confirmed — `cat /etc/passwd` output absent from console, present only in staged file |
| hidden-file behavior post-activation | `__malicious_recon` and `__malicious_harvest` absent from `ls -la /tmp`; `rk.so` still visible (expected — not covered by the hook's hiding logic) |
| cleanup | staged artifact removed, shell history cleared/unset; no log truncation performed (matches evidence-preserving default) |
| disk/memory acquisition | both completed; ewfverify hash matches acquired hash |

## Integrity

- Disk image sha256 (acquired) == sha256 (ewfverify-recomputed): `d97efadbe5522d83ff936470d5892217835d1ae92758d8c23f13a5a3078cb550` — match confirmed by `ewfverify: SUCCESS`.
- Memory image sha256: `47f08e0cd6c845d9f2e7f23701faef73d19df9e14cd1a88d062541ee1e9c6483` (recorded once at acquisition; no independent re-hash step performed in this run).
