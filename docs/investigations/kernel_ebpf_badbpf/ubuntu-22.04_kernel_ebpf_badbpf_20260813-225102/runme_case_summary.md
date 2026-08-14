---
cwd: ../../../..
shell: bash
---

# Bad-BPF (eBPF) case summary and metrics

__Run:__ `ubuntu-22.04_kernel_ebpf_badbpf_20260813-225102`

**Scope:** kernel/memory interpretation of the accepted memory image for the
`kernel_ebpf_badbpf` scenario. Memory-dominant case; the point is process-hiding
visibility, identity incoherence, and enumerable eBPF mechanism.

Source notebook:

- [memory investigation](./runme_memory_investigation.md)

## Case identity and integrity

| Field | Value |
|---|---|
| Run ID | `ubuntu-22.04_kernel_ebpf_badbpf_20260813-225102` |
| Repository revision | `2e5dadc` |
| Platform | Ubuntu 22.04.5 LTS, kernel `5.15.0-179-generic`, `vanilla`, UTC guest |
| Memory image | `dumps/memory/mem.raw`, SHA-256 `e2bc1d74…0abaa` (verified) |
| Technique | eBPF `pidhide`/`exechijack` process hiding and identity masking |

## Metric contract

The B01–B05 inventory is fixed before the measured examination and scoped to
kernel/memory observables. Applicability: memory B01–B05; filesystem/timeline out
of scope for this memory-focused run. Scenario facts (worker PID 1053, executable
`/a`, pool `192.168.100.1:3333`) validate candidates only after technique-led
selection and are never forensic locators.

## Per-artifact evidence matrix

| ID | Phase/category | Expected artifact or fact | Filesystem | Timeline | Memory | Contribution | Principal method(s) | Accepted locator or limitation |
|---|---|---|---:|---:|---:|---:|---|---|
| B01 | Process hiding | Hidden worker visible in kernel memory | -- | -- | O | S | Vol3 `pslist`/`psaux` | PID 1053 `kworker/u8:2`, hidden from `/proc`; loader `pidhide --pid-to-hide 1053`. |
| B02 | Identity masking | Worker identity incoherence | -- | -- | O | S | Vol3 `pslist`/`psaux`/`proc.Maps` | `comm kworker/u8:2` but PPID 1, UID 1000, exe `/a` inode 74173 ≠ argv `/usr/bin/uptime`. |
| B03 | Mechanism | eBPF process-hiding program present | -- | -- | O | S | Vol3 `ebpf` | Three `handle_getdents` `BPF_PROG_TYPE_TRACEPOINT` programs. |
| B04 | Network | Pool connection established | -- | -- | O | S | Vol3 `sockstat` | Socket `0x8ddac379c600`, `192.168.100.32:38018` → `192.168.100.1:3333`, PID 1053. |
| B05 | Loader | pidhide loader chain disclosing target | -- | -- | O | S | Vol3 `psaux` | PID 1058/1059/1060 `sudo`→`pidhide`, declared target 1053. |

## Source metric summary

| Source | O | P | N | TF | Found / A | Coverage | U / C / S | X | Union gain | Rejected candidates | TTF | Principal methods |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|
| Filesystem | 0 | 0 | 0 | 0 | 0 / 0 | out of scope | -- | 0 | -- | N/A | not measured | not examined |
| Timeline | 0 | 0 | 0 | 0 | 0 / 0 | out of scope | -- | 0 | -- | N/A | not measured | not examined |
| Memory | 5 | 0 | 0 | 0 | 5 / 5 | 100.0% | 0 / 0 / 5 | 0 | -- | 0 | not measured | Volatility 3 2.28.0 (`pslist`,`psaux`,`proc.Maps`,`ebpf`,`sockstat`) |
| Union | 5 | 0 | 0 | 0 | 5 / 5 | 100.0% | 0 / 0 / 5 | 0 | +0 | 0 case-wide | not measured | Volatility 3 |

All five targets are specialized memory findings. Unlike Diamorphine, the hooking
mechanism is directly observed (B03): a loaded eBPF program is a first-class
kernel object with a dedicated plugin, whereas an LKM hook may leave no signature
the available plugins read.

## Cross-source conclusion

Memory exposes the hidden worker despite the eBPF `/proc` filter (Volatility walks
the kernel task list), the mutually incoherent identity views (comm vs argv vs
executable `/a`), the enumerable `handle_getdents` tracepoint programs that
implement the hiding, and the established pool connection. All are established from
kernel structures, not planted names; scenario values confirm identity only after
technique-led selection. Limitation: the eBPF bytecode was not disassembled, so
that the programs filter specifically PID 1053 is consistent with the observed
chain but not proven by decoding the program. Compared with Diamorphine, this case
shows that mechanism traceability — not the memory source itself — governs whether
an active hook can be demonstrated.
