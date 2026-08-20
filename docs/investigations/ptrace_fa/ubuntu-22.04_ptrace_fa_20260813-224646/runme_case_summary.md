---
cwd: ../../../..
shell: bash
---

# ptrace foreign-allocation case summary and metrics

__Run:__ `ubuntu-22.04_ptrace_fa_20260813-224646`

**Scope:** memory-led interpretation of the accepted memory image for the
`ptrace_fa` scenario. This is a memory-dominant case; cold sources are declared
bounded/out of scope for this run because the technique establishes no
persistence.

Source notebook:

- [memory investigation](./runme_memory_investigation.md)

## Case identity and integrity

| Field | Value |
|---|---|
| Run ID | `ubuntu-22.04_ptrace_fa_20260813-224646` |
| Repository revision | `2e5dadc` |
| Platform | Ubuntu 22.04.5 LTS, kernel `5.15.0-179-generic`, `vanilla`, UTC guest |
| Memory image | `dumps/memory/mem.raw`, SHA-256 `9f8852bf…8231` (verified) |
| Technique | `ptrace` foreign-allocation shellcode injection, reverse shell |

## Metric contract

The P01–P05 inventory is fixed before the measured examination and scoped to the
memory-resident behaviour the technique produces. Applicability: memory P01–P05;
filesystem and timeline are declared out of scope for this run (no persistence to
recover). Status codes and `U`/`C`/`S` follow `../../../../ai/archive/METHODOLOGY.md`. Scenario facts
(victim PID 1044, listener `192.168.100.1:4444`, identity `labuser`) validate
candidates only after technique-led selection and are never forensic locators.

## Per-artifact evidence matrix

| ID | Phase/category | Expected artifact or fact | Filesystem | Timeline | Memory | Contribution | Principal method(s) | Accepted locator or limitation |
|---|---|---|---:|---:|---:|---:|---|---|
| P01 | Injection | Injected executable region | -- | -- | O | S | Vol3 `malfind`/`proc.Maps` | Anonymous `r-x` page `0x7f5864d1d000` in PID 1044; shellcode not fully disassembled. |
| P02 | Injection | Target process survived | -- | -- | O | S | Vol3 `pslist` | PID 1044 `./victim` UID 1000 present at acquisition. |
| P03 | Payload | Child shell spawned | -- | -- | O | S | Vol3 `pstree`/`psaux` | PID 1046 `sh`, child of 1044, UID 1000, created ~22 ms after victim. |
| P04 | Payload | Reverse shell established | -- | -- | O | S | Vol3 `sockstat` | Socket `0x8d050965abc0`, `192.168.100.32:54032` → `192.168.100.1:4444`, FDs 0/1/2/3 of PID 1046. |
| P05 | Identity | Execution identity | -- | -- | O | S | Vol3 `pslist` | UID 1000 (`labuser`) for PID 1044 and 1046. |

## Source metric summary

| Source | O | P | N | TF | Found / A | Coverage | U / C / S | X | Union gain | Rejected candidates | TTF | Principal methods |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|
| Filesystem | 0 | 0 | 0 | 0 | 0 / 0 | out of scope | -- | 0 | -- | N/A | not measured | not examined (memory-dominant run) |
| Timeline | 0 | 0 | 0 | 0 | 0 / 0 | out of scope | -- | 0 | -- | N/A | not measured | not examined (memory-dominant run) |
| Memory | 5 | 0 | 0 | 0 | 5 / 5 | 100.0% | 0 / 0 / 5 | 0 | -- | 2 | not measured | Volatility 3 2.28.0 (`malfind`,`proc.Maps`,`pslist`,`pstree`,`psaux`,`sockstat`) |
| Union | 5 | 0 | 0 | 0 | 5 / 5 | 100.0% | 0 / 0 / 5 | 0 | +0 | 2 case-wide | not measured | Volatility 3 |

All five targets are specialized memory findings: no other source family was
applicable, so there is no corroboration and no union gain. This is the expected
shape of a memory-resident technique, not a coverage weakness.

**Rejected candidates.** `malfind` flagged `rwx` anonymous regions in unrelated
system daemons `networkd-dispat` (PID 611) and `unattended-upgr` (PID 659); both
are rejected — no reverse-shell socket, no child shell, long-running system
daemons whose `rwx` regions are a common `malfind` false positive (2 rejected).

## Cross-source conclusion

The entire attack chain — injected executable page, surviving target process,
child shell, and established reverse shell to the listener — is established from
volatile memory alone. Because the injection establishes no persistence, no cold
source could reconstruct the chain; had memory not been acquired while the guest
was running, the case would be unresolvable from disk alone. This is the
methodological counterpart to the disk-led Father case: there the independent
memory acquisition corroborated a durable disk artefact, here it is the sole
carrier of the evidence. Limitation: the injected page proves injection, but the
shellcode was not fully disassembled; its function is inferred from its nature
(anonymous, executable) and observed effect (the reverse shell), not from a
complete instruction decode.
