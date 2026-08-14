---
cwd: ../../../..
shell: bash
---

# Diamorphine (LKM) case summary and metrics

__Run:__ `ubuntu-22.04_kernel_diamorphine_20260813-224854`

**Scope:** kernel-memory interpretation of the accepted memory image for the
`kernel_diamorphine` scenario. Memory-dominant case; the point is the module-view
discrepancy and the bounded limits of proving active hooks.

Source notebook:

- [memory investigation](./runme_memory_investigation.md)

## Case identity and integrity

| Field | Value |
|---|---|
| Run ID | `ubuntu-22.04_kernel_diamorphine_20260813-224854` |
| Repository revision | `2e5dadc` |
| Platform | Ubuntu 22.04.5 LTS, kernel `5.15.0-179-generic`, `vanilla`, UTC guest |
| Memory image | `dumps/memory/mem.raw`, SHA-256 `75edc2d3…0446` (verified) |
| Technique | Self-hiding LKM rootkit; file hiding + signal-64 privilege helper |

## Metric contract

The D01–D04 inventory is fixed before the measured examination and scoped to
kernel-memory observables. Applicability: memory D01–D04. Filesystem/timeline are
out of scope for this memory-focused kernel case (offline disk would expose the
hidden files, as in the Father case, but was not examined here). Scenario facts
(hidden dir `/tmp/diamorphine_secret_dir`, signal-64 escalation to uid=0) are
validation, never forensic locators, and are explicitly **not** used to assert
the hook (D03/D04).

## Per-artifact evidence matrix

| ID | Phase/category | Expected artifact or fact | Filesystem | Timeline | Memory | Contribution | Principal method(s) | Accepted locator or limitation |
|---|---|---|---:|---:|---:|---:|---|---|
| D01 | Module hiding | Module loaded but hidden from `lsmod` | -- | -- | O | S | Vol3 `lsmod`/`check_modules`/`hidden_modules` | Absent from `lsmod` (57 modules); resident at offset `0xffffc0b620c0`, code size `0x4000`. |
| D02 | Module hiding | View discrepancy and taints | -- | -- | O | S | Vol3 `modxview` | `diamorphine` *In procfs* `False`, *In sysfs*/*In scan* `True`; taints `OOT_MODULE,UNSIGNED_MODULE`; only hidden module. |
| D03 | Hooking | Active syscall-table hook | -- | -- | N | S | Vol3 `check_syscall` | `getdents`/`getdents64`/`kill` point to normal kernel symbols, not the module range. |
| D04 | Hooking | Active ftrace hook | -- | -- | N | S | Vol3 `CheckFtrace` | No `ftrace_ops` installed. |

## Source metric summary

| Source | O | P | N | TF | Found / A | Coverage | U / C / S | X | Union gain | Rejected candidates | TTF | Principal methods |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|
| Filesystem | 0 | 0 | 0 | 0 | 0 / 0 | out of scope | -- | 0 | -- | N/A | not measured | not examined |
| Timeline | 0 | 0 | 0 | 0 | 0 / 0 | out of scope | -- | 0 | -- | N/A | not measured | not examined |
| Memory | 2 | 0 | 2 | 0 | 2 / 4 | 50.0% | 0 / 0 / 2 | 0 | -- | 0 | not measured | Volatility 3 2.28.0 (`lsmod`,`check_modules`,`hidden_modules`,`modxview`,`check_syscall`,`CheckFtrace`) |
| Union | 2 | 0 | 2 | 0 | 2 / 4 | 50.0% | 0 / 0 / 2 | 0 | +0 | 0 case-wide | not measured | Volatility 3 |

The 50% coverage is not a tool failure: D01/D02 (module loading and hiding) are
observed and D03/D04 (active hook) are true bounded negatives. Recording the hook
targets as `N` rather than omitting them is what makes the observed/not-observed
boundary auditable. `check_syscall` and `CheckFtrace` produced valid results (no
redirection, no `ftrace_ops`); this is `N`, not `TF`.

## Cross-source conclusion

Kernel memory is the specialized source that establishes module loading and
hiding through a verifiable discrepancy between independent module enumerations
(D01, D02): the module is unlinked from the list `lsmod` reads yet present in
sysfs and by memory scanning, tainted `OOT_MODULE,UNSIGNED_MODULE`. The same
examination does not establish the active hook (D03, D04): the syscall table is
unmodified for the relevant calls and no ftrace hook is installed. Whether this
reflects a hooking mechanism the plugins do not check or a plugin limitation
cannot be concluded from the available evidence; the defensible statement is that
memory proves loading and concealment but not interception. Deducing the hook
from scenario success would confuse execution provenance with forensic
observation.
