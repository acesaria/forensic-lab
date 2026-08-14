---
cwd: ../../../..
shell: bash
---

# Diamorphine (LKM) case summary and metrics

__Run:__ `ubuntu-22.04_kernel_diamorphine_20260813-224854`

**Scope:** kernel-memory interpretation of the accepted memory image for the
`kernel_diamorphine` scenario. Memory-dominant case; the point is the module-view
discrepancy and the bounded limits of proving active hooks.

Source notebooks:

- [memory investigation](./runme_memory_investigation.md)
- [timeline investigation](./runme_timeline_investigation.md)

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
kernel observables. Applicability: memory D01–D04; timeline D01–D02 for their
disk-observable loading and taint facets. Filesystem remains out of scope.
Scenario facts (hidden dir `/tmp/diamorphine_secret_dir`, signal-64 escalation
to uid=0) are validation, never forensic locators, and are explicitly **not**
used to assert the hook (D03/D04). The timeline was re-scoped only after a
bounded, technique-led cold-disk examination established accepted locators.

## Per-artifact evidence matrix

| ID | Phase/category | Expected artifact or fact | Filesystem | Timeline | Memory | Contribution | Principal method(s) | Accepted locator or limitation |
|---|---|---|---:|---:|---:|---:|---|---|
| D01 | Module hiding | Module loaded but hidden from `lsmod` | -- | P | O | C | Plaso `systemd_journal`/`filestat`; Vol3 `lsmod`/`check_modules`/`hidden_modules` | TL `insmod` PID 1046 at `20:48:54.273979`, kernel taint at `.279631`, and `.ko` inode 74173 crtime `20:48:54.176000`; missing element: runtime hiding from `lsmod`. Mem: absent from `lsmod` (57 modules), resident at `0xffffc0b620c0`, code size `0x4000`. |
| D02 | Module hiding | View discrepancy and taints | -- | P | O | C | Plaso `systemd_journal`; Vol3 `modxview` | TL journal records out-of-tree and unsigned-module taints at `20:48:54.279`; missing element: the runtime procfs/sysfs discrepancy. Mem: *In procfs* `False`, *In sysfs*/*In scan* `True`, taints `OOT_MODULE,UNSIGNED_MODULE`; only hidden module. |
| D03 | Hooking | Active syscall-table hook | -- | -- | N | -- | Vol3 `check_syscall` | `getdents`/`getdents64`/`kill` point to normal kernel symbols, not the module range. |
| D04 | Hooking | Active ftrace hook | -- | -- | N | -- | Vol3 `CheckFtrace` | No `ftrace_ops` installed. |

## Source metric summary

| Source | O | P | N | TF | Found / A | Coverage | U / C / S | X | Union gain | Rejected candidates | TTF | Principal methods |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|
| Filesystem | 0 | 0 | 0 | 0 | 0 / 0 | out of scope | -- | 0 | -- | N/A | not measured | not examined |
| Timeline | 0 | 2 | 0 | 0 | 2 / 2 | 100.0% | 0 / 2 / 0 | 0 | -- | N/A | not measured | Plaso 20260512 curated `timeline_curated.plaso` plus unfiltered control; bounded `filestat`, `systemd_journal`, `utmp` queries |
| Memory | 2 | 0 | 2 | 0 | 2 / 4 | 50.0% | 0 / 2 / 0 | 0 | -- | 0 | not measured | Volatility 3 2.28.0 (`lsmod`,`check_modules`,`hidden_modules`,`modxview`,`check_syscall`,`CheckFtrace`) |
| Union | 2 | 0 | 2 | 0 | 2 / 4 | 50.0% | 0 / 2 / 0 | 0 | +0 | 0 case-wide | not measured | Plaso 20260512 + Volatility 3 |

The 50% union coverage is not a tool failure: D01/D02 (module loading and
hiding) are observed and D03/D04 (active hook) are true bounded negatives.
Timeline's 100% uses a different, two-target applicability set and is not a
cross-tool performance comparison. Recording the hook targets as `N` rather
than omitting them is what makes the observed/not-observed boundary auditable.
`check_syscall` and `CheckFtrace` produced valid results (no redirection, no
`ftrace_ops`); this is `N`, not `TF`.

## Cross-source conclusion

Kernel memory establishes module loading and hiding through a verifiable
discrepancy between module enumerations (D01, D02): the module is unlinked from
the list `lsmod` reads yet present in sysfs and by memory scanning. The cold
timeline partially supports those compound targets: it dates the `.ko`, the
`insmod`, and the two taint messages, but cannot observe runtime hiding. The
taints `OOT_MODULE,UNSIGNED_MODULE` are the same attribute observed in the disk
journal and memory `modxview`, across independent acquisitions; this is genuine
corroboration. D01/D02 are mechanically `C` because both applicable families
find a facet, but only D02's taint is claimed as same-attribute corroboration.

The timeline also dates the concealed directory (inode 258128) and note (inode
258129) at `20:48:54.180`–`.204`, before module load at `.274`: cold-disk
visibility establishes their existence and order, not that the hook hid them.
The examination still does not establish the active hook (D03, D04): the syscall
table is unmodified for the relevant calls and no ftrace hook is installed.
Whether this reflects a mechanism the plugins do not check or a plugin
limitation cannot be concluded. Deducing the hook from scenario success would
confuse execution provenance with forensic observation.
