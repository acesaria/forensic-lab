# userland_father_ldpreload

`userland_father_ldpreload` is a lab-safe userland LD_PRELOAD rootkit case
study inspired by Father: https://github.com/mav8557/Father.

The scenario vendors the original Father source as an inert pinned sample archive
for provenance and DFIR sample-management artifacts. It is pinned to upstream
commit `4eb2712caf612a7dc55fd4f34ff5c72b74c7c332` under the Unlicense, with
archive SHA-256
`90e440a2ff8264a3f39c5c2b63ee7b8def9b85f87a7b79c666bfb46f25a2c125`.

The scenario does not execute the original Father rootkit and does not
demonstrate complete offensive capability. Runtime execution uses a small
controlled harness in
`files/father_lab_preload.c` that preserves LD_PRELOAD forensic artifacts while
neutralizing unsafe behavior.

## Safety Model

Disabled or not implemented:

- remote backdoor;
- reverse shell;
- privilege escalation;
- GnuPG or user-data tampering;
- logic bomb;
- destructive anti-detection;
- propagation;
- exfiltration.

The default preload configuration path is lab-only:
`/tmp/forensic-lab/father_ldpreload/etc/ld.so.preload.lab`.
The scenario does not modify host `/etc/ld.so.preload` by default. It is intended
for an isolated VM that can be reverted from snapshot.

## Forensic Intent

The scenario produces artifacts for disk, memory, and timeline analysis:

- pinned Father upstream source archive and lock metadata;
- preload configuration;
- compiled shared object;
- benign process started with LD_PRELOAD;
- process/library relation via `/proc/<pid>/maps` and memory tooling when
  acquisition happens while the process is alive;
- hiding-feature marker as a forensic concept, not functional stealth;
- partial cleanup and a deleted marker candidate.

## Thesis Snippet

“Lo scenario userland_father_ldpreload utilizza Father come caso di studio di
rootkit userland basato su LD_PRELOAD. Poiché il progetto originale include
funzionalità offensive quali hiding, privilege escalation, backdoor e
anti-detection, l’esperimento è stato eseguito in modalità controllata e
confinata, disabilitando o neutralizzando le componenti non necessarie alla
valutazione forense. L’obiettivo non è misurare l’efficacia offensiva del
rootkit, ma valutare la capacità della pipeline di acquisizione, normalizzazione,
detection e matching di ricostruire artefatti rilevanti su disco, memoria e
timeline.”

## Limits

This scenario does not measure the full realism of a real compromise. It does
not evaluate advanced stealth, network forensics, or adversary resilience. The
hiding feature is represented by a documented marker and indirect artifacts
rather than active userspace stealth.

## Expected Pipeline

Run the declarative scenario with the existing scenario engine, acquire RAM/disk
through the lab orchestrator when VM-backed execution is used, convert cached raw
tool outputs to `ToolFinding`, run GT-blind detectors, then run the GT-aware
matcher.
