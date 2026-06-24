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

The preload configuration is written to a lab-only path inside the guest:
`/tmp/forensic-lab/father_ldpreload/etc/ld.so.preload.lab`. The scenario does
**not** modify the guest's real `/etc/ld.so.preload`. The benign target process
is hooked by passing `LD_PRELOAD` in its environment directly, so the
preload-configuration file is an on-disk forensic marker that names the shared
object rather than a system-wide active hook. This keeps the run reversible by
snapshot revert and avoids destabilizing the guest while still leaving the
ld.so.preload artifact a DFIR examiner would look for.

Socket / backdoor / reverse shell: **not applicable**. Father's remote backdoor
and reverse shell are disabled, so the scenario declares no network-socket
observable and reports no socket metrics. The benign process holds no listening
socket.

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

## Running the scenario

There are two execution modes.

Local (engine only, no VM, no acquisition) -- for fast iteration on the steps
and the canonical truth/expectation files:

```bash
.venv/bin/python cli.py run-scenario \
  attacks/scenarios/userland_father_ldpreload/scenario.yml \
  --out-dir /tmp/father_local --run-id father_local
```

The local mode runs the steps on the host with a `LocalExecutor`, writes the
artifacts under `/tmp/forensic-lab/father_ldpreload`, and leaves
`reference_context.json` guest/acquisition fields null. It is for development
only and is not thesis evidence.

VM-backed (full case study) -- reverts the lab VM to baseline, runs the steps
inside the guest over SSH, then acquires and evaluates:

```bash
# execution only, no acquisition (fast check that the steps run in the guest)
.venv/bin/python cli.py run --distro ubuntu-22.04 \
  --scenario userland_father_ldpreload --no-acquire

# full run: scenario + RAM/disk acquisition + canonical evaluation
.venv/bin/python cli.py run --distro ubuntu-22.04 \
  --scenario userland_father_ldpreload
```

In VM-backed mode the guest paths under `/tmp/forensic-lab/father_ldpreload`
live inside the disposable VM, and `reference_context.json` records the real
guest distro, kernel, user and timezone.

## Outputs

A run writes to `shared/experiments/<run_id>/`:

- `dumps/` -- canonical truth (`execution_truth.jsonl`,
  `artifact_expectations.jsonl`, `reference_context.json`, `command_log.jsonl`)
  plus the acquired `memory/`, `disk/` images and `manifest.json`.
- `analysis/` -- raw forensic outputs (`vol3.json`, `bodyfile`,
  `timeline.jsonl`), the canonical `tool_findings.jsonl`,
  `detection_claims.jsonl`, and the matcher's `matches.jsonl`, `metrics.json`,
  `score_report.md`.

The pipeline is: scenario truth/expectations -> acquire RAM+disk -> extract
(Volatility3 / Sleuth Kit / Plaso) -> adapt to `ToolFinding` -> GT-blind
detectors emit `DetectionClaim`s -> GT-aware matcher scores claims against the
expectations. Detectors never read ground truth; findings are never derived
from it.

## Metrics: quantitative vs qualitative

Quantitative (in `score_report.md` / `metrics.json`):

- class-level coverage (did the artifact class appear at all);
- instance-level reconstruction (did the exact planted entity match);
- critical-event recall;
- per-source and per-artifact-class precision/recall/F1;
- source breakdown of tool findings (disk / memory / timeline).

Qualitative (documented, not scored as detection effectiveness):

- the hiding feature, represented by a marker file rather than active stealth;
- the disabled offensive components listed under Safety Model.

## Known limitations

- The benign `sleep` process is intentionally not malicious, so the GT-blind
  detectors do not raise a process claim for it on its own; the process is
  recovered as a memory mapping via the process/library correlation rule, so the
  bare `process` expectation can show as a class-level or instance miss. This is
  an honest measurement of the detectors, not a pipeline failure.
- Commands run over a one-shot SSH exec channel, not an interactive login shell,
  so the shell-history observable is opportunistic and may be absent.
- The preload configuration is a lab-only marker, not an active system-wide
  `/etc/ld.so.preload` hook (see Safety Model).
- No network, stealth, or adversary-resilience realism is claimed.
