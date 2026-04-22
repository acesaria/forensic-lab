# forensic-lab

A Python framework for evaluating forensic methodologies on KVM/libvirt virtual machines. The idea is straightforward: spin up a clean VM, run an attack (rootkit, process injection, whatever), acquire RAM and disk images, then measure how well forensic tools can reconstruct what happened.

This is research tooling for a thesis project — not production software. That said, it's designed to be repeatable, scriptable, and easy to extend with new distros and attack scenarios.

---

## What it does

The full experiment cycle looks like this:

1. **Provision** a clean VM from a pinned cloud image (Ubuntu, Debian, others)
2. **Snapshot** the pristine state — this becomes the baseline every experiment starts from
3. **Generate an ISF file** for Volatility3 if one doesn't exist for that kernel (optional, handled by a separate ephemeral VM)
4. **Run an attack scenario** — rootkit deployment, process injection, etc.
5. **Acquire** a live memory dump and a forensic disk image (EWF format)
6. **Analyse** with Sleuth Kit and Volatility3, and eventually compute detection metrics

Steps 1–3 happen once per distro. Steps 4–6 repeat as many times as needed — the baseline snapshot guarantees a clean slate every time.

---

## Repository layout

```
forensic-lab/
├── config.yaml                  # your local environment config (not committed)
├── cli.py                       # entry point — all commands start here
│
├── infra/                       # infrastructure layer — VMs, images, networking
│   ├── profiles/                # one YAML file per supported distro
│   │   ├── ubuntu-22.04.yaml
│   │   ├── ubuntu-24.04.yaml
│   │   └── debian-13.yaml
│   ├── cloud-init/              # cloud-init user-data templates, one per role
│   │   ├── lab/user-data
│   │   └── build-isf/user-data
│   ├── image_store.py           # download + verify base images
│   └── provider.py              # libvirt-python: VM lifecycle, network, storage
│
├── orchestrator/                # experiment pipeline layer
│   ├── core/
│   │   ├── orchestrator.py      # coordinates the full experiment lifecycle
│   │   ├── vm_manager.py        # high-level VM operations for experiments
│   │   └── ssh_client.py        # key-based SSH/SFTP to lab VMs
│   ├── forensics/
│   │   ├── dumper.py            # RAM and disk acquisition + manifest
│   │   ├── isf_builder.py       # ephemeral build-isf VM lifecycle (milestone 2)
│   │   └── analyzer.py          # forensic analysis tooling (WIP)
│   └── attacks/                 # one module per attack scenario
│       ├── attack_01_ptrace.py
│       └── ...
│
└── shared/                      # experiment outputs (gitignored)
    ├── dumps/                   # acquired images + manifests
    ├── isf/                     # generated Volatility3 ISF files
    └── results/                 # ground truth and analysis results
```

---

## Two VM roles, two networks

The lab uses two distinct VM roles with intentionally different network access:

| Role | Network | Purpose | Lifecycle |
|---|---|---|---|
| `lab` | `forensics-isolated` | Runs experiments — no internet access | Persistent, snapshots |
| `build-isf` | `default` (internet) | Builds Volatility3 ISF symbol files | Ephemeral — created and destroyed per build |

The `forensics-isolated` network is a host-only libvirt network (`192.168.100.0/24`). Lab VMs can reach the host and each other, but have no route to the outside. This matters for rootkit experiments — you don't want the VM phoning home or downloading updates mid-experiment.

---

## Adding a new distro

Drop a YAML file in `infra/profiles/`:

```yaml
# infra/profiles/debian-13.yaml
distro_id: debian-13
os_variant: debian13        # from: osinfo-query os | grep debian

image:
  url: https://cloud.debian.org/images/cloud/trixie/20260413-2447/debian-13-genericcloud-amd64-20260413-2447.qcow2
  checksum_url: https://cloud.debian.org/images/cloud/trixie/20260413-2447/SHA512SUMS
  checksum_algo: sha512
```

That's it. VM sizing and network defaults come from `config.yaml` and apply to all distros unless overridden.

If `os_variant` isn't recognised by your local osinfo database, set it to `null` — virt-install falls back to `generic`, which works fine.

---

## Configuration

Copy `config.yaml.example` to `config.yaml` and adjust paths for your machine. This file is gitignored — it contains your local SSH key path and storage preferences.

```yaml
lab:
  libvirt_uri: qemu:///system
  pool_name: forensic-lab-pool
  pool_path: /var/lib/forensic-lab/disks
  ssh_user: labuser
  ssh_key: ~/.ssh/forensics-lab
  shared_dir: ./shared

  networks:
    isolated: forensics-isolated
    internet: default

role_defaults:
  lab:
    disk_size: 10G
    ram_mb: 2048
    vcpus: 2
  build-isf:
    disk_size: 15G
    ram_mb: 6144
    vcpus: 4
    ephemeral: true
```

---

## Typical workflow

```bash
# One-time setup — creates the libvirt network and storage pool
python cli.py setup

# Prepare a distro for experiments — downloads image, creates VM, takes baseline snapshot
python cli.py prepare --distro ubuntu-22.04

# Run an experiment — reverts to baseline, runs the attack, acquires RAM + disk
python cli.py run --distro ubuntu-22.04 --scenario father-rootkit

# Clean up a VM when you're done with a distro
python cli.py destroy --distro ubuntu-22.04
```

The `prepare` step is intentionally separate from `run`. You set up a distro once, snapshot it, and then run as many experiments as you want against that clean baseline.

---

## How snapshots work

Each lab VM has exactly **one snapshot** named `baseline`. It's created automatically at the end of `prepare`, after cloud-init has finished and the VM is in a known good state.

Before every experiment run, the orchestrator reverts the VM to this snapshot. You get a guaranteed clean environment every time without reprovisioning — which takes seconds rather than minutes.

The snapshot is never automatically recreated or overwritten. If you need to reset it (e.g. after installing something permanently in the VM), destroy the VM and run `prepare` again.

---

## Forensic acquisition

Memory and disk are acquired separately:

- **RAM** — `virsh dump --memory-only --live` while the VM is running. No VM pause required.
- **Disk** — the VM is shut down cleanly, the qcow2 overlay is exposed via `qemu-nbd` in read-only mode, and `ewfacquire` produces a compressed EWF image. The VM is restarted immediately after.

Both images land in `shared/dumps/<scenario_id>/` alongside a `manifest.json` with SHA256 hashes, sizes, timestamps, and acquisition timing.

---

## ISF files for Volatility3

Volatility3 requires an ISF (Intermediate Symbol Format) JSON file matching the exact kernel version of the target VM. These files are generated by the `build-isf` VM role:

1. A `build-isf-<distro_id>` VM is created (internet-connected)
2. The VM fetches the appropriate kernel debug symbols from the distro's debug package repository
3. `dwarf2json` converts the DWARF symbols to ISF JSON
4. The file is copied to `shared/isf/` on the host
5. The VM is destroyed

This is handled automatically when a matching ISF file is missing. It only runs once per distro+kernel combination.

---

## Prerequisites

On the host machine:

- KVM/QEMU with libvirt (`virsh`, `virt-install`, `qemu-img`, `qemu-nbd`)
- `cloud-localds` (from `cloud-image-utils`)
- `ewfacquire` (from `libewf-tools`)
- User in the `libvirt` group: `sudo usermod -aG libvirt $USER`
- SSH key at `~/.ssh/forensics-lab` (ed25519 recommended)

Python dependencies:

```
libvirt-python
paramiko
requests
pyyaml
```

---

## Design principles

A few things that guided the architecture choices:

**Immutable base images.** The downloaded cloud image is set read-only after verification. VMs run on qcow2 overlays. Reprovisioning is always a fresh start.

**Desired state, not scripts.** `prepare` and `setup` are idempotent — run them twice and nothing breaks. The code checks current state before acting.

**Two layers, clear boundary.** `infra/` handles VMs as infrastructure (create, destroy, snapshot). `orchestrator/` handles VMs as experiment subjects (baseline, attack, acquire). Neither layer reaches into the other's concerns.

**Ephemeral build VMs.** The `build-isf` VM is created and destroyed in a single session. It never accumulates state and doesn't need to be managed.

---
