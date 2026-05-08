## TODO LIST

1. Review VM Life cycle (create, shutdown, turn on, destroy)
2. Review init + sudo handling (how to ensure permission correct? rerun sudo -v?
3. Review cli.py => in distro-setup really needed? Can't do auto when run? Same for init command? Simplify!!!
4. Why debian so long creating? How to check what is slowing?
5. Remove profile from build_isf... check and review
6. handle "reason".. not always clear
7. error handling.. and make output clear (Why libvirt error are showed? ecc..) => [Ex. libvirt: QEMU Driver error : Domain not found: no domain with matching name 'build-isf-debian-13']
8. manifest should include virtual (real) disk size
9. separation of concerns not so  clear.. orchestrator.py imports vmmanger and provider at the same time.. avoidable?
10. is SSH wait every time needed? can't reduce polling?
11. orchestrator.py still hardcoded path management


forensic-lab/
├── cli.py             # Entry point (CLI parser + high-level flow)
├── config.yaml        # Single source of truth (now including constants)
├── TODO.md            # Track our progress
├── orchestrator/
│   ├── __init__.py
│   ├── core/
│   │   ├── config.py  # Loads config.yaml + normalized Constants (paths, playbooks)
│   │   ├── orchestrator.py  # Only knows Experiment Lifecycle (Prepare -> Attack -> Dump)
│   │   └── vm_manager.py    # Only knows VM Lifecycle (Registry of VMs, SSH, Snapshots)
│   ├── attacks/       # Pure logic (receives SSH connection, runs payload)
│   └── forensics/     # Dumper + analysis logic
├── infra/
│   ├── provider.py    # Thin wrapper around libvirt/QEMU (the 'Driver')
│   └── profiles/      # YAML distro profiles (metadata, not logic)
└── shared/
    ├── isf/           # Volatility ISF files
    └── dumps/         # Memory/Disk dumps


Master Refactoring List
Phase 1: Foundation and Cleanup

Consolidate Constants: Move all snapshot names, playbook paths, and directory defaults into config.py.

Clean config.py: Remove legacy code, move load_profile into a clean helper, and ensure it provides the project "constants" as properties.

Merge bootstrap.py: Move setup logic into cli.py and delete bootstrap.py.

Phase 2: Lifecycle Ownership

VMManager Takeover: Move the build VM lifecycle (create/destroy/start/shutdown) from Orchestrator to VMManager.

Orchestrator Diet: Strip Orchestrator of its Provider reference. It should only talk to VMManager.

Phase 3: Hypervisor Modernization

libvirt-python Migration: Rewrite Provider methods (create_vm, destroy_vm, get_vm_ip, snapshot_exists) using the official libvirt API.

SSH Modernization: Replace the ssh_client.py wrapper with direct paramiko usage inside VMManager.

Phase 4: UX and Final Polish

Command Unification: Clean up cli.py to make run the primary driver.

Validation: Ensure the manifest generation (virtual disk size) is robust.

