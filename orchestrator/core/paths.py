"""
orchestrator/core/paths.py

Single source of truth for every filesystem location the project uses.

User-tunable roots come from config.yaml (machine-local):
    repo_root, shared_dir, state_dir, ssh_key, ssh_pub_key

Derived locations are computed as properties so callers never re-derive shared
or state paths on their own. Each experiment owns one directory under
experiments_dir, named by its `run_id` ("{distro}_{scenario}_{ts}"), holding a
dumps/ subtree (raw acquisition) via run_dumps_dir(). run_analysis_dir() is
used only by the setup-time Plaso probe; a scenario run creates no analysis/.

investigations_dir and its run_investigation_dir()/run_derived_dir() helpers
mirror this for the ignored analyst workspace under shared/investigations/
(see docs/investigations/README.md). No Python code creates or reads this
tree today -- Runme notebooks derive it by hand as "shared/investigations/
$RUN_ID" -- these accessors exist so any future orchestrator-side tooling
does not re-hardcode that literal and drift from shared_dir.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ProjectPaths:
    repo_root: Path
    shared_dir: Path
    state_dir: Path
    ssh_key: Path
    ssh_pub_key: Path

    @classmethod
    def from_config(cls, repo_root: Path, host_cfg: dict[str, Any]) -> "ProjectPaths":
        return cls(
            repo_root=repo_root,
            shared_dir=host_cfg["shared_dir"],
            state_dir=host_cfg["state_dir"],
            ssh_key=host_cfg["ssh_key"],
            ssh_pub_key=host_cfg["ssh_pub_key"],
        )

    # --- shared/ tree (experiment outputs) -------------------------------

    @property
    def experiments_dir(self) -> Path:
        return self.shared_dir / "experiments"

    @property
    def isf_dir(self) -> Path:
        return self.shared_dir / "isf"

    @property
    def investigations_dir(self) -> Path:
        return self.shared_dir / "investigations"

    # --- state_dir tree (libvirt-owned storage) --------------------------

    @property
    def images_dir(self) -> Path:
        return self.state_dir / "images"

    @property
    def pool_dir(self) -> Path:
        return self.state_dir / "disks"

    # --- per-run -------------------------------------------------------
    # One directory per experiment, named by run_id.

    def run_dumps_dir(self, run_id: str) -> Path:
        return self.experiments_dir / run_id / "dumps"

    def run_analysis_dir(self, run_id: str) -> Path:
        return self.experiments_dir / run_id / "analysis"

    def run_investigation_dir(self, run_id: str) -> Path:
        """Ignored analyst workspace root for one run; see run_derived_dir()."""
        return self.investigations_dir / run_id

    def run_derived_dir(self, run_id: str, source: str) -> Path:
        """Where a Runme notebook writes derived output for one source
        (disk/memory/timeline/...), per docs/investigations/README.md."""
        return self.run_investigation_dir(run_id) / "derived" / source
