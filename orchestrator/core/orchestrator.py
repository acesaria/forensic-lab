import json
import os
import re
import shutil
import subprocess
import time

import paramiko


CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ORCHESTRATOR_DIR = os.path.dirname(CURRENT_DIR)
PROJECT_ROOT = os.path.dirname(ORCHESTRATOR_DIR)

class ForensicOrchestrator:
    """
    Minimal orchestration API for:
    - ISF build lifecycle on isf-build VM
    - victim baseline lifecycle + snapshots
    - scenario deployment/execution utilities
    """

    def __init__(
        self,
        target_ip: str = "192.168.56.10",
        username: str = "vagrant",
        password: str = "vagrant",
        builder_vm: str = "isf-build",
        victim_vm: str = "victim",
    ) -> None:
        self.target_ip = target_ip
        self.auth = {"username": username, "password": password}
        self.builder_vm = builder_vm
        self.victim_vm = victim_vm
        self.project_root = PROJECT_ROOT
        self.results_path = os.path.join(self.project_root, "shared", "results")
        self.isf_path = os.path.join(self.project_root, "shared", "isf")


        os.makedirs(self.results_path, exist_ok=True)
        os.makedirs(self.isf_path, exist_ok=True)

    # ---------------------------
    # Vagrant helpers
    # ---------------------------

    def _ensure_vagrant(self) -> None:
        if shutil.which("vagrant") is None:
            raise RuntimeError("vagrant is not installed or not available in PATH")

    def _run_vagrant(self, args: list[str]) -> subprocess.CompletedProcess:
        self._ensure_vagrant()
        return subprocess.run(
            ["vagrant", *args],
            cwd=self.project_root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def _list_snapshots(self, vm_name: str) -> list[str]:
        try:
            result = self._run_vagrant(["snapshot", "list", vm_name])
        except subprocess.CalledProcessError:
            return []

        snapshots: list[str] = []
        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if not line or line.lower().startswith("no snapshots"):
                continue

            if line.startswith("-"):
                line = line[1:].strip()

            snapshot_name = line.split()[0]
            snapshots.append(snapshot_name)
        return snapshots

    def snapshot_exists(self, vm_name: str, snapshot_name: str) -> bool:
        return snapshot_name in self._list_snapshots(vm_name)

    def _ensure_command(self, command: str) -> None:
        if shutil.which(command) is None:
            raise RuntimeError(f"{command} is not installed or not available in PATH")

    def run_host_command(
        self,
        args: list[str],
        *,
        require_command: str | None = None,
        sudo: bool = False,
    ) -> subprocess.CompletedProcess:
        if require_command:
            self._ensure_command(require_command)

        command = [*args]
        if sudo and os.geteuid() != 0:
            self._ensure_command("sudo")
            command = ["sudo", *command]

        return subprocess.run(
            command,
            cwd=self.project_root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def _get_vagrant_libvirt_id(self, vm_name: str) -> str | None:
        machine_id_path = os.path.join(
            self.project_root,
            ".vagrant",
            "machines",
            vm_name,
            "libvirt",
            "id",
        )
        if not os.path.isfile(machine_id_path):
            return None

        with open(machine_id_path, "r", encoding="utf-8") as handle:
            machine_id = handle.read().strip()
        return machine_id or None

    def resolve_libvirt_domain(self, vm_name: str) -> str:
        self._ensure_command("virsh")

        machine_id = self._get_vagrant_libvirt_id(vm_name)
        if machine_id:
            try:
                self.run_host_command(
                    ["virsh", "dominfo", machine_id],
                    require_command="virsh",
                    sudo=True,
                )
                return machine_id
            except subprocess.CalledProcessError:
                pass

        listing = self.run_host_command(
            ["virsh", "list", "--all", "--name"],
            require_command="virsh",
            sudo=True,
        )
        candidates = [name.strip() for name in listing.stdout.splitlines() if name.strip()]

        for candidate in candidates:
            if candidate == vm_name:
                return candidate
        for candidate in candidates:
            if vm_name in candidate:
                return candidate

        raise RuntimeError(f"Could not resolve libvirt domain for VM '{vm_name}'")

    def resolve_victim_domain(self) -> str:
        return self.resolve_libvirt_domain(self.victim_vm)

    def get_domain_disk_source(self, domain: str) -> str:
        self._ensure_command("virsh")
        result = self.run_host_command(
            ["virsh", "domblklist", domain, "--details"],
            require_command="virsh",
            sudo=True,
        )

        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("Type") or line.startswith("----"):
                continue

            parts = line.split()
            if len(parts) < 4:
                continue

            block_type, device, _target, source = parts[0], parts[1], parts[2], parts[3]
            if block_type == "file" and device == "disk" and source != "-":
                return source

        raise RuntimeError(f"Could not determine disk source for domain '{domain}'")

    def get_victim_disk_source(self) -> str:
        domain = self.resolve_victim_domain()
        return self.get_domain_disk_source(domain)

    # ---------------------------
    # ISF management
    # ---------------------------

    def _get_builder_kernel(self) -> str:
        """
        Ask the isf-build VM for its running kernel version (uname -r).
        """
        result = self._run_vagrant(["ssh", self.builder_vm, "-c", "uname -r"])
        kernel = result.stdout.strip().split()[0]
        if not kernel:
            raise RuntimeError("Could not determine kernel version from isf-build VM")
        return kernel

    def _find_isf_for_kernel(self, kernel_version: str) -> str | None:
        """
        Return ISF filename matching the given kernel, or None.
        We treat any '*<kernel>.json' as compatible (prefix can vary).
        """
        if not os.path.isdir(self.isf_path):
            return None

        suffix = f"{kernel_version}.json"
        for name in os.listdir(self.isf_path):
            if name.endswith(suffix) and name.endswith(".json"):
                return name
        return None
    
    def halt_builder(self) -> None:
        """
        Power off the isf-build VM to free resources.
        """
        print(f"[*] Halting {self.builder_vm} VM...")
        try:
            self._run_vagrant(["halt", self.builder_vm])
        except subprocess.CalledProcessError as exc:
            raise RuntimeError("Failed to halt isf-build VM") from exc
        print(f"[+] {self.builder_vm} VM halted.")

    def destroy_builder(self) -> None:
        """
        Destroy the isf-build VM (for future multi-distro rebuild scenarios).
        """
        print(f"[*] Destroying {self.builder_vm} VM...")
        try:
            self._run_vagrant(["destroy", "-f", self.builder_vm])
        except subprocess.CalledProcessError as exc:
            raise RuntimeError("Failed to destroy isf-build VM") from exc
        print(f"[+] {self.builder_vm} VM destroyed.")


    def build_isf_if_missing(self) -> None:
        """
        Ensure there is an ISF JSON for the current isf-build kernel.
        """
        # Step 1: make sure isf-build exists and is up (no provision yet)
        print(f"[*] Ensuring {self.builder_vm} VM is up...")
        try:
            self._run_vagrant(["up", self.builder_vm])
        except subprocess.CalledProcessError as exc:
            raise RuntimeError("Failed to start isf-build VM") from exc

        # Step 2: discover kernel version on builder
        kernel = self._get_builder_kernel()
        print(f"[i] isf-build kernel version: {kernel}")

        # Step 3: check if we already have ISF for this kernel
        existing = self._find_isf_for_kernel(kernel)
        if existing:
            print(f"[i] ISF for kernel {kernel} already present: {existing}, skipping build.")
            self.halt_builder()
            return

        # Step 4: run full Ansible provision to build ISF
        print(f"[*] No ISF found for kernel {kernel}, running Ansible build...")
        try:
            self._run_vagrant(["provision", self.builder_vm])
        except subprocess.CalledProcessError as exc:
            raise RuntimeError("Failed to build ISF via Vagrant/Ansible") from exc

        # Step 5: verify again
        generated = self._find_isf_for_kernel(kernel)
        if not generated:
            raise RuntimeError(
                f"Build completed, but no ISF JSON found in shared/isf for kernel {kernel}"
            )

        print(f"[+] ISF generated: {generated} (saved in {self.isf_path})")
        self.halt_builder()

    # ---------------------------
    # Victim VM baseline + snapshot
    # ---------------------------

    def prepare_baseline(self) -> None:
        """
        Start and provision victim VM with baseline playbook.
        """
        print("[*] Starting/provisioning victim VM with baseline...")
        try:
            self._run_vagrant(["up", self.victim_vm, "--provision-with", "ansible"])
        except subprocess.CalledProcessError as exc:
            raise RuntimeError("Failed to start/provision victim VM") from exc

        # IP is static from Vagrantfile, but we keep a sanity check
        result = self._run_vagrant(["ssh", self.victim_vm, "-c", "hostname -I"])
        candidates = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", result.stdout)
        if candidates and self.target_ip not in candidates:
            # optional: update target_ip to what we see
            self.target_ip = candidates[0]

        print(f"[+] Victim VM reachable at {self.target_ip}")

    def create_snapshot(self, snapshot_name: str = "baseline") -> None:
        """
        Create a Vagrant snapshot for the victim VM if it does not exist.
        Run once after baseline is applied.
        """
        print(f"[*] Creating snapshot '{snapshot_name}' for victim VM...")
        if self.snapshot_exists(self.victim_vm, snapshot_name):
            print(f"[i] Snapshot '{snapshot_name}' already exists; reusing it.")
            return

        try:
            self._run_vagrant(["snapshot", "save", self.victim_vm, snapshot_name])
        except subprocess.CalledProcessError as exc:
            raise RuntimeError("Failed to create victim snapshot") from exc
        print(f"[+] Snapshot '{snapshot_name}' created.")

    def restore_snapshot(self, snapshot_name: str = "baseline") -> None:
        """
        Restore victim VM to a known snapshot before running a scenario.
        """
        print(f"[*] Restoring snapshot '{snapshot_name}' for victim VM...")
        try:
            self._run_vagrant(["snapshot", "restore", self.victim_vm, snapshot_name])
        except subprocess.CalledProcessError as exc:
            raise RuntimeError("Failed to restore victim snapshot") from exc
        print(f"[+] Victim VM restored to snapshot '{snapshot_name}'.")

    # ---------------------------
    # Backward-compatible wrappers
    # ---------------------------

    def halt_isf_builder(self) -> None:
        self.halt_builder()

    def destroy_isf_builder(self) -> None:
        self.destroy_builder()

    def prepare_victim_baseline(self) -> None:
        self.prepare_baseline()

    def create_victim_snapshot(self, snapshot_name: str = "baseline") -> None:
        self.create_snapshot(snapshot_name=snapshot_name)

    def restore_victim_snapshot(self, snapshot_name: str = "baseline") -> None:
        self.restore_snapshot(snapshot_name=snapshot_name)

    # ---------------------------
    # SSH and simple scenario (demo)
    # ---------------------------

    def _open_ssh(self) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(self.target_ip, **self.auth)
        return client

    def deploy_artifacts(self, exploit_bin: str, target_bin: str) -> None:
        """
        Transfer malicious and decoy binaries to the target.
        """
        client = self._open_ssh()
        sftp = client.open_sftp()
        sftp.put(exploit_bin, "/tmp/exploit_payload")
        sftp.put(target_bin, "/tmp/victim_process")
        sftp.close()
        client.exec_command("chmod +x /tmp/exploit_payload /tmp/victim_process")
        client.close()
        print("[+] Deployed /tmp/exploit_payload and /tmp/victim_process")

    def run_ptrace_demo(self, scenario_id: str = "ptrace_demo_01") -> None:
        """
        Minimal end-to-end demo: start decoy, run exploit, write ground truth.
        """
        client = self._open_ssh()

        client.exec_command("/tmp/victim_process &")
        time.sleep(1)

        _, stdout, _ = client.exec_command("pgrep -f victim_process")
        victim_pid = stdout.read().decode().strip()
        if not victim_pid:
            client.close()
            raise RuntimeError("Could not find victim_process PID on target")

        print(f"[*] Executing scenario {scenario_id} against PID {victim_pid}")
        client.exec_command(f"/tmp/exploit_payload --target {victim_pid}")
        client.exec_command("unset HISTFILE && rm -f ~/.bash_history")

        ground_truth = {
            "scenario": scenario_id,
            "target_pid": victim_pid,
            "timestamp": time.time(),
            "artifacts": ["/tmp/exploit_payload", "/tmp/victim_process"],
        }
        gt_path = os.path.join(self.results_path, f"gt_{scenario_id}.json")
        with open(gt_path, "w", encoding="utf-8") as f:
            json.dump(ground_truth, f, indent=4)

        client.close()
        print(f"[+] Ground truth saved to {gt_path}")
