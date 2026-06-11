# GT-blind detector unit tests over crafted raw outputs (no live tools needed).

from pathlib import Path

from orchestrator.evaluation.detect import tsk_heuristics, vol3_heuristics
from orchestrator.evaluation.detect.plaso_sigma import detect as sigma_detect
from orchestrator.evaluation.detect.run import run_detection

_RULE_CFG = {
    "sigma_rule_dirs": [
        str(Path(__file__).resolve().parent.parent / "config" / "rules" / "custom")
    ],
    "vol3": {"private_ranges": ["192.168.100.0/24"]},
}


def test_vol3_hidden_process():
    raw = {
        "vol3": {
            "linux.pslist": [{"PID": 100, "Comm": "bash"}],
            "linux.psscan": [{"PID": 100, "Comm": "bash"}, {"PID": 666, "Comm": "evil"}],
        }
    }
    findings = list(vol3_heuristics.detect(raw, _RULE_CFG))
    hidden = [f for f in findings if f.detector == "vol3:hidden_process"]
    assert len(hidden) == 1
    assert hidden[0].entity.value == "evil"
    assert hidden[0].ts_quality == "none"


def test_vol3_suspicious_socket():
    # Real vol3 linux.sockstat schema: Source/Destination Addr+Port + State.
    raw = {
        "vol3": {
            "linux.sockstat": [
                # Reverse shell: outbound (ephemeral source) to a non-service
                # remote port on the lab's private net -> flagged.
                {
                    "PID": 765, "Process Name": "nc", "Proto": "TCP", "State": "ESTABLISHED",
                    "Source Addr": "192.168.100.36", "Source Port": "39996",
                    "Destination Addr": "192.168.100.1", "Destination Port": "4444",
                },
                # SSH management channel: service source port 22, ephemeral
                # remote -> NOT flagged (not an outbound-to-unusual-port).
                {
                    "PID": 620, "Process Name": "sshd", "Proto": "TCP", "State": "ESTABLISHED",
                    "Source Addr": "192.168.100.36", "Source Port": "22",
                    "Destination Addr": "192.168.100.1", "Destination Port": "53136",
                },
                # Listening socket: no real peer -> NOT flagged.
                {
                    "PID": 527, "Process Name": "sshd", "Proto": "TCP", "State": "LISTEN",
                    "Source Addr": "0.0.0.0", "Source Port": "22",
                    "Destination Addr": "0.0.0.0", "Destination Port": "0",
                },
                # Genuinely external address: flagged regardless of port.
                {
                    "PID": 800, "Process Name": "curl", "Proto": "TCP", "State": "ESTABLISHED",
                    "Source Addr": "192.168.100.36", "Source Port": "443",
                    "Destination Addr": "8.8.8.8", "Destination Port": "443",
                },
            ]
        }
    }
    socks = [
        f for f in vol3_heuristics.detect(raw, _RULE_CFG)
        if f.detector == "vol3:suspicious_socket"
    ]
    values = {f.entity.value for f in socks}
    assert values == {"192.168.100.1:4444", "8.8.8.8:443"}
    assert all(f.event_class == "network_connection" for f in socks)


def test_vol3_hidden_process_ignores_nameless():
    # psscan-only rows with an empty command are pool noise, not hidden tasks.
    raw = {
        "vol3": {
            "linux.pslist": [{"PID": 100, "Process Name": "bash"}],
            "linux.psscan": [
                {"PID": 100, "Process Name": "bash"},
                {"PID": 666, "Process Name": "evil"},
                {"PID": 700, "Process Name": ""},
            ],
        }
    }
    hidden = [
        f for f in vol3_heuristics.detect(raw, _RULE_CFG)
        if f.detector == "vol3:hidden_process"
    ]
    assert {f.entity.value for f in hidden} == {"evil"}


def test_tsk_temp_exec_skips_directories():
    # Directories carry the x bit (mode 1777); only regular files are temp execs.
    body = "\n".join(
        [
            "0|/tmp/.X11-unix|11|d/drwxrwxrwt|0|0|4096|1700000000|1700000000|1700000000|1700000000",
            "0|/tmp/payload|12|r/rrwxr-xr-x|0|0|120|1700000000|1700000000|1700000000|1700000000",
        ]
    )
    raw = {"tsk": {"bodyfile": body}}
    created = [
        f for f in tsk_heuristics.detect(raw, _RULE_CFG)
        if f.detector == "tsk:temp_exec_created"
    ]
    assert {f.entity.value for f in created} == {"/tmp/payload"}


def test_sigma_process_rule_skips_filestat():
    # A process_creation rule must not fire on a filesystem-metadata event.
    events = [
        {"timestamp": 1700000000_000000, "data_type": "fs:stat", "parser": "filestat",
         "filename": "/tmp/.ICE-unix", "message": "EXT:/tmp/.ICE-unix Type: directory"},
        {"timestamp": 1700000001_000000, "executable": "/tmp/payload", "message": "ran /tmp/payload"},
    ]
    raw = {"plaso": events}
    findings = [f for f in sigma_detect(raw, _RULE_CFG) if f.detector == "sigma:lnx_tmp_exec"]
    assert {str(f.entity.value) for f in findings} == {"/tmp/payload"} or all(
        ".ICE-unix" not in str(f.entity.value) for f in findings
    )


def test_tsk_deleted_and_persistence():
    body = "\n".join(
        [
            "0|/tmp/.evil.sh (deleted)|111|r/rrwxr-xr-x|0|0|120|1700000000|1700000000|1700000000|1700000000",
            "0|/etc/cron.d/backdoor|222|r/rrw-r--r--|0|0|50|1700000100|1700000100|1700000100|1700000100",
            "0|/usr/bin/ls|333|r/rrwxr-xr-x|0|0|100|1600000000|1600000000|1600000000|1600000000",
        ]
    )
    raw = {"tsk": {"bodyfile": body}}
    findings = list(tsk_heuristics.detect(raw, _RULE_CFG))
    by_det = {f.detector for f in findings}
    assert "tsk:deleted_recoverable" in by_det
    assert "tsk:persistence_path_created" in by_det
    deleted = next(f for f in findings if f.detector == "tsk:deleted_recoverable")
    assert deleted.event_class == "file_deleted"
    assert deleted.ts_quality == "wallclock" and deleted.ts_utc is not None


def test_tsk_timestamp_anomaly():
    body = "0|/tmp/x|1|r/rrwxr-xr-x|0|0|10|1700000000|1700000000|1700000000|1700000500"
    raw = {"tsk": {"bodyfile": body}}
    anomalies = [
        f for f in tsk_heuristics.detect(raw, _RULE_CFG)
        if f.detector == "tsk:timestamp_anomaly"
    ]
    assert len(anomalies) == 1


def test_sigma_custom_tmp_exec_fires():
    events = [
        {"timestamp": 1700000000_000000, "executable": "/tmp/payload", "message": "ran /tmp/payload"},
        {"timestamp": 1700000001_000000, "executable": "/usr/bin/ls", "message": "ran ls"},
    ]
    raw = {"plaso": events}
    findings = [f for f in sigma_detect(raw, _RULE_CFG) if f.detector == "sigma:lnx_tmp_exec"]
    assert len(findings) == 1
    assert findings[0].rule_layer == "custom"
    assert "/tmp/payload" in str(findings[0].entity.value)


def test_run_detection_assigns_sorted_ids():
    raw = {
        "vol3": {"linux.psscan": [{"PID": 9, "Comm": "x"}], "linux.pslist": []},
        "tsk": {"bodyfile": "0|/tmp/a (deleted)|1|r/r|0|0|1|1|1|1|1"},
    }
    findings = run_detection(raw, _RULE_CFG)
    ids = [f.finding_id for f in findings]
    assert ids == sorted(ids)
    assert all(fid.startswith("f-") for fid in ids)
