# GT-blind detector unit tests over crafted raw outputs (no live tools needed).

import textwrap

from orchestrator.evaluation.detect import tsk_heuristics, vol3_heuristics
from orchestrator.evaluation.detect.plaso_sigma import detect as sigma_detect
from orchestrator.evaluation.detect.run import run_detection

_RULE_CFG = {
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


def test_sigma_file_event_rule_fires():
    # A vendored file_event rule (TripleCross "ebpfbackdoor") compiles to SQL and
    # fires on the matching filesystem-metadata row.
    events = [{"timestamp": 1700000000_000000, "data_type": "fs:stat",
               "filename": "/etc/cron.d/ebpfbackdoor"}]
    findings = list(sigma_detect({"plaso": events}, {}))
    assert findings
    f = findings[0]
    assert f.source_tool == "plaso_sigma" and f.rule_layer == "community"
    assert f.event_class == "file_created" and f.entity.value == "/etc/cron.d/ebpfbackdoor"
    assert f.technique == "T1053.003"


def test_sigma_keyword_rule_fires_via_fts():
    # Sigma full-text "keyword" rules cannot be expressed by the SQL backend, so
    # the detector evaluates them with SQLite FTS5 over the event text. The
    # vendored ld.so.preload rule (keyword /etc/ld.so.preload, T1574.006) fires,
    # and the entity is the IOC path itself -- even when matched in a log line.
    events = [
        {"timestamp": 1700000000_000000, "data_type": "fs:stat",
         "filename": "/etc/ld.so.preload"},
        {"timestamp": 1700000001_000000, "data_type": "syslog:line",
         "filename": "/var/log/auth.log",
         "message": "sudo: sh -c echo x > /etc/ld.so.preload"},
    ]
    findings = list(sigma_detect({"plaso": events}, {}))
    preload = [f for f in findings if f.entity.value == "/etc/ld.so.preload"]
    assert preload, "ld.so.preload keyword rule should fire via FTS5"
    f = preload[0]
    assert f.source_tool == "plaso_sigma" and f.entity.type == "path"
    assert f.event_class == "file_created" and f.technique == "T1574.006"
    # The log-line mention maps to the IOC, not to /var/log/auth.log.
    assert all(f2.entity.value != "/var/log/auth.log" for f2 in findings)


def test_sigma_gate_skips_filestat_for_process_rule(tmp_path):
    # A process_creation rule must not fire on a bare filesystem-metadata row (a
    # file existing under /tmp is not proof it executed); it may fire on a real
    # execution event. Uses a throwaway rule dir so the test is self-contained.
    (tmp_path / "proc.yml").write_text(textwrap.dedent("""
        title: Temp Exec
        id: 00000000-0000-0000-0000-000000000001
        status: test
        logsource: {product: linux, category: process_creation}
        detection:
          sel: {Image|startswith: '/tmp/'}
          condition: sel
        tags: [attack.t1059.004]
    """).strip(), encoding="utf-8")
    events = [
        {"timestamp": 1700000000_000000, "data_type": "fs:stat", "filename": "/tmp/payload"},
        {"timestamp": 1700000001_000000, "executable": "/tmp/payload"},
    ]
    cfg = {"sigma_vendored_dirs": [str(tmp_path)]}
    refs = {f.raw_ref for f in sigma_detect({"plaso": events}, cfg)}
    assert "plaso_sigma:event:1" in refs  # real execution fired
    assert "plaso_sigma:event:0" not in refs  # filestat row gated out


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


def test_tsk_temp_nonexec_and_fifo_created():
    # No-cleanup coverage: a non-exec drop (discovery output) and a FIFO in /tmp
    # are created artifacts even without the exec bit; a directory stays excluded.
    body = "\n".join(
        [
            "0|/tmp/T1082.txt|11|r/rrw-r--r--|0|0|800|1700000000|1700000000|1700000000|1700000000",
            "0|/tmp/.rs_fifo|12|p/prw-r--r--|0|0|0|1700000000|1700000000|1700000000|1700000000",
            "0|/tmp/.X11-unix|13|d/drwxrwxrwt|0|0|4096|1700000000|1700000000|1700000000|1700000000",
        ]
    )
    raw = {"tsk": {"bodyfile": body}}
    created = [
        f for f in tsk_heuristics.detect(raw, _RULE_CFG) if f.event_class == "file_created"
    ]
    assert {f.entity.value for f in created} == {"/tmp/T1082.txt", "/tmp/.rs_fifo"}
    assert all(f.detector == "tsk:temp_file_created" for f in created)


def test_tsk_ld_preload_persistence():
    # /etc/ld.so.preload is the T1574.006 persistence mechanism path.
    body = "0|/etc/ld.so.preload|22|r/rrw-r--r--|0|0|18|1700000000|1700000000|1700000000|1700000000"
    raw = {"tsk": {"bodyfile": body}}
    found = [
        f for f in tsk_heuristics.detect(raw, _RULE_CFG)
        if f.detector == "tsk:persistence_path_created"
    ]
    assert len(found) == 1
    assert found[0].entity.value == "/etc/ld.so.preload"
    assert found[0].event_class == "persistence_installed"
    assert found[0].technique == "T1574.006"


def test_tsk_timestamp_anomaly():
    body = "0|/tmp/x|1|r/rrwxr-xr-x|0|0|10|1700000000|1700000000|1700000000|1700000500"
    raw = {"tsk": {"bodyfile": body}}
    anomalies = [
        f for f in tsk_heuristics.detect(raw, _RULE_CFG)
        if f.detector == "tsk:timestamp_anomaly"
    ]
    assert len(anomalies) == 1


def test_run_detection_assigns_sorted_ids():
    raw = {
        "vol3": {"linux.psscan": [{"PID": 9, "Comm": "x"}], "linux.pslist": []},
        "tsk": {"bodyfile": "0|/tmp/a (deleted)|1|r/r|0|0|1|1|1|1|1"},
    }
    findings = run_detection(raw, _RULE_CFG)
    ids = [f.finding_id for f in findings]
    assert ids == sorted(ids)
    assert all(fid.startswith("f-") for fid in ids)
