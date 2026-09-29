"""Behavioral tests for the bounded-memory five-tuple detector."""

import csv
from datetime import datetime, timedelta
import json
from pathlib import Path

from baseline.netcluster.anomaly_detector.network_flow.five_tuple import (
    detect_router, load_config)
from baseline.netcluster.cli.run_netflow_5tuple_detection import group_symptoms, run


FIELDS = ("entity", "minute_utc", "region_code", "region", "interface_id",
          "if_role", "collector_port", "protocol", "protocol_name", "src_addr",
          "src_port", "src_region_inferred", "dst_addr", "dst_port",
          "dst_region_inferred", "packets", "bytes", "flow_record_count",
          "first_seen", "last_seen")


def _series_file(tmp_path: Path, rows: list[dict]) -> Path:
    path = tmp_path / "first_stage" / "beida" / "br-1" / "netflow" / "netflow_5tuple.csv"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    return path


def _row(index: int, *, protocol: str = "6", packets: int = 40,
         byte_count: int = 8000, port: int = 80,
         cross_region: bool = True) -> dict:
    minute = (datetime(2026, 8, 1) + timedelta(minutes=index)).strftime(
        "%Y-%m-%d %H:%M:%S")
    row = {key: "" for key in FIELDS}
    row.update(entity="br-1", minute_utc=minute, region_code="beida",
               interface_id="ens4", protocol=protocol, src_addr="client",
               src_port="40000", dst_addr="server", dst_port=str(port),
               src_region_inferred="beida" if cross_region else "NULL",
               dst_region_inferred="shanghai" if cross_region else "NULL",
               packets=str(packets), bytes=str(byte_count), flow_record_count="1")
    return row


def _events(tmp_path: Path, rows: list[dict], config_overrides: dict | None = None):
    path = _series_file(tmp_path, rows)
    config = load_config(Path(__file__).resolve().parents[1] /
                         "baseline/netcluster/config/netflow_5tuple_detection.json")
    config["chunk_rows"] = 12
    config.update(config_overrides or {})
    result = detect_router((path,), tmp_path / "out", config)
    events = [json.loads(line) for line in
              (tmp_path / "out" / result["evidence_file"]).read_text(encoding="utf-8").splitlines()]
    return events, result


def test_opposite_direction_absence_requires_historic_bidirectionality(tmp_path: Path):
    path = tmp_path / "first_stage" / "beida" / "br-1" / "netflow" / "netflow_5tuple.csv"
    path.parent.mkdir(parents=True)
    start = datetime(2026, 8, 1)
    rows = []
    for index in range(38):
        minute = (start + timedelta(minutes=index)).strftime("%Y-%m-%d %H:%M:%S")
        base = {key: "" for key in FIELDS}
        base.update(entity="br-1", minute_utc=minute, region_code="beida",
                    interface_id="ens4", protocol="17", packets="20", bytes="2000",
                    flow_record_count="1")
        rows.append({**base, "src_addr": "host_a", "dst_addr": "host_b",
                     "src_port": "40000", "dst_port": "53",
                     "src_region_inferred": "beida", "dst_region_inferred": "shanghai"})
        if index < 35:
            rows.append({**base, "src_addr": "host_b", "dst_addr": "host_a",
                         "src_port": "53", "dst_port": "40000",
                         "src_region_inferred": "shanghai", "dst_region_inferred": "beida"})
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(reversed(rows))  # Real files are not guaranteed to be sorted.
    config = load_config(Path(__file__).resolve().parents[1] /
                         "baseline/netcluster/config/netflow_5tuple_detection.json")
    config["chunk_rows"] = 10
    result = detect_router((path,), tmp_path / "out", config)
    assert result["scanned_rows"] == 73
    events = [json.loads(line) for line in
              (tmp_path / "out" / result["evidence_file"]).read_text(encoding="utf-8").splitlines()]
    absence = [event for event in events if event["feature"] == "regional_opposite_presence"]
    assert len(absence) == 1
    assert absence[0]["start_minute"] == "2026-08-01 00:35:00"
    assert absence[0]["last_seen_minute"] == "2026-08-01 00:37:00"
    assert absence[0]["reliability"] is None
    assert absence[0]["observed"] is True


def test_volume_drop_preserves_unknown_export_gap(tmp_path: Path):
    path = tmp_path / "first_stage" / "beida" / "cr-1" / "netflow" / "netflow_5tuple.csv"
    path.parent.mkdir(parents=True)
    start = datetime(2026, 8, 1)
    rows = []
    for index in range(38):
        if index == 20:
            continue
        row = {key: "" for key in FIELDS}
        row.update(entity="cr-1", minute_utc=(start + timedelta(minutes=index)).strftime(
                       "%Y-%m-%d %H:%M:%S"), interface_id="ens5", protocol="6",
                   src_addr="host", dst_addr="server", src_port="30000", dst_port="80",
                   packets="100", bytes="10000" if index >= 35 else "200000")
        rows.append(row)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(reversed(rows))
    config = load_config(Path(__file__).resolve().parents[1] /
                         "baseline/netcluster/config/netflow_5tuple_detection.json")
    config["chunk_rows"] = 10
    result = detect_router((path,), tmp_path / "out", config)
    events = [json.loads(line) for line in
              (tmp_path / "out" / result["evidence_file"]).read_text(encoding="utf-8").splitlines()]
    assert len(events) == 1
    assert events[0]["feature"] == "interface_bytes"
    assert events[0]["direction"] == "down"
    assert events[0]["start_minute"] == "2026-08-01 00:35:00"
    assert events[0]["last_seen_minute"] == "2026-08-01 00:37:00"
    assert result["unknown_minutes"] == 1
    coverage = [json.loads(line) for line in
                (tmp_path / "out" / result["coverage_file"]).read_text(encoding="utf-8").splitlines()]
    assert coverage[20]["status"] == "unknown"
    assert coverage[20]["expected"] is None


def test_stable_region_port_flow_disappearance_requires_live_interface(tmp_path: Path):
    rows = []
    for index in range(38):
        rows.append(_row(index, byte_count=3000, cross_region=False))
        if index < 35:
            rows.append(_row(index, byte_count=2000))
    events, _ = _events(tmp_path, rows)
    drops = [event for event in events if event["feature"] == "region_port_bytes"
             and event["direction"] == "down"]
    assert len(drops) == 1
    assert drops[0]["start_minute"] == "2026-08-01 00:35:00"
    assert drops[0]["last_seen_minute"] == "2026-08-01 00:37:00"
    assert drops[0]["attributes"]["last_observed"]["bytes"] == 0
    assert drops[0]["attributes"]["inferred_zero"] is True
    assert drops[0]["attributes"]["contains_inferred_zero"] is True
    assert drops[0]["attributes"]["interface_coverage_packets"] == 40
    assert drops[0]["attributes"]["baseline_samples"] >= 30


def test_control_flow_disappearance_is_detected_with_other_interface_traffic(tmp_path: Path):
    rows = []
    for index in range(38):
        rows.append(_row(index, packets=50, cross_region=False))
        if index < 35:
            rows.append(_row(index, protocol="89", packets=12, byte_count=1200,
                             port=0, cross_region=False))
    events, _ = _events(tmp_path, rows)
    control = [event for event in events if event["feature"] == "control_packets"
               and event["direction"] == "down"]
    assert len(control) == 1
    assert control[0]["attributes"]["last_observed"]["packets"] == 0


def test_udp_packet_burst_has_its_own_feature(tmp_path: Path):
    rows = [_row(index, protocol="17", packets=50 if index < 35 else 6000,
                 byte_count=5000 if index < 35 else 600000,
                 port=1053, cross_region=False) for index in range(38)]
    events, _ = _events(tmp_path, rows)
    udp = [event for event in events if event["feature"] == "interface_udp_small_packets"]
    assert len(udp) == 1
    assert udp[0]["direction"] == "up"


def test_volume_baseline_adapts_to_persistent_high_mode(tmp_path: Path):
    rows = [_row(index, byte_count=200000 if index < 40 else 450000,
                 cross_region=False) for index in range(150)]
    events, _ = _events(tmp_path, rows)
    high = [event for event in events if event["feature"] == "interface_bytes"
            and event["direction"] == "up"]
    assert high
    assert high[-1]["last_seen_minute"] < "2026-08-01 02:00:00"


def test_region_port_workload_rise_does_not_emit_fault_symptom(tmp_path: Path):
    rows = [_row(index, byte_count=12000 if index < 35 else 60000)
            for index in range(38)]
    events, _ = _events(tmp_path, rows)
    assert not any(event["feature"] == "region_port_bytes" for event in events)


def test_zero_fill_does_not_cross_export_gap(tmp_path: Path):
    rows = [_row(index, byte_count=12000) for index in range(35)]
    after_gap = _row(39, byte_count=3000, cross_region=False)
    rows.append(after_gap)
    events, result = _events(tmp_path, rows)
    assert result["unknown_minutes"] == 4
    assert not any(event["feature"] == "region_port_bytes" for event in events)


def test_large_udp_packets_do_not_trigger_small_packet_pressure(tmp_path: Path):
    rows = [_row(index, protocol="17", packets=50 if index < 35 else 6000,
                 byte_count=75000 if index < 35 else 9000000,
                 port=5201, cross_region=False) for index in range(38)]
    events, _ = _events(tmp_path, rows)
    assert not any(event["feature"] == "interface_udp_small_packets" for event in events)


def test_directional_group_preserves_each_router_evidence():
    attrs = {"protocol": "17", "port_group": "1053",
             "region_a_inferred": "beida", "region_b_inferred": "shanghai",
             "active_direction": "a_to_b"}
    first = {"evidence_id": "a", "entity_id": "beida-br-1",
             "feature": "regional_opposite_presence", "direction": "absent",
             "start_minute": "2026-08-01 00:35:00",
             "last_seen_minute": "2026-08-01 00:37:00", "attributes": attrs}
    second = {**first, "evidence_id": "b", "entity_id": "beida-cr-1"}
    groups = group_symptoms([first, second])
    assert len(groups) == 1
    assert groups[0]["observer_count"] == 2
    assert groups[0]["evidence_ids"] == ["a", "b"]


def test_runner_writes_grouped_review_without_dropping_evidence(tmp_path: Path):
    rows = [_row(index, protocol="17", packets=50 if index < 35 else 6000,
                 byte_count=5000 if index < 35 else 600000,
                 port=1053, cross_region=False) for index in range(38)]
    _series_file(tmp_path, rows)
    config_path = (Path(__file__).resolve().parents[1] /
                   "baseline/netcluster/config/netflow_5tuple_detection.json")
    result = run(tmp_path / "first_stage", tmp_path / "result", config_path)
    assert result["detector_version"] == "netflow-5tuple-v3"
    assert result["evidence_episodes"] == 1
    assert result["feature_counts"] == {"interface_udp_small_packets": 1}
    assert result["symptom_group_count"] == 1
    assert (tmp_path / "result" / "symptom_groups.jsonl").is_file()
