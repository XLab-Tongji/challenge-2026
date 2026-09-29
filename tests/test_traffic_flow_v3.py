"""Regression cases for traffic-flow anomaly feature extraction."""

from datetime import datetime, timedelta
from pathlib import Path

import csv


def write_series(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def rows_for(kind: str, count: int) -> list[dict]:
    rows = []
    for index in range(count):
        minute = (datetime(2026, 8, 1) + timedelta(minutes=index)).strftime(
            "%Y-%m-%d %H:%M:%S")
        rows.append({"timestamp_utc": minute, "prometheus_sample_time_utc": minute,
                     "series_key": f"{kind}-series", "flow_type": kind,
                     "source_region": "beida", "source_ip": "fd00::1",
                     "target_region": "shanghai", "target_domain": f"{kind}.example",
                     "protocol": "http", "requests_total": 100 * index,
                     "success_total": 100 * index, "error_total": 0,
                     "batches_started_total": index,
                     "batches_completed_total": index,
                     "batches_failed_total": 0, "batches_timeout_total": 0,
                     "latency_p95_seconds": 0.05})
    return rows
from baseline.netcluster.anomaly_detector.network_flow.traffic_flow_v3 import (
    detect_file, load_config)
from baseline.netcluster.cli.run_traffic_flow_anomaly_detection import run


CONFIG = Path(__file__).resolve().parents[1] / "baseline/netcluster/config/traffic_flow_detection_v3.json"


def test_common_high_latency_mode_is_not_anomaly_but_new_shift_is(tmp_path: Path):
    rows = rows_for("web", 135)
    for index, row in enumerate(rows):
        row["observed_qps"] = 4
        row["latency_p95_seconds"] = 0.02 if index % 2 == 0 else 0.22
    for index in range(131, 135):
        rows[index]["latency_p95_seconds"] = 0.36
    path = tmp_path / "web.csv"
    write_series(path, rows)
    events, _, _ = detect_file(path, load_config(CONFIG))
    latency = [event for event in events if event["feature"] == "latency_p95_seconds"]
    assert len(latency) == 1
    assert latency[0]["start_minute"] == rows[131]["timestamp_utc"]
    assert latency[0]["last_seen_minute"] == rows[134]["timestamp_utc"]


def test_histogram_tail_increase_is_detected_from_counter_increments(tmp_path: Path):
    rows = rows_for("web", 80)
    for index, row in enumerate(rows):
        row["request_latency_seconds_count"] = 100 * index
        row["request_latency_seconds_bucket_le_1"] = 100 * index
    for index in range(76, 80):
        rows[index]["request_latency_seconds_bucket_le_1"] -= 50 * (index - 75)
    path = tmp_path / "web.csv"
    write_series(path, rows)
    events, _, _ = detect_file(path, load_config(CONFIG))
    tail = [event for event in events if event["feature"] == "latency_tail_ratio"]
    assert len(tail) == 1
    assert tail[0]["start_minute"] == rows[76]["timestamp_utc"]
    assert tail[0]["last_seen_minute"] == rows[79]["timestamp_utc"]


def test_elephant_completion_emits_loss_once_despite_repeated_snapshot(tmp_path: Path):
    rows = rows_for("elephant", 4)
    for index, row in enumerate(rows):
        minute = datetime(2026, 8, 1) + timedelta(hours=index)
        row["timestamp_utc"] = minute.strftime("%Y-%m-%d %H:%M:%S")
        row["prometheus_sample_time_utc"] = row["timestamp_utc"]
        row["throughput_bps"] = 20_000_000
        row["loss_rate"] = 0.03 if index >= 2 else 0
        row["jitter_seconds"] = 0.00005
        row["batches_completed_total"] = 1 if index == 1 else 2 if index >= 2 else 0
    path = tmp_path / "elephant.csv"
    write_series(path, rows)
    events, coverage, _ = detect_file(path, load_config(CONFIG))
    loss = [event for event in events if event["feature"] == "elephant_loss_rate"]
    assert len(loss) == 1
    assert loss[0]["start_minute"] == rows[2]["timestamp_utc"]
    assert len(coverage) == 4


def test_elephant_normal_rate_mode_switch_is_not_throughput_anomaly(tmp_path: Path):
    rows = rows_for("elephant", 8)
    for index, row in enumerate(rows):
        row["throughput_bps"] = 50_000_000 if index < 7 else 20_000_000
        row["loss_rate"] = 0
        row["jitter_seconds"] = 0.00005
    path = tmp_path / "elephant.csv"
    write_series(path, rows)
    events, _, _ = detect_file(path, load_config(CONFIG))
    assert not any(event["feature"] == "elephant_throughput_bps"
                   for event in events)


def test_runner_selects_v3_and_writes_compatible_outputs(tmp_path: Path):
    data_root = tmp_path / "data"
    path = data_root / "beida" / "traffic-vm" / "traffic_flow" / "web.csv"
    path.parent.mkdir(parents=True)
    write_series(path, rows_for("web", 4))
    output = tmp_path / "result"
    manifest = run(data_root, output, CONFIG)
    assert manifest["detector_version"] == "traffic-flow-v3.1"
    assert manifest["file_count"] == 1
    assert (output / "evidence_events.jsonl").is_file()
    assert (output / "observation_coverage.jsonl").is_file()


def test_error_baseline_includes_valid_alert_windows_without_hiding_severe_errors(tmp_path: Path):
    rows = rows_for("web", 105)
    for index in range(1, 105):
        rows[index]["error_total"] = 50 * index
        rows[index]["success_total"] = 50 * index
    path = tmp_path / "web.csv"
    write_series(path, rows)
    events, _, _ = detect_file(path, load_config(CONFIG))
    errors = [event for event in events if event["feature"] == "request_error_ratio"]
    assert len(errors) == 1
    assert errors[0]["last_seen_minute"] == rows[-1]["timestamp_utc"]
    assert errors[0]["attributes"]["episode_request_count"] == 10_400
    assert errors[0]["attributes"]["episode_error_count"] == 5_200
    assert errors[0]["attributes"]["episode_valid_windows"] == 104
    assert errors[0]["attributes"]["last_baseline"] == 0.5


def test_timeout_event_accumulates_all_completed_batches(tmp_path: Path):
    rows = rows_for("web", 6)
    for index in range(2, 6):
        rows[index]["batches_completed_total"] = 1
        rows[index]["batches_failed_total"] = index - 1
        rows[index]["batches_timeout_total"] = index - 1
    path = tmp_path / "web.csv"
    write_series(path, rows)
    events, _, _ = detect_file(path, load_config(CONFIG))
    timeout = [event for event in events if event["feature"] == "batch_timeout_ratio"]
    assert len(timeout) == 1
    assert timeout[0]["attributes"]["episode_finished_batches"] == 4
    assert timeout[0]["attributes"]["episode_timeout_count"] == 4
    assert timeout[0]["attributes"]["episode_valid_windows"] == 4
