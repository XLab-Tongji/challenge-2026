"""Metric evidence retains detector diagnostics and honest collection coverage."""

from datetime import datetime, timedelta
import json
from pathlib import Path

from baseline.netcluster.anomaly_detector.metric.output import (
    metric_parts, score_kind, standard_evidence_row, write_coverage,
)


def _event(metric_id: str, minute: str, event_type: str = "metric_anomaly") -> dict:
    return {
        "metric_name": metric_id,
        "start_time": minute,
        "end_time": minute,
        "point_index": 1,
        "event_type": event_type,
        "component": "raw",
        "detector": "historical_null_check" if event_type == "missing_value" else "local_mad_raw",
        "direction": "" if event_type == "missing_value" else "high",
        "severity": 1.0 if event_type == "missing_value" else 7.5,
        "raw_value": None if event_type == "missing_value" else 20.0,
        "observed_value": "" if event_type == "missing_value" else 20.0,
        "baseline_value": "observed_history" if event_type == "missing_value" else 10.0,
        "generation_model": "direct_local_mad_raw",
        "metric_shape": "direct",
        "profile": {"periodic_minutes": None, "trend_score": 0.25},
    }


def test_metric_event_preserves_labels_score_and_raw_location():
    name = "beida.br-1.routing_metrics.bgp_peer_up__label_urlencoded_peer%3D%22fd00%3A%3A1%22"
    row = standard_evidence_row(_event(name, "2026-08-19 04:01:00"), Path("wide.csv"))
    assert set(row) == {
        "evidence_id", "episode_id", "start_minute", "last_seen_minute",
        "entity_id", "modality", "feature", "anomaly_kind", "direction",
        "raw_score", "score_kind", "reliability", "observed", "attributes",
    }
    assert row["feature"] == "bgp_peer_up"
    assert row["entity_id"] == "beida-br-1"
    assert row["direction"] == "up"
    assert row["score_kind"] == "local_mad_z"
    assert row["raw_score"] == 7.5
    assert row["reliability"] is None
    assert row["attributes"]["labels"] == {"peer": "fd00::1"}
    assert row["attributes"]["source_row"] == 3
    assert row["attributes"]["baseline_value"] == 10.0
    assert row["attributes"]["profile"]["trend_score"] == 0.25
    assert standard_evidence_row(_event(name, "2026-08-19 04:01:00"), Path("wide.csv"))["evidence_id"] == row["evidence_id"]
    assert score_kind("ecod_raw+local_mad") == "max_ecod_tail_log_or_local_mad_z"


def test_missing_sample_is_not_present_evidence_and_coverage_is_compact(tmp_path: Path):
    name = "beida.br-1.interface_metrics.ens3_rx_drop_rate"
    times = [datetime(2026, 8, 19, 4) + timedelta(minutes=index) for index in range(5)]
    missing = _event(name, "2026-08-19 04:01:00", "missing_value")
    row = standard_evidence_row(missing, tmp_path / "wide.csv")
    assert row["observed"] is False
    assert row["direction"] is None
    assert row["attributes"]["expected_basis"] == "historical_null_check"
    assert metric_parts(name)[3:] == ("rx_drop_rate", {"interface": "ens3"})

    target = tmp_path / "observation_coverage.jsonl"
    count = write_coverage(times, {name: [1.0, None, None, 2.0, 3.0]},
                           [missing], tmp_path / "wide.csv", target)
    intervals = [json.loads(line) for line in target.read_text(encoding="utf-8").splitlines()]
    assert count == 4
    assert [item["status"] for item in intervals] == ["observed", "missing", "unknown", "observed"]
    assert intervals[1]["expected"] is True
    assert intervals[2]["expected"] is None
    assert intervals[3]["last_seen_minute"] == "2026-08-19 04:04:00"
    assert intervals[3]["observed_count"] == 2
