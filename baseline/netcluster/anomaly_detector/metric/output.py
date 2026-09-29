"""Lossless state-machine evidence and compact observation coverage for metrics."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
import hashlib
import json
import math
from pathlib import Path
import re
from typing import Any, Iterable
from urllib.parse import unquote


VERSION = "metric-output-v1"
MINUTE = timedelta(minutes=1)
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
INTERFACE_PREFIX = re.compile(r"^(ens\d+)_(.+)$")
LABEL = re.compile(r'(\w+)="([^"]*)"')


def _identity(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:24]


def _value(value: Any) -> Any:
    if value is None or value == "":
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


def metric_parts(metric_id: str) -> tuple[str, str, str, str, dict[str, str]]:
    city, node, source, column = metric_id.split(".", 3)
    feature = column
    labels: dict[str, str] = {}
    if "__label_urlencoded_" in feature:
        feature, encoded = feature.split("__label_urlencoded_", 1)
        decoded = unquote(encoded)
        labels = dict(LABEL.findall(decoded))
        if not labels:
            labels = {"unparsed": decoded}
    if "__target_urlencoded_" in feature:
        prefix, encoded_and_name = feature.split("__target_urlencoded_", 1)
        if "__" in encoded_and_name:
            encoded, suffix = encoded_and_name.rsplit("__", 1)
            feature = f"{prefix}__{suffix}"
            labels["target"] = unquote(encoded)
    match = INTERFACE_PREFIX.fullmatch(feature)
    if match:
        labels["interface"] = match.group(1)
        feature = match.group(2)
    return city, node, source, feature, labels


def score_kind(detector: str) -> str:
    if detector == "historical_null_check":
        return "historical_null_indicator"
    if detector in {"configured_state", "rare_state"}:
        return "state_rule_indicator"
    if "+local_mad" in detector:
        return "max_ecod_tail_log_or_local_mad_z"
    if detector.startswith("ecod"):
        return "ecod_tail_log_score"
    if detector.startswith("local_mad"):
        return "local_mad_z"
    return "detector_score"


def standard_evidence_row(event: dict[str, Any], testset_csv: Path) -> dict[str, Any]:
    metric_id = str(event["metric_name"])
    city, node, source, feature, labels = metric_parts(metric_id)
    start = str(event["start_time"])
    detector = str(event["detector"])
    event_type = str(event["event_type"])
    missing = event_type == "missing_value"
    original_direction = str(event.get("direction") or "")
    direction = {"high": "up", "low": "down", "up": "up", "down": "down"}.get(original_direction)
    identity = _identity(VERSION, metric_id, event_type,
                         str(event["component"]), detector, start)
    attributes = {
        "metric_id": metric_id,
        "metric_column": metric_id.split(".", 3)[3],
        "metric_source": source,
        "source_ref": str(testset_csv),
        "source_column": metric_id,
        "source_row": event.get("point_index", -1) + 2,
        "labels": labels,
        "dependency_id": _identity(city, node, metric_id),
        "detector_version": VERSION,
        "detector": detector,
        "generation_model": event.get("generation_model"),
        "metric_shape": event.get("metric_shape"),
        "component": event.get("component"),
        "event_type": event_type,
        "original_direction": original_direction or None,
        "severity": _value(event.get("severity")),
        "raw_value": _value(event.get("raw_value")),
        "observed_value": _value(event.get("observed_value")),
        "baseline_value": _value(event.get("baseline_value")),
        "residual": _value(event.get("residual")),
        "change_time": _value(event.get("change_time")),
        "old_model_params": _value(event.get("old_model_params")),
        "new_model_params": _value(event.get("new_model_params")),
        "reason": event.get("reason"),
        "profile": event.get("profile"),
        "reliability_missing_reason": "not_calibrated",
    }
    if missing:
        attributes["expected_basis"] = "historical_null_check"
    return {
        "evidence_id": identity,
        "episode_id": identity,
        "start_minute": start,
        "last_seen_minute": str(event["end_time"]),
        "entity_id": f"{city}-{node}",
        "modality": "metric",
        "feature": feature,
        "anomaly_kind": event_type,
        "direction": direction,
        "raw_score": _value(event.get("severity")),
        "score_kind": score_kind(detector),
        "reliability": None,
        "observed": not missing and event.get("raw_value") is not None,
        "attributes": attributes,
    }


def write_evidence(events: Iterable[dict[str, Any]], testset_csv: Path, path: Path) -> int:
    count = 0
    with path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(standard_evidence_row(event, testset_csv),
                                    ensure_ascii=False, separators=(",", ":")) + "\n")
            count += 1
    return count


def write_coverage(
    timestamps: list[datetime],
    raw_values_by_metric: dict[str, list[float | str | None]],
    events: Iterable[dict[str, Any]],
    testset_csv: Path,
    path: Path,
) -> int:
    """Compress consecutive observed, historical missing, and unknown samples."""
    detected_missing: dict[str, set[int]] = defaultdict(set)
    for event in events:
        if event["event_type"] == "missing_value":
            detected_missing[str(event["metric_name"])].add(int(event["point_index"]))
    count = 0
    with path.open("w", encoding="utf-8") as handle:
        for metric_id, values in raw_values_by_metric.items():
            city, node, _, _, _ = metric_parts(metric_id)
            metric_missing = detected_missing.get(metric_id, set())
            active_status: str | None = None
            first: datetime | None = None
            last: datetime | None = None
            sample_count = 0

            def flush() -> None:
                nonlocal count
                if active_status is None or first is None or last is None:
                    return
                row = {
                    "minute": first.strftime(TIME_FORMAT),
                    "last_seen_minute": last.strftime(TIME_FORMAT),
                    "modality": "metric",
                    "entity_id": f"{city}-{node}",
                    "feature_or_source": metric_id,
                    "status": active_status,
                    "expected": True if active_status == "missing" else None,
                    "observed_count": sample_count if active_status == "observed" else 0,
                    "source_ref": str(testset_csv),
                    "source_column": metric_id,
                }
                handle.write(json.dumps(row, ensure_ascii=False,
                                        separators=(",", ":")) + "\n")
                count += 1

            for index, (minute, value) in enumerate(zip(timestamps, values)):
                if value is not None and (not isinstance(value, float) or math.isfinite(value)):
                    status = "observed"
                elif index in metric_missing:
                    status = "missing"
                else:
                    status = "unknown"
                if status != active_status or (last is not None and minute != last + MINUTE):
                    flush()
                    active_status = status
                    first = minute
                    sample_count = 0
                last = minute
                sample_count += 1
            flush()
    return count
