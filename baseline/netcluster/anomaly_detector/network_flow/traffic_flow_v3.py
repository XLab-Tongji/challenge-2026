"""Detect probe anomalies with distribution-aware latency and batch outcomes."""

from __future__ import annotations

import csv
from collections import deque
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
from pathlib import Path
from statistics import median


VERSION = "traffic-flow-v3.1"
PERIODIC = {"dns", "web", "auth"}
META_FIELDS = ("series_key", "flow_type", "source_region", "source_ip",
               "target_region", "target_domain", "protocol")
REQUIRED = set(META_FIELDS) | {"timestamp_utc", "requests_total", "success_total",
                               "error_total", "batches_started_total",
                               "batches_completed_total", "batches_failed_total",
                               "batches_timeout_total", "latency_p95_seconds"}


def load_config(path: Path) -> dict:
    config = json.loads(path.read_text(encoding="utf-8"))
    if config.get("schema_version") != 2:
        raise ValueError("Unsupported traffic_flow config")
    for name in ("max_counter_gap_seconds", "min_requests", "baseline_points",
                 "baseline_min_points", "latency_min_run_minutes",
                 "failure_min_run_minutes", "min_error_count",
                 "latency_tail_count_min"):
        if type(config.get(name)) is not int or config[name] < 1:
            raise ValueError(f"{name} must be a positive integer")
    for name in ("error_ratio_min", "error_ratio_excess", "timeout_ratio_min",
                 "error_ratio_multiplier", "severe_error_ratio",
                 "latency_upper_quantile", "latency_upper_multiplier",
                 "latency_tail_ratio_min", "elephant_loss_rate_min",
                 "elephant_jitter_seconds_min"):
        value = config.get(name)
        if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
            raise ValueError(f"{name} must be positive")
    if config["baseline_min_points"] > config["baseline_points"]:
        raise ValueError("baseline_min_points exceeds baseline_points")
    for kind in PERIODIC:
        value = config["latency_min_increase_seconds"].get(kind)
        if (type(value) not in (int, float) or not math.isfinite(value)
                or value <= 0):
            raise ValueError(f"Missing latency floor for {kind}")
    if not 0 < config["latency_upper_quantile"] < 1:
        raise ValueError("latency_upper_quantile must be between zero and one")
    return config


def number(raw: str | None) -> float | None:
    if raw in (None, "", "NULL"):
        return None
    try:
        value = float(raw)
    except ValueError:
        return None
    return value if math.isfinite(value) else None


def delta(old: dict, new: dict, field: str, seconds: float, limit: int) -> float | None:
    left, right = number(old.get(field)), number(new.get(field))
    if (left is None or right is None or seconds <= 0 or seconds > limit
            or right < left):
        return None
    return right - left


def stable_id(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:24]


def _sample_time(row: dict) -> datetime:
    raw = row.get("prometheus_sample_time_utc")
    value = datetime.fromisoformat((raw if raw not in (None, "", "NULL")
                                    else row["timestamp_utc"]).replace("Z", "+00:00"))
    return value.astimezone(timezone.utc).replace(tzinfo=None) if value.tzinfo else value


def quantile(values: deque[float], probability: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = int(position)
    upper = min(len(ordered) - 1, lower + 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _latency_signal(value: float, history: deque[float], kind: str, config: dict):
    if len(history) < config["baseline_min_points"] or value <= 0:
        return None
    upper = quantile(history, config["latency_upper_quantile"])
    if upper <= 0:
        return None
    threshold = max(upper + config["latency_min_increase_seconds"][kind],
                    upper * config["latency_upper_multiplier"])
    if value > threshold:
        return upper, threshold, value / threshold
    return None


def _episode(meta: dict, feature: str, direction: str, start: str, end: str,
             score: float, score_kind: str, attributes: dict) -> dict:
    evidence_id = stable_id(VERSION, meta["series_key"], feature, direction, start)
    return {"evidence_id": evidence_id, "episode_id": evidence_id,
            "start_minute": start, "last_seen_minute": end,
            "entity_id": f"{meta['source_region']}-traffic-vm",
            "modality": "traffic_flow", "feature": feature,
            "anomaly_kind": "degradation", "direction": direction,
            "raw_score": round(score, 6), "score_kind": score_kind,
            "reliability": None, "observed": True,
            "attributes": {**meta, **attributes, "detector_version": VERSION,
                           "dependency_id": meta["series_key"]}}


def detect_file(path: Path, config: dict) -> tuple[list[dict], list[dict], dict]:
    """Return episodes, coverage intervals and per-file statistics."""
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        missing = REQUIRED - set(reader.fieldnames or ())
        if missing:
            raise ValueError(f"Missing traffic_flow fields in {path}: {sorted(missing)}")
        rows = sorted(reader, key=lambda row: row["timestamp_utc"])
    if not rows:
        return [], [], {"source_file": str(path), "rows": 0, "episodes": 0}
    meta = {key: rows[0].get(key, "") for key in META_FIELDS}
    kind = meta["flow_type"]
    if kind not in PERIODIC | {"elephant"}:
        raise ValueError(f"Unsupported flow_type {kind!r} in {path}")
    if any(any(row.get(key, "") != meta[key] for key in META_FIELDS) for row in rows):
        raise ValueError(f"Changing traffic_flow metadata within {path}")
    coverage = []
    episodes = []
    active: dict[str, dict] = {}
    errors: deque[float] = deque(maxlen=config["baseline_points"])
    latencies: dict[int, deque[float]] = {}
    elephant_valid_throughputs = 0
    previous = None
    valid_windows = 0

    def close(feature: str) -> None:
        old = active.pop(feature, None)
        if old and old["length"] >= old["min_run"]:
            episodes.append(_episode(meta, feature, "up", old["start"], old["end"],
                                     old["score"], old["score_kind"], old["attributes"]))

    def observe(feature: str, minute: str, score: float, score_kind: str,
                attributes: dict, min_run: int) -> None:
        current = active.get(feature)
        if current and datetime.fromisoformat(minute) != (
                datetime.fromisoformat(current["end"]) + timedelta(minutes=1)):
            close(feature)
            current = None
        if current is None:
            current = {"start": minute, "end": minute, "length": 0,
                       "score": score, "score_kind": score_kind,
                       "attributes": attributes, "min_run": min_run}
            active[feature] = current
        else:
            for key in ("episode_request_count", "episode_error_count",
                        "episode_finished_batches", "episode_timeout_count",
                        "episode_valid_windows"):
                if key in attributes:
                    current["attributes"][key] += attributes[key]
        current["end"] = minute
        current["length"] += 1
        current["score"] = max(current["score"], score)
        current["attributes"]["last_observed"] = attributes["last_observed"]
        if feature == "request_error_ratio":
            current["attributes"]["last_baseline"] = attributes["baseline"]
            current["attributes"]["last_threshold"] = attributes["threshold"]
        if feature == "latency_p95_seconds":
            current["attributes"]["last_baseline"] = attributes["baseline"]
            current["attributes"]["last_threshold"] = attributes["threshold"]
            current["attributes"]["last_load_bucket"] = attributes["load_bucket"]
            buckets = current["attributes"]["load_buckets"]
            if attributes["load_bucket"] not in buckets:
                buckets.append(attributes["load_bucket"])
                buckets.sort()

    for row in rows:
        minute = row["timestamp_utc"]
        current_time = datetime.fromisoformat(minute)
        if previous is not None:
            old_minute = datetime.fromisoformat(previous["timestamp_utc"])
            if kind in PERIODIC and current_time > old_minute + timedelta(minutes=1):
                coverage.append({"start_minute": (old_minute + timedelta(minutes=1)).strftime(
                    "%Y-%m-%d %H:%M:%S"),
                                 "last_seen_minute": (current_time - timedelta(minutes=1)).strftime(
                    "%Y-%m-%d %H:%M:%S"), "status": "unknown", "expected": None,
                                 "modality": "traffic_flow",
                                 "entity_id": f"{meta['source_region']}-traffic-vm",
                                 "feature_or_source": meta["series_key"],
                                 "observed_count": 0, "source_ref": str(path)})
        observed_coverage = {"minute": minute, "status": "observed",
                             "expected": False if kind == "elephant" else None,
                             "modality": "traffic_flow",
                             "entity_id": f"{meta['source_region']}-traffic-vm",
                             "feature_or_source": meta["series_key"],
                             "observed_count": 1, "source_ref": str(path),
                             "valid_request_window": False,
                             "valid_latency_sample": False,
                             "valid_batch_window": False}
        coverage.append(observed_coverage)
        if previous is None:
            previous = row
            continue
        if kind == "elephant":
            before = number(previous.get("batches_completed_total"))
            after = number(row.get("batches_completed_total"))
            # A completed batch reports a new outcome. Intermediate snapshots
            # repeat the last result and must not become independent events.
            completed_batch = (before is not None and after is not None
                               and after > before)
            if completed_batch:
                throughput = number(row.get("throughput_bps"))
                loss = number(row.get("loss_rate"))
                jitter = number(row.get("jitter_seconds"))
                elephant_valid_throughputs += throughput is not None
                observations = (
                    ("elephant_loss_rate", loss, config["elephant_loss_rate_min"],
                     "loss_fraction"),
                    ("elephant_jitter_seconds", jitter,
                     config["elephant_jitter_seconds_min"], "seconds"),
                )
                for feature, value, threshold, score_kind in observations:
                    if value is not None and value >= threshold:
                        episodes.append(_episode(
                            meta, feature, "up", minute, minute, value, score_kind,
                            {"baseline": 0 if feature == "elephant_loss_rate" else None,
                             "threshold": threshold, "completed_batches": after - before,
                             "throughput_bps": throughput,
                             "last_observed": {feature: value}}))
            previous = row
            continue
        seconds = (_sample_time(row) - _sample_time(previous)).total_seconds()
        if seconds <= 0 or seconds > config["max_counter_gap_seconds"]:
            errors.clear()
            latencies.clear()
        requests = delta(previous, row, "requests_total", seconds,
                         config["max_counter_gap_seconds"])
        successes = delta(previous, row, "success_total", seconds,
                          config["max_counter_gap_seconds"])
        failures = delta(previous, row, "error_total", seconds,
                         config["max_counter_gap_seconds"])
        started = delta(previous, row, "batches_started_total", seconds,
                        config["max_counter_gap_seconds"])
        completed = delta(previous, row, "batches_completed_total", seconds,
                          config["max_counter_gap_seconds"])
        failed_batches = delta(previous, row, "batches_failed_total", seconds,
                               config["max_counter_gap_seconds"])
        timeouts = delta(previous, row, "batches_timeout_total", seconds,
                         config["max_counter_gap_seconds"])
        seen = set()
        valid_request = (requests is not None and successes is not None and failures is not None
                         and requests >= config["min_requests"]
                         and successes <= requests and failures <= requests
                         and successes + failures <= requests + 1)
        observed_coverage["valid_request_window"] = valid_request
        if valid_request:
            valid_windows += 1
            ratio = failures / requests
            baseline = median(errors) if len(errors) >= config["baseline_min_points"] else None
            threshold = max(config["error_ratio_min"],
                            baseline + config["error_ratio_excess"] if baseline is not None else 0,
                            baseline * config["error_ratio_multiplier"]
                            if baseline is not None else 0)
            error_detected = (failures >= config["min_error_count"]
                              and (ratio >= config["severe_error_ratio"]
                                   or ratio >= threshold))
            if error_detected:
                feature = "request_error_ratio"
                observe(feature, minute, ratio, "error_fraction",
                        {"baseline": baseline, "threshold": threshold,
                         "request_count": requests, "error_count": failures,
                         "episode_request_count": requests,
                         "episode_error_count": failures,
                         "episode_valid_windows": 1,
                         "last_observed": {"error_ratio": ratio}},
                        1 if ratio >= config["severe_error_ratio"]
                        else config["failure_min_run_minutes"])
                seen.add(feature)
            # Keep every valid observation in the rolling reference, including
            # alerts; the absolute severe-error rule remains active throughout.
            errors.append(ratio)
            latency = number(row.get("latency_p95_seconds"))
            if latency is not None and ratio < 0.2:
                observed_coverage["valid_latency_sample"] = True
                observed_qps = number(row.get("observed_qps"))
                qps = observed_qps if observed_qps is not None else requests / seconds
                load_bucket = max(0, round(qps))
                latency_history = latencies.setdefault(
                    load_bucket, deque(maxlen=config["baseline_points"]))
                scored = _latency_signal(latency, latency_history, kind, config)
                if scored:
                    baseline_latency, threshold_latency, ratio_to_threshold = scored
                    feature = "latency_p95_seconds"
                    observe(feature, minute, ratio_to_threshold, "threshold_ratio",
                            {"baseline": baseline_latency, "unit": "seconds",
                             "threshold": threshold_latency,
                             "load_bucket": load_bucket,
                             "load_buckets": [load_bucket],
                             "observed_qps": observed_qps,
                             "request_count": requests,
                             "last_observed": {"latency_p95_seconds": latency}},
                            config["latency_min_run_minutes"])
                    seen.add(feature)
                # Include both low and high valid observations. Excluding every
                # high mode previously locked this baseline to the low mode.
                latency_history.append(latency)
            tail_count = delta(previous, row, "request_latency_seconds_count",
                               seconds, config["max_counter_gap_seconds"])
            below_one_second = delta(
                previous, row, "request_latency_seconds_bucket_le_1",
                seconds, config["max_counter_gap_seconds"])
            if (tail_count is not None and below_one_second is not None
                    and tail_count >= config["min_requests"]
                    and 0 <= below_one_second <= tail_count):
                slow_count = tail_count - below_one_second
                tail_ratio = slow_count / tail_count
                if (slow_count >= config["latency_tail_count_min"]
                        and tail_ratio >= config["latency_tail_ratio_min"]):
                    feature = "latency_tail_ratio"
                    observe(feature, minute, tail_ratio, "tail_fraction",
                            {"threshold_seconds": 1, "sample_count": tail_count,
                             "slow_count": slow_count,
                             "last_observed": {"tail_ratio": tail_ratio}},
                            config["failure_min_run_minutes"])
                    seen.add(feature)
        valid_batches = (started is not None and completed is not None
                         and failed_batches is not None and timeouts is not None
                         and started >= 0 and completed >= 0 and failed_batches >= 0
                         and 0 <= timeouts <= failed_batches)
        observed_coverage["valid_batch_window"] = valid_batches
        if valid_batches:
            finished = completed + failed_batches
            if finished > 0 and 0 < timeouts <= finished:
                timeout_ratio = timeouts / finished
                if timeout_ratio >= config["timeout_ratio_min"]:
                    feature = "batch_timeout_ratio"
                    observe(feature, minute, timeout_ratio, "timeout_fraction",
                            {"finished_batches": finished, "timeout_count": timeouts,
                             "episode_finished_batches": finished,
                             "episode_timeout_count": timeouts,
                             "episode_valid_windows": 1,
                             "last_observed": {"timeout_ratio": timeout_ratio}},
                            config["failure_min_run_minutes"])
                    seen.add(feature)
        for feature in list(active):
            if feature not in seen:
                close(feature)
        previous = row
    for feature in list(active):
        close(feature)
    return episodes, coverage, {"source_file": str(path), "rows": len(rows),
                                "valid_request_windows": valid_windows,
                                "episodes": len(episodes), "flow_type": kind,
                                "elephant_valid_throughputs": elephant_valid_throughputs}
