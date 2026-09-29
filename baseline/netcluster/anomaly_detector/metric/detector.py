from __future__ import annotations

import argparse
from bisect import bisect_left, bisect_right
from collections import deque
from concurrent.futures import ProcessPoolExecutor
import csv
from fnmatch import fnmatchcase
import hashlib
import json
import math
import re
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta
from pathlib import Path
from statistics import mean, median
from typing import Any

if __package__ in {None, ""}:
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from baseline.netcluster.anomaly_detector.metric.baselines import (
    BaselineResult,
    median_step_seconds,
    safe_filename,
    write_modeled_series_csv,
)
from baseline.netcluster.anomaly_detector.events import METRIC_EVENT_FIELDS, metric_event_row, write_event_rows
from baseline.netcluster.anomaly_detector.metric.output import write_coverage, write_evidence
from baseline.netcluster.anomaly_detector.metric.series import parse_number, parse_timestamp, robust_scale


DEFAULT_RULES_CONFIG = Path(__file__).resolve().parents[2] / "config" / "metric_detection_rules.json"
NULL_STATE_TOKENS = {"", "null", "none", "nan", "n/a", "na", "\\n"}


@dataclass(frozen=True)
class ResidualAdConfig:
    rolling_window: int = 121
    anomaly_fraction: float = 0.005
    n_sigma: float = 2.5
    min_effect_size: float = 3.0
    min_valid_points: int = 30
    trend_score_threshold: float = 2.0
    trend_r2_threshold: float = 0.65
    periodic_score_threshold: float = 0.55
    period_candidate_minutes: tuple[int, ...] = tuple(range(60, 721, 60)) + (1440,)
    resource_high_tail_only: bool = True
    dynamic_peak_period_min_minutes: int = 300
    dynamic_peak_period_max_minutes: int = 540
    dynamic_peak_tolerance_minutes: int = 10
    dynamic_peak_min_support: int = 2
    mad_window_points: int = 60
    mad_min_history: int = 3
    mad_z_threshold: float = 4.0
    mad_relative_floor: float = 0.05
    mad_reset_gap_minutes: int = 5
    mad_max_age_minutes: int = 180


@dataclass(frozen=True)
class MetricProfile:
    metric_id: str
    periodic_minutes: int | None
    periodic_kind: str
    trend_score: float
    trend_r2: float
    periodic_score: float


@dataclass(frozen=True)
class EcodProfile:
    reference_values: list[float]
    center: float
    scale: float


@dataclass(frozen=True)
class MissingDetectionConfig:
    enabled: bool = True
    history_window_minutes: int = 360
    history_min_valid_ratio: float = 0.8
    max_missing_duration_minutes: int = 60


@dataclass(frozen=True)
class MetricDetectionRule:
    enabled: bool | None = None
    metric_type: str | None = None
    workflow: str | None = None
    tail: str = "two_sided"
    anomaly_fraction: float | None = None
    min_effect_size: float | None = None
    n_sigma: float | None = None
    numeric_detectors: str | None = None
    mad_floor: float | None = None
    mad_relative_floor: float | None = None
    mad_z_threshold: float | None = None
    mad_min_run_points: int | None = None
    mad_run_gap_minutes: int | None = None
    bottleneck_threshold: float | None = None
    min_absolute_change: float | None = None
    min_relative_change: float | None = None
    normal_values: tuple[str, ...] = ()
    failure_values: tuple[str, ...] = ()
    failure_regex: str | None = None
    ignore_values: tuple[str, ...] = ()
    normal_is_null: bool | None = None
    missing_detection_enabled: bool | None = None


@dataclass(frozen=True)
class DetectionRules:
    rare_state_max_unique: int = 4
    rare_state_min_dominant_ratio: float = 0.95
    default_rule: MetricDetectionRule = MetricDetectionRule()
    missing: MissingDetectionConfig = MissingDetectionConfig()
    rules: tuple[tuple[str, MetricDetectionRule], ...] = ()


def load_detection_rules(path: Path = DEFAULT_RULES_CONFIG) -> DetectionRules:
    if not path.exists():
        return DetectionRules()
    payload = json.loads(path.read_text(encoding="utf-8"))
    defaults = payload.get("defaults", {})
    missing = payload.get("missing_detection", {})
    default_rule = MetricDetectionRule(
        enabled=bool(defaults.get("enabled", True)),
        metric_type=str(defaults.get("metric_type", "continuous")),
        workflow=str(defaults.get("workflow", "numeric")),
        tail=str(defaults.get("numeric_tail", "two_sided")),
        anomaly_fraction=float(defaults["anomaly_fraction"]) if "anomaly_fraction" in defaults else None,
        n_sigma=float(defaults["n_sigma"]) if "n_sigma" in defaults else None,
        numeric_detectors=str(defaults.get("numeric_detectors", "ecod")),
        mad_floor=float(defaults["mad_floor"]) if "mad_floor" in defaults else None,
        mad_relative_floor=float(defaults["mad_relative_floor"]) if "mad_relative_floor" in defaults else None,
        mad_z_threshold=float(defaults["mad_z_threshold"]) if "mad_z_threshold" in defaults else None,
        mad_min_run_points=int(defaults.get("mad_min_run_points", 1)),
        mad_run_gap_minutes=int(defaults.get("mad_run_gap_minutes", 0)),
        min_absolute_change=(float(defaults["min_absolute_change"]) if "min_absolute_change" in defaults else None),
        min_relative_change=(float(defaults["min_relative_change"]) if "min_relative_change" in defaults else None),
    )
    if default_rule.numeric_detectors not in {"ecod", "mad", "both"}:
        raise ValueError(f"Invalid numeric_detectors in {path}: {default_rule.numeric_detectors}")
    if default_rule.mad_floor is not None and default_rule.mad_floor < 0:
        raise ValueError(f"Invalid mad_floor in {path}: {default_rule.mad_floor}")
    if default_rule.mad_relative_floor is not None and default_rule.mad_relative_floor < 0:
        raise ValueError(f"Invalid mad_relative_floor in {path}: {default_rule.mad_relative_floor}")
    if default_rule.mad_z_threshold is not None and default_rule.mad_z_threshold <= 0:
        raise ValueError(f"Invalid mad_z_threshold in {path}: {default_rule.mad_z_threshold}")
    if type(default_rule.mad_min_run_points) is not int or default_rule.mad_min_run_points < 1:
        raise ValueError(f"Invalid mad_min_run_points in {path}: {default_rule.mad_min_run_points}")
    if type(default_rule.mad_run_gap_minutes) is not int or default_rule.mad_run_gap_minutes < 0:
        raise ValueError(f"Invalid mad_run_gap_minutes in {path}: {default_rule.mad_run_gap_minutes}")
    for name in ("min_absolute_change", "min_relative_change"):
        value = getattr(default_rule, name)
        if value is not None and (not math.isfinite(value) or value < 0):
            raise ValueError(f"Invalid {name} in {path}: {value}")
    configured_rules: list[tuple[str, MetricDetectionRule]] = []
    for item in payload.get("rules", []):
        pattern = str(item["match"])
        enabled = item.get("enabled")
        metric_type = item.get("metric_type")
        workflow = item.get("workflow")
        tail = item.get("tail", defaults.get("numeric_tail", "two_sided"))
        anomaly_fraction = item.get("anomaly_fraction")
        min_effect_size = item.get("min_effect_size")
        n_sigma = item.get("n_sigma")
        numeric_detectors = item.get("numeric_detectors")
        mad_floor = item.get("mad_floor")
        mad_relative_floor = item.get("mad_relative_floor")
        mad_z_threshold = item.get("mad_z_threshold")
        mad_min_run_points = item.get("mad_min_run_points")
        mad_run_gap_minutes = item.get("mad_run_gap_minutes")
        bottleneck_threshold = item.get("bottleneck_threshold")
        min_absolute_change = item.get("min_absolute_change")
        min_relative_change = item.get("min_relative_change")
        normal_values = tuple(str(value) for value in item.get("normal_values", []))
        failure_values = tuple(str(value) for value in item.get("failure_values", []))
        failure_regex = item.get("failure_regex")
        ignore_values = tuple(str(value) for value in item.get("ignore_values", []))
        normal_is_null = item.get("normal_is_null")
        missing_detection_enabled = item.get("missing_detection_enabled")
        if workflow not in {None, "state", "rare_state", "numeric"}:
            raise ValueError(f"Unsupported workflow in {path}: {workflow}")
        if tail not in {"upper", "lower", "two_sided"}:
            raise ValueError(f"Unsupported tail in {path}: {tail}")
        if anomaly_fraction is not None and not 0.0 < float(anomaly_fraction) <= 0.5:
            raise ValueError(f"Invalid anomaly_fraction in {path}: {anomaly_fraction}")
        if min_effect_size is not None and float(min_effect_size) < 0.0:
            raise ValueError(f"Invalid min_effect_size in {path}: {min_effect_size}")
        if n_sigma is not None and float(n_sigma) <= 0.0:
            raise ValueError(f"Invalid n_sigma in {path}: {n_sigma}")
        if numeric_detectors is not None and numeric_detectors not in {"ecod", "mad", "both"}:
            raise ValueError(f"Invalid numeric_detectors in {path}: {numeric_detectors}")
        if mad_floor is not None and float(mad_floor) < 0.0:
            raise ValueError(f"Invalid mad_floor in {path}: {mad_floor}")
        if mad_relative_floor is not None and float(mad_relative_floor) < 0.0:
            raise ValueError(f"Invalid mad_relative_floor in {path}: {mad_relative_floor}")
        if mad_z_threshold is not None and float(mad_z_threshold) <= 0.0:
            raise ValueError(f"Invalid mad_z_threshold in {path}: {mad_z_threshold}")
        if mad_min_run_points is not None and (type(mad_min_run_points) is not int or mad_min_run_points < 1):
            raise ValueError(f"Invalid mad_min_run_points in {path}: {mad_min_run_points}")
        if mad_run_gap_minutes is not None and (type(mad_run_gap_minutes) is not int or mad_run_gap_minutes < 0):
            raise ValueError(f"Invalid mad_run_gap_minutes in {path}: {mad_run_gap_minutes}")
        if bottleneck_threshold is not None and not math.isfinite(float(bottleneck_threshold)):
            raise ValueError(f"Invalid bottleneck_threshold in {path}: {bottleneck_threshold}")
        for name, value in (("min_absolute_change", min_absolute_change), ("min_relative_change", min_relative_change)):
            if value is not None and (not math.isfinite(float(value)) or float(value) < 0):
                raise ValueError(f"Invalid {name} in {path}: {value}")
        if failure_regex is not None:
            re.compile(str(failure_regex))
        configured_rules.append(
            (
                pattern,
                MetricDetectionRule(
                    enabled=bool(enabled) if enabled is not None else None,
                    metric_type=str(metric_type) if metric_type is not None else None,
                    workflow=workflow,
                    tail=tail,
                    anomaly_fraction=float(anomaly_fraction) if anomaly_fraction is not None else None,
                    min_effect_size=float(min_effect_size) if min_effect_size is not None else None,
                    n_sigma=float(n_sigma) if n_sigma is not None else None,
                    numeric_detectors=str(numeric_detectors) if numeric_detectors is not None else None,
                    mad_floor=float(mad_floor) if mad_floor is not None else None,
                    mad_relative_floor=float(mad_relative_floor) if mad_relative_floor is not None else None,
                    mad_z_threshold=float(mad_z_threshold) if mad_z_threshold is not None else None,
                    mad_min_run_points=mad_min_run_points,
                    mad_run_gap_minutes=mad_run_gap_minutes,
                    bottleneck_threshold=(
                        float(bottleneck_threshold) if bottleneck_threshold is not None else None
                    ),
                    min_absolute_change=(float(min_absolute_change) if min_absolute_change is not None else None),
                    min_relative_change=(float(min_relative_change) if min_relative_change is not None else None),
                    normal_values=normal_values,
                    failure_values=failure_values,
                    failure_regex=str(failure_regex) if failure_regex is not None else None,
                    ignore_values=ignore_values,
                    normal_is_null=bool(normal_is_null) if normal_is_null is not None else None,
                    missing_detection_enabled=(
                        bool(missing_detection_enabled) if missing_detection_enabled is not None else None
                    ),
                ),
            )
        )
    return DetectionRules(
        rare_state_max_unique=int(defaults.get("state_distinct_value_limit", defaults.get("rare_state_max_unique", 4))),
        rare_state_min_dominant_ratio=float(defaults.get("state_dominant_ratio", defaults.get("rare_state_min_dominant_ratio", 0.95))),
        default_rule=default_rule,
        missing=MissingDetectionConfig(
            enabled=bool(missing.get("enabled", True)),
            history_window_minutes=int(missing.get("history_window_minutes", 360)),
            history_min_valid_ratio=float(missing.get("history_min_valid_ratio", 0.8)),
            max_missing_duration_minutes=int(missing.get("max_missing_duration_minutes", 60)),
        ),
        rules=tuple(configured_rules),
    )


def resolve_metric_rule(metric_id: str, rules: DetectionRules | None = None) -> MetricDetectionRule:
    active_rules = rules or load_detection_rules()
    resolved = active_rules.default_rule
    for pattern, rule in active_rules.rules:
        if fnmatchcase(metric_id, pattern):
            resolved = MetricDetectionRule(
                enabled=rule.enabled if rule.enabled is not None else resolved.enabled,
                metric_type=rule.metric_type if rule.metric_type is not None else resolved.metric_type,
                workflow=rule.workflow if rule.workflow is not None else resolved.workflow,
                tail=rule.tail,
                anomaly_fraction=(
                    rule.anomaly_fraction if rule.anomaly_fraction is not None else resolved.anomaly_fraction
                ),
                min_effect_size=(
                    rule.min_effect_size if rule.min_effect_size is not None else resolved.min_effect_size
                ),
                n_sigma=rule.n_sigma if rule.n_sigma is not None else resolved.n_sigma,
                numeric_detectors=(rule.numeric_detectors if rule.numeric_detectors is not None else resolved.numeric_detectors),
                mad_floor=rule.mad_floor if rule.mad_floor is not None else resolved.mad_floor,
                mad_relative_floor=(rule.mad_relative_floor if rule.mad_relative_floor is not None else resolved.mad_relative_floor),
                mad_z_threshold=(rule.mad_z_threshold if rule.mad_z_threshold is not None else resolved.mad_z_threshold),
                mad_min_run_points=(rule.mad_min_run_points if rule.mad_min_run_points is not None else resolved.mad_min_run_points),
                mad_run_gap_minutes=(rule.mad_run_gap_minutes if rule.mad_run_gap_minutes is not None else resolved.mad_run_gap_minutes),
                bottleneck_threshold=(
                    rule.bottleneck_threshold
                    if rule.bottleneck_threshold is not None
                    else resolved.bottleneck_threshold
                ),
                min_absolute_change=(rule.min_absolute_change if rule.min_absolute_change is not None else resolved.min_absolute_change),
                min_relative_change=(rule.min_relative_change if rule.min_relative_change is not None else resolved.min_relative_change),
                normal_values=rule.normal_values or resolved.normal_values,
                failure_values=rule.failure_values or resolved.failure_values,
                failure_regex=rule.failure_regex if rule.failure_regex is not None else resolved.failure_regex,
                ignore_values=rule.ignore_values or resolved.ignore_values,
                normal_is_null=(
                    rule.normal_is_null if rule.normal_is_null is not None else resolved.normal_is_null
                ),
                missing_detection_enabled=(
                    rule.missing_detection_enabled
                    if rule.missing_detection_enabled is not None
                    else resolved.missing_detection_enabled
                ),
            )
    return resolved


def detector_config_for_metric(metric_id: str, config: ResidualAdConfig, rules: DetectionRules | None = None) -> ResidualAdConfig:
    rule = resolve_metric_rule(metric_id, rules)
    return replace(
        config,
        anomaly_fraction=rule.anomaly_fraction if rule.anomaly_fraction is not None else config.anomaly_fraction,
        min_effect_size=rule.min_effect_size if rule.min_effect_size is not None else config.min_effect_size,
        n_sigma=rule.n_sigma if rule.n_sigma is not None else config.n_sigma,
    )


def parse_raw_state(value: str | None) -> float | str | None:
    if value is None:
        return None
    text = value.strip().strip('"')
    if text.casefold() in NULL_STATE_TOKENS:
        return None
    number = parse_number(text)
    return number if number is not None else text


def normalized_state(value: float | str | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, float):
        return format(value, ".15g").casefold()
    return value.strip().casefold()


def configured_state_points(
    timestamps: list[datetime],
    values: list[float | str | None],
    rule: MetricDetectionRule,
) -> list[dict[str, Any]]:
    """Emit state anomalies solely from configured normal/failure definitions."""
    normal = {normalized_state(value) for value in rule.normal_values}
    failures = {normalized_state(value) for value in rule.failure_values}
    ignored = {normalized_state(value) for value in rule.ignore_values}
    failure_pattern = re.compile(rule.failure_regex, re.IGNORECASE) if rule.failure_regex else None
    if not normal and not failures and failure_pattern is None and not rule.normal_is_null:
        return []

    points: list[dict[str, Any]] = []
    for index, (timestamp, value) in enumerate(zip(timestamps, values)):
        normalized = normalized_state(value)
        if normalized is None or normalized in ignored:
            continue
        is_failure = (
            normalized in failures
            if failures
            else failure_pattern.search(str(value)) is not None
            if failure_pattern is not None
            else True
            if rule.normal_is_null
            else normalized not in normal
        )
        if is_failure:
            points.append(
                {
                    "point_index": index,
                    "timestamp": timestamp,
                    "component": "state",
                    "event_type": "state_anomaly",
                    "score": 1.0,
                    "direction": "state",
                    "detector": "configured_state",
                    "value": display_state(value),
                    "baseline": "NULL" if rule.normal_is_null else ",".join(rule.normal_values),
                }
            )
    return points


def load_raw_testset(path: Path) -> tuple[list[datetime], dict[str, list[float | str | None]]]:
    with path.open(newline="", encoding="utf-8-sig", errors="replace") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or "timestamp" not in reader.fieldnames:
            raise ValueError(f"{path} must contain a timestamp column")
        timestamps: list[datetime] = []
        values_by_metric = {field: [] for field in reader.fieldnames if field != "timestamp"}
        for row in reader:
            timestamp = parse_timestamp(row.get("timestamp", ""))
            if timestamp is None:
                continue
            timestamps.append(timestamp)
            for metric_id in values_by_metric:
                values_by_metric[metric_id].append(parse_raw_state(row.get(metric_id)))
    return timestamps, values_by_metric


def state_key(value: float | str | None) -> tuple[str, str]:
    if value is None:
        return ("null", "")
    if isinstance(value, str):
        return ("string", value)
    return ("number", repr(value))


def display_state(value: float | str | None) -> str | float:
    return "NULL" if value is None else value


def rare_state_summary(
    values: list[float | str | None],
    max_unique: int = 4,
    min_dominant_ratio: float = 0.95,
) -> tuple[bool, float | str | None]:
    if not values:
        return False, None
    counts: dict[tuple[str, str], int] = {}
    representatives: dict[tuple[str, str], float | str | None] = {}
    for value in values:
        key = state_key(value)
        counts[key] = counts.get(key, 0) + 1
        representatives.setdefault(key, value)
    dominant_key = max(counts, key=counts.get)
    dominant_ratio = counts[dominant_key] / len(values)
    is_rare_state = len(counts) < max_unique and dominant_ratio >= min_dominant_ratio
    return is_rare_state, representatives[dominant_key]


def rare_state_points(
    timestamps: list[datetime],
    values: list[float | str | None],
    dominant_state: float | str | None = None,
) -> tuple[list[dict[str, Any]], float | str | None]:
    if dominant_state is None:
        _, dominant_state = rare_state_summary(values)
    dominant_key = state_key(dominant_state)
    points: list[dict[str, Any]] = []
    for index, (timestamp, value) in enumerate(zip(timestamps, values)):
        if state_key(value) != dominant_key:
            points.append(
                {
                    "point_index": index,
                    "timestamp": timestamp,
                    "component": "raw",
                    "event_type": "state_anomaly",
                    "score": 1.0,
                    "direction": "state_change",
                    "detector": "rare_state",
                    "value": display_state(value),
                    "baseline": display_state(dominant_state),
                }
            )
    return points, dominant_state


def tail_direction_filter(tail: str) -> str | None:
    if tail == "upper":
        return "high"
    if tail == "lower":
        return "low"
    return None


def valid_values(values: list[float | None]) -> list[float]:
    return [value for value in values if value is not None and math.isfinite(value)]


def is_constant_series(values: list[float | None]) -> bool:
    finite = valid_values(values)
    if not finite:
        return False
    first = finite[0]
    return all(value == first for value in finite)


def missing_value_points(
    timestamps: list[datetime],
    values: list[float | str | None],
    config: MissingDetectionConfig | None = None,
) -> list[dict[str, Any]]:
    active_config = config or MissingDetectionConfig()
    if not active_config.enabled or not timestamps or not values:
        return []

    def is_observed(value: float | str | None) -> bool:
        return value is not None and (not isinstance(value, float) or math.isfinite(value))

    positive_steps = [
        (right - left).total_seconds()
        for left, right in zip(timestamps, timestamps[1:])
        if right > left
    ]
    step_seconds = median(positive_steps) if positive_steps else 60.0
    history_window = timedelta(minutes=active_config.history_window_minutes)
    maximum_gap_seconds = active_config.max_missing_duration_minutes * 60.0
    points: list[dict[str, Any]] = []
    index = 0
    while index < min(len(timestamps), len(values)):
        if is_observed(values[index]):
            index += 1
            continue
        gap_start = index
        while index + 1 < len(values) and not is_observed(values[index + 1]):
            index += 1
        gap_end = index
        duration_seconds = (timestamps[gap_end] - timestamps[gap_start]).total_seconds() + step_seconds
        history_cutoff = timestamps[gap_start] - history_window
        history_start = bisect_left(timestamps, history_cutoff, 0, gap_start)
        history_values = values[history_start:gap_start]
        has_full_history_window = (
            bool(history_values)
            and timestamps[gap_start] - timestamps[history_start] >= history_window
        )
        valid_ratio = (
            sum(1 for value in history_values if is_observed(value)) / len(history_values)
            if history_values
            else 0.0
        )
        if (
            duration_seconds <= maximum_gap_seconds
            and has_full_history_window
            and valid_ratio >= active_config.history_min_valid_ratio
        ):
            for point_index in range(gap_start, gap_end + 1):
                timestamp = timestamps[point_index]
                points.append(
                    {
                        "point_index": point_index,
                        "timestamp": timestamp,
                        "component": "raw",
                        "event_type": "missing_value",
                        "score": 1.0,
                        "direction": "",
                        "detector": "historical_null_check",
                        "value": "",
                        "baseline": "observed_history",
                    }
                )
        index += 1
    return points


def infer_metric_profile(
    metric_id: str,
    timestamps: list[datetime],
    values: list[float | None],
    candidate_period_minutes: tuple[int, ...],
    config: ResidualAdConfig | None = None,
) -> MetricProfile:
    active_config = config or ResidualAdConfig(period_candidate_minutes=candidate_period_minutes)
    trend_score, trend_r2, detrended_values = time_aware_trend_profile(timestamps, values)
    periodic_minutes, periodic_score = aligned_periodic_profile(
        timestamps,
        detrended_values,
        candidate_period_minutes,
    )
    dynamic_minutes, dynamic_score = dynamic_periodic_profile(timestamps, values, active_config)
    periodic_kind = "fixed"
    if dynamic_minutes is not None and dynamic_score > periodic_score:
        periodic_minutes = dynamic_minutes
        periodic_score = dynamic_score
        periodic_kind = "dynamic"
    return MetricProfile(
        metric_id=metric_id,
        periodic_minutes=periodic_minutes,
        periodic_kind=periodic_kind,
        trend_score=trend_score,
        trend_r2=trend_r2,
        periodic_score=periodic_score,
    )


def time_aware_trend_profile(
    timestamps: list[datetime],
    values: list[float | None],
) -> tuple[float, float, list[float | None]]:
    """Fit a linear trend against elapsed time without compressing missing samples."""
    finite_pairs = [
        (timestamp, float(value))
        for timestamp, value in zip(timestamps, values)
        if value is not None and math.isfinite(value)
    ]
    detrended: list[float | None] = [None] * len(values)
    if len(finite_pairs) < 2:
        return 0.0, 0.0, detrended
    origin = finite_pairs[0][0]
    xs = [(timestamp - origin).total_seconds() / 60.0 for timestamp, _ in finite_pairs]
    ys = [value for _, value in finite_pairs]
    x_mean = mean(xs)
    y_mean = mean(ys)
    denominator = sum((x - x_mean) ** 2 for x in xs)
    if denominator <= 1e-12:
        return 0.0, 0.0, detrended
    slope = sum((x - x_mean) * (y - y_mean) for x, y in zip(xs, ys)) / denominator
    intercept = y_mean - slope * x_mean
    fitted = [intercept + slope * x for x in xs]
    total = sum((value - y_mean) ** 2 for value in ys)
    residual_sum = sum((value - fit) ** 2 for value, fit in zip(ys, fitted))
    r2 = 0.0 if total <= 1e-12 else max(0.0, 1.0 - residual_sum / total)
    center = median(ys)
    scale = robust_scale(ys, center)
    if scale <= 1e-12:
        scale = max(abs(center) * 0.05, 1e-6)
    score = abs(fitted[-1] - fitted[0]) / scale
    finite_position = 0
    for index, value in enumerate(values):
        if value is None or not math.isfinite(value):
            continue
        detrended[index] = float(value) - fitted[finite_position]
        finite_position += 1
    return score, r2, detrended


def aligned_periodic_profile(
    timestamps: list[datetime],
    values: list[float | None],
    candidate_period_minutes: tuple[int, ...],
) -> tuple[int | None, float]:
    """Compute pairwise autocorrelation at configured wall-clock lags."""
    if len(timestamps) < 2:
        return None, 0.0
    value_by_time = {
        timestamp: float(value)
        for timestamp, value in zip(timestamps, values)
        if value is not None and math.isfinite(value)
    }
    best_minutes: int | None = None
    best_score = 0.0
    end_time = timestamps[-1]
    for minutes in candidate_period_minutes:
        if minutes <= 0 or end_time - timestamps[0] < timedelta(minutes=minutes * 3):
            continue
        lag = timedelta(minutes=minutes)
        expected = sum(1 for timestamp in timestamps if timestamp + lag <= end_time)
        pairs = [
            (value, value_by_time[timestamp + lag])
            for timestamp, value in value_by_time.items()
            if timestamp + lag in value_by_time
        ]
        if len(pairs) < 3 or expected <= 0 or len(pairs) / expected < 0.5:
            continue
        left = [pair[0] for pair in pairs]
        right = [pair[1] for pair in pairs]
        left_mean = mean(left)
        right_mean = mean(right)
        numerator = sum((a - left_mean) * (b - right_mean) for a, b in pairs)
        left_energy = sum((a - left_mean) ** 2 for a in left)
        right_energy = sum((b - right_mean) ** 2 for b in right)
        denominator = math.sqrt(left_energy * right_energy)
        score = numerator / denominator if denominator > 1e-12 else 0.0
        if score > best_score:
            best_minutes = minutes
            best_score = score
    return best_minutes, best_score


def should_decompose(profile: MetricProfile, config: ResidualAdConfig) -> bool:
    return has_significant_trend(profile, config) or has_significant_period(profile, config)


def has_significant_trend(profile: MetricProfile, config: ResidualAdConfig) -> bool:
    return profile.trend_score >= config.trend_score_threshold and profile.trend_r2 >= config.trend_r2_threshold


def has_significant_period(profile: MetricProfile, config: ResidualAdConfig) -> bool:
    return profile.periodic_score >= config.periodic_score_threshold


def fill_missing(values: list[float | None]) -> list[float]:
    finite_pairs = [(index, value) for index, value in enumerate(values) if value is not None and math.isfinite(value)]
    if not finite_pairs:
        return [0.0] * len(values)
    filled = [0.0] * len(values)
    first_index, first_value = finite_pairs[0]
    for index in range(0, first_index + 1):
        filled[index] = first_value
    for (left_index, left_value), (right_index, right_value) in zip(finite_pairs, finite_pairs[1:]):
        span = right_index - left_index
        for offset in range(span + 1):
            ratio = offset / span if span else 0.0
            filled[left_index + offset] = left_value + (right_value - left_value) * ratio
    last_index, last_value = finite_pairs[-1]
    for index in range(last_index, len(values)):
        filled[index] = last_value
    return filled


def strict_centered_moving_average(values: list[float], window: int) -> list[float | None]:
    if not values:
        return []
    width = max(1, int(window))
    half = width // 2
    prefix = [0.0]
    for value in values:
        prefix.append(prefix[-1] + value)
    trend: list[float | None] = []
    for index in range(len(values)):
        left = index - half
        right = index + half + 1
        if left < 0 or right > len(values):
            trend.append(None)
        else:
            trend.append((prefix[right] - prefix[left]) / (right - left))
    return trend


def strict_centered_rolling_median(values: list[float], window: int) -> list[float | None]:
    if not values:
        return []
    width = max(1, int(window))
    half = width // 2
    trend: list[float | None] = []
    for index in range(len(values)):
        left = index - half
        right = index + half + 1
        if left < 0 or right > len(values):
            trend.append(None)
        else:
            trend.append(median(values[left:right]))
    return trend


def seasonal_phase_average(
    values: list[float],
    trend: list[float | None],
    period_points: int | None,
) -> list[float | None]:
    if period_points is None:
        return [0.0 if trend_value is not None else None for trend_value in trend]
    phase_values: dict[int, list[float]] = {}
    for index, (value, trend_value) in enumerate(zip(values, trend)):
        if trend_value is not None:
            phase_values.setdefault(index % period_points, []).append(value - trend_value)
    phase_average = {phase: mean(items) for phase, items in phase_values.items() if items}
    center = mean(phase_average.values()) if phase_average else 0.0
    seasonal: list[float | None] = []
    for index, trend_value in enumerate(trend):
        if trend_value is None:
            seasonal.append(None)
        else:
            seasonal.append(phase_average.get(index % period_points, 0.0) - center)
    return seasonal


def moving_average_components(
    timestamps: list[datetime],
    values: list[float | None],
    profile: MetricProfile,
    config: ResidualAdConfig,
) -> tuple[list[float | None], list[float | None], list[float | None], list[float | None]]:
    filled = fill_missing(values)
    period_points: int | None = None
    periodic_minutes = profile.periodic_minutes
    if has_significant_period(profile, config) and periodic_minutes is None:
        periodic_minutes = estimate_period_minutes(timestamps, values, config)
    if has_significant_period(profile, config) and periodic_minutes is not None:
        step_seconds = median_step_seconds(timestamps)
        if step_seconds > 0:
            period_points = max(2, int(round(periodic_minutes * 60 / step_seconds)))
    window = period_points or config.rolling_window
    if has_significant_period(profile, config) and profile.periodic_kind == "dynamic":
        trend = strict_centered_rolling_median(filled, window)
        seasonal = dynamic_periodic_peak_component(values, config, trend=trend, timestamps=timestamps)
    else:
        trend = strict_centered_moving_average(filled, window)
        seasonal = seasonal_phase_average(filled, trend, period_points)
    fitted = [
        None if trend_value is None or seasonal_value is None else trend_value + seasonal_value
        for trend_value, seasonal_value in zip(trend, seasonal)
    ]
    residual = [
        None if raw is None or fit is None else raw - fit
        for raw, fit in zip(values, fitted)
    ]
    for index, raw in enumerate(values):
        if raw is None or not math.isfinite(raw):
            trend[index] = None
            seasonal[index] = None
            fitted[index] = None
            residual[index] = None
    return trend, seasonal, fitted, residual


def estimate_period_minutes(
    timestamps: list[datetime],
    values: list[float | None],
    config: ResidualAdConfig,
) -> int | None:
    finite_values = [value for value in values if value is not None and math.isfinite(value)]
    if len(finite_values) < 30:
        return None
    _, _, detrended = time_aware_trend_profile(timestamps, values)
    minutes, score = aligned_periodic_profile(timestamps, detrended, config.period_candidate_minutes)
    if minutes is None or score < config.periodic_score_threshold:
        return None
    return minutes


def dynamic_periodic_profile(
    timestamps: list[datetime],
    values: list[float | None],
    config: ResidualAdConfig,
) -> tuple[int | None, float]:
    period_points, score, _ = dynamic_periodic_peak_model(timestamps, values, config)
    if period_points is None:
        return None, score
    step_seconds = median_step_seconds(timestamps)
    return max(1, int(round(period_points * step_seconds / 60))), score


def dynamic_periodic_peak_model(
    timestamps: list[datetime],
    values: list[float | None],
    config: ResidualAdConfig,
) -> tuple[int | None, float, list[int]]:
    """Validate configured peak periods across the complete observation range."""
    finite = [value for value in values if value is not None and math.isfinite(value)]
    if len(finite) < config.min_valid_points:
        return None, 0.0, []
    step_seconds = median_step_seconds(timestamps)
    if step_seconds <= 0:
        return None, 0.0, []
    peak_threshold = linear_quantile(finite, 0.995)
    peak_indexes = collapse_consecutive_peaks(local_peak_indexes(values, peak_threshold), values)
    if len(peak_indexes) < config.dynamic_peak_min_support + 1:
        return None, 0.0, []
    candidate_minutes = sorted({period for period in config.period_candidate_minutes if period > 0})
    best_period: int | None = None
    highest_score = 0.0
    best_valid_key: tuple[float, int] | None = None
    best_supported: list[int] = []
    for period_minutes in candidate_minutes:
        score, supported, missing_count, unmatched_count = validate_peak_period(
            timestamps,
            peak_indexes,
            period_minutes,
            config.dynamic_peak_tolerance_minutes,
        )
        highest_score = max(highest_score, score)
        is_valid = (
            missing_count <= 1
            and len(supported) >= config.dynamic_peak_min_support + 1
            and score >= config.periodic_score_threshold
        )
        valid_key = (score, len(supported))
        if is_valid and (best_valid_key is None or valid_key > best_valid_key):
            best_period = max(1, int(round(period_minutes * 60 / step_seconds)))
            best_valid_key = valid_key
            best_supported = supported
    return best_period, (best_valid_key[0] if best_valid_key is not None else highest_score), best_supported


def collapse_consecutive_peaks(
    peak_indexes: list[int],
    values: list[float | None],
) -> list[int]:
    if not peak_indexes:
        return []
    runs: list[list[int]] = [[peak_indexes[0]]]
    for index in peak_indexes[1:]:
        if index == runs[-1][-1] + 1:
            runs[-1].append(index)
        else:
            runs.append([index])
    representatives = []
    for run in runs:
        center = (run[0] + run[-1]) / 2.0
        representatives.append(
            max(run, key=lambda index: (float(values[index] or 0.0), -abs(index - center)))
        )
    return representatives


def validate_peak_period(
    timestamps: list[datetime],
    peak_indexes: list[int],
    period_minutes: int,
    tolerance_minutes: int,
) -> tuple[float, list[int], int, int]:
    period = timedelta(minutes=period_minutes)
    tolerance_seconds = tolerance_minutes * 60.0
    peak_pairs = [(timestamps[index], index) for index in peak_indexes]
    best: tuple[float, list[int], int, int] = (0.0, [], len(peak_indexes), len(peak_indexes))
    for anchor, _ in peak_pairs:
        first_slot = anchor
        while first_slot >= timestamps[0] + period:
            first_slot -= period
        slots = []
        slot = first_slot
        while slot <= timestamps[-1]:
            slots.append(slot)
            slot += period

        supported: list[int] = []
        missing_count = 0
        unmatched_count = 0
        peak_position = 0
        for expected in slots:
            while (
                peak_position < len(peak_pairs)
                and (peak_pairs[peak_position][0] - expected).total_seconds() < -tolerance_seconds
            ):
                unmatched_count += 1
                peak_position += 1
            if (
                peak_position < len(peak_pairs)
                and abs((peak_pairs[peak_position][0] - expected).total_seconds()) <= tolerance_seconds
            ):
                supported.append(peak_pairs[peak_position][1])
                peak_position += 1
            else:
                missing_count += 1
        unmatched_count += len(peak_pairs) - peak_position
        denominator = len(slots) + unmatched_count
        score = len(supported) / denominator if denominator else 0.0
        candidate = (score, supported, missing_count, unmatched_count)
        if (score, len(supported), -missing_count, -unmatched_count) > (
            best[0], len(best[1]), -best[2], -best[3]
        ):
            best = candidate
    return best


def dynamic_period_candidates(
    peak_indexes: list[int],
    min_period: int,
    max_period: int,
    tolerance: int,
) -> list[int]:
    candidates: set[int] = set()
    for left_position, left in enumerate(peak_indexes):
        for right in peak_indexes[left_position + 1 :]:
            distance = right - left
            min_cycles = max(1, math.ceil(distance / max_period))
            max_cycles = distance // min_period
            for cycles in range(min_cycles, max_cycles + 1):
                estimate = int(round(distance / cycles))
                for period in range(estimate - tolerance, estimate + tolerance + 1):
                    if min_period <= period <= max_period:
                        candidates.add(period)
    return sorted(candidates)


def phase_aligned_peak_indexes(
    peak_indexes: list[int],
    period: int,
    tolerance: int,
) -> list[int]:
    best_supported: list[int] = []
    for anchor in peak_indexes:
        supported = []
        for peak in peak_indexes:
            remainder = abs(peak - anchor) % period
            distance_to_cycle = min(remainder, period - remainder)
            if distance_to_cycle <= tolerance:
                supported.append(peak)
        if len(supported) > len(best_supported):
            best_supported = supported
    return best_supported


def constant_baseline(values: list[float | None]) -> list[float | None]:
    finite = [value for value in values if value is not None and math.isfinite(value)]
    center = median(finite) if finite else 0.0
    return [None if value is None else center for value in values]


def residual_from_baseline(values: list[float | None], baseline: list[float | None]) -> list[float | None]:
    return [None if value is None or base is None else value - base for value, base in zip(values, baseline)]


def build_ecod_profiles(values: list[float | None]) -> list[EcodProfile]:
    finite = sorted(value for value in values if value is not None and math.isfinite(value))
    if len(finite) < 30:
        return []
    center = median(finite)
    scale = robust_scale(finite, center)
    if scale <= 1e-12:
        q1 = linear_quantile(finite, 0.25)
        q3 = linear_quantile(finite, 0.75)
        scale = (q3 - q1) / 1.349 if q3 > q1 else max(abs(center) * 0.05, 1e-6)
    return [EcodProfile(finite, center, scale)]


def linear_quantile(values: list[float], quantile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * max(0.0, min(1.0, quantile))
    lower = int(math.floor(position))
    upper = int(math.ceil(position))
    if lower == upper:
        return ordered[lower]
    ratio = position - lower
    return ordered[lower] * (1.0 - ratio) + ordered[upper] * ratio


def ecod_score(value: float, profile: EcodProfile) -> tuple[float, float, int]:
    refs = profile.reference_values
    lower_count = bisect_right(refs, value)
    upper_count = len(refs) - bisect_left(refs, value)
    lower_tail = max(lower_count, 1) / (len(refs) + 1)
    upper_tail = max(upper_count, 1) / (len(refs) + 1)
    tail_probability = min(1.0, 2.0 * min(lower_tail, upper_tail))
    score = -math.log(max(tail_probability, 1e-12))
    effect = (value - profile.center) / profile.scale
    direction = 1 if effect > 0 else -1 if effect < 0 else 0
    return score, abs(effect), direction


def detect_local_mad_points(
    timestamps: list[datetime],
    values: list[float | None],
    *,
    mad_floor: float = 0.0,
    direction_filter: str | None = None,
    config: ResidualAdConfig = ResidualAdConfig(),
    component: str = "raw",
    baseline_values: list[float | None] | None = None,
    threshold_values: list[float | None] | None = None,
    bottleneck_threshold: float | None = None,
    z_threshold: float | None = None,
    min_run_points: int = 1,
    max_gap_minutes: int = 0,
    relative_floor: float | None = None,
) -> list[dict[str, Any]]:
    """Causal trailing median/MAD; freeze the normal reference on outliers."""
    history: deque[tuple[datetime, float]] = deque(maxlen=config.mad_window_points)
    previous_observed: datetime | None = None
    points: list[dict[str, Any]] = []
    threshold = config.mad_z_threshold if z_threshold is None else z_threshold
    for index, (timestamp, value) in enumerate(zip(timestamps, values)):
        if value is None or not math.isfinite(value):
            continue
        if previous_observed is not None and timestamp - previous_observed > timedelta(minutes=config.mad_reset_gap_minutes):
            history.clear()
        previous_observed = timestamp
        while history and timestamp - history[0][0] > timedelta(minutes=config.mad_max_age_minutes):
            history.popleft()
        if len(history) < config.mad_min_history:
            history.append((timestamp, value))
            continue
        normal = [sample for _, sample in history]
        center = median(normal)
        deviation = median(abs(sample - center) for sample in normal)
        scale = max(1.4826 * deviation, mad_floor,
                    abs(center) * (config.mad_relative_floor if relative_floor is None else relative_floor), 1e-12)
        delta = value - center
        direction = "high" if delta > 0 else "low" if delta < 0 else ""
        score = abs(delta) / scale
        is_candidate = score >= threshold and (direction_filter is None or direction_filter == direction)
        tested_value = threshold_values[index] if threshold_values is not None else value
        if is_candidate and bottleneck_threshold is not None and tested_value is not None:
            if direction == "high" and tested_value < bottleneck_threshold:
                is_candidate = False
            if direction == "low" and tested_value > bottleneck_threshold:
                is_candidate = False
        # Freeze on large deviations in either direction so a sustained shift
        # cannot become its own normal reference.
        if score < threshold:
            history.append((timestamp, value))
        if not is_candidate:
            continue
        baseline = center
        if baseline_values is not None and baseline_values[index] is not None:
            baseline += float(baseline_values[index])
        points.append({
            "point_index": index,
            "timestamp": timestamp,
            "component": component,
            "event_type": "residual_anomaly" if component == "residual" else "metric_anomaly",
            "score": min(score, 12.0),
            "direction": direction,
            "detector": f"local_mad_{component}",
            "value": value,
            "baseline": baseline,
        })
    if min_run_points <= 1:
        return points
    kept: list[dict[str, Any]] = []
    run: list[dict[str, Any]] = []
    for point in points:
        if run and (
            point["timestamp"] - run[-1]["timestamp"] > timedelta(minutes=max_gap_minutes + 1)
            or point["direction"] != run[-1]["direction"]
        ):
            if len(run) >= min_run_points:
                kept.extend(run)
            run = []
        run.append(point)
    if len(run) >= min_run_points:
        kept.extend(run)
    return kept


def detect_ecod_points(
    timestamps: list[datetime],
    values: list[float | None],
    config: ResidualAdConfig,
    component: str,
    event_type: str,
    detector: str,
    direction_filter: str | None = None,
    bottleneck_threshold: float | None = None,
    threshold_values: list[float | None] | None = None,
    baseline_values: list[float | None] | None = None,
) -> list[dict[str, Any]]:
    """Return loose ECOD candidates that also pass the configured directional N-Sigma gate."""
    profiles = build_ecod_profiles(values)
    if not profiles:
        return []
    profile = profiles[0]
    finite_values = [value for value in values if value is not None and math.isfinite(value)]
    train_scores = [ecod_score(value, profile)[0] for value in finite_values]
    threshold = linear_quantile(train_scores, 1.0 - max(0.0, min(config.anomaly_fraction, 0.5)))
    # The ECOD reference contains the points being scored.  A classical standard
    # deviation is therefore inflated by a sustained anomaly and can mask every
    # point in that anomaly.  The profile scale is MAD/IQR based and represents
    # the normal bulk of the series, which is the intended N-Sigma reference.
    sigma = max(profile.scale, 1e-12)
    points: list[dict[str, Any]] = []
    for index, (timestamp, value) in enumerate(zip(timestamps, values)):
        if value is None or not math.isfinite(value):
            continue
        score, effect, direction = ecod_score(value, profile)
        direction_name = "high" if direction > 0 else "low" if direction < 0 else ""
        if direction_filter is not None and direction_name != direction_filter:
            continue
        threshold_value = threshold_values[index] if threshold_values is not None else value
        if bottleneck_threshold is not None and threshold_value is not None:
            if direction_name == "high" and threshold_value < bottleneck_threshold:
                continue
            if direction_name == "low" and threshold_value > bottleneck_threshold:
                continue
        if score >= threshold and abs(value - profile.center) >= config.n_sigma * sigma:
            baseline = profile.center
            if baseline_values is not None and baseline_values[index] is not None:
                baseline = float(baseline_values[index]) + profile.center
            points.append(
                {
                    "point_index": index,
                    "timestamp": timestamp,
                    "component": component,
                    "event_type": event_type,
                    "score": score,
                    "direction": direction_name,
                    "detector": detector,
                    "value": value,
                    "baseline": baseline,
                }
            )
    return points


def detect_numeric_points(
    timestamps: list[datetime],
    values: list[float | None],
    config: ResidualAdConfig,
    rule: MetricDetectionRule,
    *,
    component: str,
    baseline_values: list[float | None] | None = None,
    threshold_values: list[float | None] | None = None,
) -> list[dict[str, Any]]:
    mode = rule.numeric_detectors or "ecod"
    direction = tail_direction_filter(rule.tail)
    ecod: list[dict[str, Any]] = []
    mad: list[dict[str, Any]] = []
    if mode in {"ecod", "both"}:
        ecod = detect_ecod_points(
            timestamps, values, config, component,
            "residual_anomaly" if component == "residual" else "metric_anomaly",
            "ecod_residual" if component == "residual" else "ecod_raw",
            direction_filter=direction,
            bottleneck_threshold=rule.bottleneck_threshold,
            threshold_values=threshold_values,
            baseline_values=baseline_values,
        )
    if mode in {"mad", "both"}:
        mad = detect_local_mad_points(
            timestamps, values,
            mad_floor=rule.mad_floor or 0.0,
            direction_filter=direction,
            config=config,
            component=component,
            baseline_values=baseline_values,
            threshold_values=threshold_values,
            bottleneck_threshold=rule.bottleneck_threshold,
            z_threshold=rule.mad_z_threshold,
            min_run_points=rule.mad_min_run_points or 1,
            max_gap_minutes=rule.mad_run_gap_minutes or 0,
            relative_floor=rule.mad_relative_floor,
        )
    by_point: dict[int, dict[str, Any]] = {item["point_index"]: item for item in ecod}
    for item in mad:
        previous = by_point.get(item["point_index"])
        if previous is None:
            by_point[item["point_index"]] = item
        elif previous["direction"] == item["direction"]:
            # Preserve the global ECOD score for comparability; both methods
            # agreeing is recorded in the diagnostic detector field.
            previous["detector"] += "+local_mad"
            previous["score"] = max(previous["score"], item["score"])
        # Opposite local/global directions are ambiguous; retain ECOD only.
    return list(by_point.values())


def has_minimum_change(point: dict[str, Any], raw_values: list[float | None], rule: MetricDetectionRule) -> bool:
    """Apply physical-unit and relative gates to a numeric detector candidate."""
    observed = raw_values[point["point_index"]]
    baseline = point.get("baseline")
    if observed is None or baseline is None:
        return False
    change = abs(observed - float(baseline))
    if rule.min_absolute_change is not None and change < rule.min_absolute_change:
        return False
    if rule.min_relative_change is not None and change / max(abs(float(baseline)), 1.0) < rule.min_relative_change:
        return False
    return True


def is_resource_metric(metric_id: str) -> bool:
    return ".node_metrics." in metric_id


def resource_direction_filter(metric_id: str, config: ResidualAdConfig) -> str | None:
    if config.resource_high_tail_only and is_resource_metric(metric_id):
        return "high"
    return None


def local_peak_indexes(values: list[float | None], threshold: float) -> list[int]:
    peaks: list[int] = []
    for index in range(1, len(values) - 1):
        value = values[index]
        if value is None or not math.isfinite(value) or value <= threshold:
            continue
        left = values[index - 1]
        right = values[index + 1]
        left_value = -math.inf if left is None else left
        right_value = -math.inf if right is None else right
        if value >= left_value and value >= right_value:
            peaks.append(index)
    return peaks


def dynamic_periodic_peak_component(
    values: list[float | None],
    config: ResidualAdConfig,
    trend: list[float | None] | None = None,
    timestamps: list[datetime] | None = None,
) -> list[float | None]:
    finite = [value for value in values if value is not None and math.isfinite(value)]
    if len(finite) < config.min_valid_points:
        return [None if value is None else 0.0 for value in values]
    component = [None if value is None else 0.0 for value in values]
    peak_timestamps = timestamps or [datetime.min + timedelta(minutes=index) for index in range(len(values))]
    period, _, supported_peaks = dynamic_periodic_peak_model(
        peak_timestamps,
        values,
        config,
    )
    if period is None:
        return component
    for peak_index in supported_peaks:
        trend_value = trend[peak_index] if trend is not None else 0.0
        component[peak_index] = None if trend_value is None else values[peak_index] - trend_value
    return component


def group_component_points(
    metric_id: str,
    profile: MetricProfile,
    result: BaselineResult,
    points: list[dict[str, Any]],
    raw_values: list[float | str | None] | None = None,
) -> list[dict[str, Any]]:
    if not points:
        return []
    return [
        points_to_event(metric_id, profile, result, [point], raw_values)
        for point in sorted(points, key=lambda item: item["point_index"])
    ]


def points_to_event(
    metric_id: str,
    profile: MetricProfile,
    result: BaselineResult,
    points: list[dict[str, Any]],
    raw_values: list[float | str | None] | None = None,
) -> dict[str, Any]:
    scores = [float(point["score"]) for point in points]
    first = points[0]
    return {
        "metric_name": metric_id,
        "metric_family": "",
        "metric_shape": "decomposed" if result.model_type == "moving_average_decomposition_raw" else "direct",
        "component": first["component"],
        "event_type": first["event_type"],
        "start_time": points[0]["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
        "end_time": points[-1]["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
        "change_time": first["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
        if first["event_type"] in {"trend_change", "seasonal_change"}
        else "",
        "detector": first["detector"],
        "generation_model": result.model_type,
        "severity": round(max(scores), 6),
        "direction": first.get("direction", ""),
        "observed_value": first.get("value", ""),
        "raw_value": raw_values[first["point_index"]] if raw_values is not None else first.get("value", ""),
        "baseline_value": first.get("baseline", ""),
        "residual": first.get("value", "") if first["component"] == "residual" else "",
        "old_model_params": first.get("old_model_params", ""),
        "new_model_params": first.get("new_model_params", ""),
        "reason": f"{first['event_type']} detected on {first['component']} component",
        "point_index": first["point_index"],
        "profile": {
            "periodic_minutes": profile.periodic_minutes,
            "periodic_kind": profile.periodic_kind,
            "trend_score": round(profile.trend_score, 6),
            "trend_r2": round(profile.trend_r2, 6),
            "periodic_score": round(profile.periodic_score, 6),
        },
    }


def write_events_csv(events: list[dict[str, Any]], path: Path) -> None:
    write_event_rows(path, (metric_event_row(event) for event in events), METRIC_EVENT_FIELDS)


def write_plot_html(
    metric_id: str,
    timestamps: list[datetime],
    values: list[float | str | None],
    baseline: list[float | str | None],
    trend: list[float | None],
    seasonal: list[float | None],
    residual: list[float | None],
    events: list[dict[str, Any]],
    profile: MetricProfile,
    result: BaselineResult,
    path: Path,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    x_values = [timestamp.strftime("%Y-%m-%d %H:%M:%S") for timestamp in timestamps]
    markers = marker_payload(events, timestamps, values, trend, seasonal, residual)
    payload = {
        "title": metric_id,
        "x": x_values,
        "raw": values,
        "trend": trend,
        "seasonal": seasonal,
        "residual": residual,
        "markers": markers,
        "trend_score": round(profile.trend_score, 6),
        "trend_r2": round(profile.trend_r2, 6),
        "periodic_score": round(profile.periodic_score, 6),
        "periodic_minutes": profile.periodic_minutes or "",
        "periodic_kind": profile.periodic_kind,
        "generation_model": result.model_type,
    }
    document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{metric_id}</title>
  <script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>
  <style>
    body {{ margin: 0; font-family: Arial, sans-serif; }}
    #chart {{ width: 100vw; height: 100vh; }}
  </style>
</head>
<body>
  <div id="chart"></div>
  <script>
    const payload = {json.dumps(payload, ensure_ascii=False)};
    const traces = [
      {{x: payload.x, y: payload.raw, mode: "lines", name: "raw value", line: {{color: "#2563eb", width: 1.3}}, connectgaps: false, xaxis: "x", yaxis: "y"}},
      {{x: payload.markers.all.x, y: payload.markers.all.y, mode: "markers", name: "all anomaly points", marker: {{color: "#dc2626", size: 7}}, xaxis: "x", yaxis: "y"}},
      {{x: payload.x, y: payload.trend, mode: "lines", name: "trend component", line: {{color: "#7c3aed", width: 1.4}}, connectgaps: false, xaxis: "x2", yaxis: "y2"}},
      {{x: payload.markers.trend.x, y: payload.markers.trend.y, mode: "markers", name: "trend anomaly points", marker: {{color: "#dc2626", size: 7}}, xaxis: "x2", yaxis: "y2"}},
      {{x: payload.x, y: payload.seasonal, mode: "lines+markers", name: "periodic / seasonal component", line: {{color: "#0891b2", width: 1.4}}, marker: {{color: "#0891b2", size: 4}}, connectgaps: false, xaxis: "x3", yaxis: "y3"}},
      {{x: payload.markers.seasonal.x, y: payload.markers.seasonal.y, mode: "markers", name: "seasonal anomaly points", marker: {{color: "#dc2626", size: 7}}, xaxis: "x3", yaxis: "y3"}},
      {{x: payload.x, y: payload.residual, mode: "lines", name: "residual", line: {{color: "#16a34a", width: 1.2}}, connectgaps: false, xaxis: "x4", yaxis: "y4"}},
      {{x: payload.markers.residual.x, y: payload.markers.residual.y, mode: "markers", name: "residual anomaly points", marker: {{color: "#dc2626", size: 7}}, xaxis: "x4", yaxis: "y4"}}
    ];
    const layout = {{
      title: payload.title + " | trend_score=" + payload.trend_score + " | trend_r2=" + payload.trend_r2 + " | periodic_score=" + payload.periodic_score + " | period_minutes=" + payload.periodic_minutes + " | periodic_kind=" + payload.periodic_kind + " | model=" + payload.generation_model,
      grid: {{rows: 4, columns: 1, pattern: "independent", roworder: "top to bottom"}},
      hovermode: "x unified",
      margin: {{l: 75, r: 30, t: 70, b: 60}},
      xaxis: {{title: "time", rangeslider: {{visible: true}}}},
      yaxis: {{title: "raw metric value", zeroline: false}},
      xaxis2: {{title: "time"}},
      yaxis2: {{title: "trend", zeroline: false}},
      xaxis3: {{title: "time"}},
      yaxis3: {{title: "periodic / seasonal", zeroline: true}},
      xaxis4: {{title: "time"}},
      yaxis4: {{title: "residual", zeroline: true}}
    }};
    Plotly.newPlot("chart", traces, layout, {{responsive: true, scrollZoom: true}});
  </script>
</body>
</html>
"""
    path.write_text(document, encoding="utf-8")


def marker_payload(
    events: list[dict[str, Any]],
    timestamps: list[datetime],
    values: list[float | str | None],
    trend: list[float | None],
    seasonal: list[float | None],
    residual: list[float | None],
) -> dict[str, dict[str, list[Any]]]:
    payload = {
        "all": {"x": [], "y": []},
        "trend": {"x": [], "y": []},
        "seasonal": {"x": [], "y": []},
        "residual": {"x": [], "y": []},
    }
    by_component = {"trend": trend, "seasonal": seasonal, "residual": residual}
    for event in events:
        if event["event_type"] == "missing_value":
            continue
        start = parse_timestamp(event["start_time"])
        end = parse_timestamp(event["end_time"])
        if start is None or end is None:
            continue
        component = event["component"]
        for index, timestamp in enumerate(timestamps):
            if start <= timestamp <= end and values[index] is not None:
                x_text = timestamp.strftime("%Y-%m-%d %H:%M:%S")
                payload["all"]["x"].append(x_text)
                payload["all"]["y"].append(values[index])
                if component in by_component:
                    payload[component]["x"].append(x_text)
                    payload[component]["y"].append(by_component[component][index])
                elif component == "raw" and residual[index] is not None:
                    payload["residual"]["x"].append(x_text)
                    payload["residual"]["y"].append(residual[index])
    return payload


def plot_path_for_metric(plot_root: Path, metric_id: str) -> Path:
    """Place each plot beneath the metric source type, e.g. interface_metrics."""
    parts = metric_id.split(".")
    metric_type = parts[2] if len(parts) >= 3 else "other"
    return plot_root / safe_filename(metric_type) / f"{safe_filename(metric_id)}.html"


@dataclass
class MetricDetectionOutcome:
    metric_id: str
    result: BaselineResult | None
    numeric_values: list[float | None] | None
    events: list[dict[str, Any]]
    skip_reason: str | None = None


_WORKER_TIMESTAMPS: list[datetime] = []
_WORKER_CONFIG = ResidualAdConfig()
_WORKER_RULES = DetectionRules()
_WORKER_WRITE_PLOTS = False
_WORKER_PLOT_DIR = Path(".")


def _initialize_detection_worker(
    timestamps: list[datetime],
    config: ResidualAdConfig,
    rules: DetectionRules,
    write_plots: bool,
    plot_dir: Path,
) -> None:
    global _WORKER_TIMESTAMPS, _WORKER_CONFIG, _WORKER_RULES, _WORKER_WRITE_PLOTS, _WORKER_PLOT_DIR
    _WORKER_TIMESTAMPS = timestamps
    _WORKER_CONFIG = config
    _WORKER_RULES = rules
    _WORKER_WRITE_PLOTS = write_plots
    _WORKER_PLOT_DIR = plot_dir


def _detect_metric_worker(item: tuple[str, list[float | str | None]]) -> MetricDetectionOutcome:
    metric_id, raw_values = item
    return detect_single_metric(
        metric_id,
        raw_values,
        _WORKER_TIMESTAMPS,
        _WORKER_CONFIG,
        _WORKER_RULES,
        _WORKER_WRITE_PLOTS,
        _WORKER_PLOT_DIR,
    )


def detect_single_metric(
    metric_id: str,
    raw_values: list[float | str | None],
    timestamps: list[datetime],
    config: ResidualAdConfig,
    rules: DetectionRules,
    write_plots: bool,
    plot_dir: Path,
) -> MetricDetectionOutcome:
    rule = resolve_metric_rule(metric_id, rules)
    detector_config = detector_config_for_metric(metric_id, config, rules)
    if rule.enabled is False:
        return MetricDetectionOutcome(metric_id, None, None, [], "disabled")
    if not any(value is not None for value in raw_values):
        return MetricDetectionOutcome(metric_id, None, None, [], "empty")

    missing_enabled = rules.missing.enabled if rule.missing_detection_enabled is None else rule.missing_detection_enabled
    missing_config = replace(rules.missing, enabled=missing_enabled and not bool(rule.normal_is_null))
    missing_points = missing_value_points(timestamps, raw_values, missing_config)
    is_state_workflow = rule.workflow in {"state", "rare_state"}
    if is_state_workflow:
        has_configured_states = bool(
            rule.normal_values or rule.failure_values or rule.failure_regex or rule.normal_is_null
        )
        if has_configured_states:
            state_points = configured_state_points(timestamps, raw_values, rule)
            baseline_label = "NULL" if rule.normal_is_null else ",".join(rule.normal_values)
            model_type = "configured_state_rule"
            residual_name = "state_vs_configured_normal"
        else:
            is_rare_state, dominant_state = rare_state_summary(
                raw_values,
                rules.rare_state_max_unique,
                rules.rare_state_min_dominant_ratio,
            )
            state_points, dominant_state = (
                rare_state_points(timestamps, raw_values, dominant_state)
                if is_rare_state
                else ([], dominant_state)
            )
            baseline_label = display_state(dominant_state)
            model_type = "rare_state_baseline"
            residual_name = "state_vs_dominant_state"
        points = [*missing_points, *state_points]
        profile = MetricProfile(metric_id, None, "none", 0.0, 0.0, 0.0)
        result = BaselineResult(
            metric_id,
            model_type,
            [baseline_label for _ in raw_values],
            [None for _ in raw_values],
            residual_name,
            {},
        )
        metric_events = group_component_points(metric_id, profile, result, points, raw_values)
        if write_plots:
            write_plot_html(
                metric_id,
                timestamps,
                raw_values,
                result.baseline,
                [None for _ in raw_values],
                [None for _ in raw_values],
                result.residual,
                metric_events,
                profile,
                result,
                plot_path_for_metric(plot_dir, metric_id),
            )
        return MetricDetectionOutcome(metric_id, result, None, metric_events)

    values: list[float | None] = [value if isinstance(value, float) else None for value in raw_values]
    finite = valid_values(values)
    if not finite:
        return MetricDetectionOutcome(metric_id, None, None, [], "empty")

    points: list[dict[str, Any]] = list(missing_points)
    skip_reason: str | None = None
    if len(finite) < config.min_valid_points:
        skip_reason = "too_few"
    elif is_constant_series(values):
        skip_reason = "constant"
    if skip_reason is not None:
        profile = MetricProfile(metric_id, None, "none", 0.0, 0.0, 0.0)
        result = BaselineResult(
            metric_id,
            f"filtered_{skip_reason}",
            [None for _ in values],
            [None for _ in values],
            "missing_value_check_only",
            {},
        )
        metric_events = group_component_points(metric_id, profile, result, points, raw_values)
        if write_plots:
            write_plot_html(
                metric_id,
                timestamps,
                values,
                result.baseline,
                [None for _ in values],
                [None for _ in values],
                result.residual,
                metric_events,
                profile,
                result,
                plot_path_for_metric(plot_dir, metric_id),
            )
        return MetricDetectionOutcome(metric_id, result, values, metric_events, skip_reason)

    profile = infer_metric_profile(metric_id, timestamps, values, config.period_candidate_minutes, config)
    if should_decompose(profile, config):
        trend, seasonal, baseline, residual = moving_average_components(timestamps, values, profile, config)
        result = BaselineResult(
            metric_id,
            "moving_average_decomposition_raw",
            baseline,
            residual,
            "value_minus_moving_average_baseline",
            {},
        )
        points.extend(detect_numeric_points(
            timestamps, residual, detector_config, rule,
            component="residual", threshold_values=values, baseline_values=baseline,
        ))
    else:
        baseline = [None for _ in values]
        residual = [None for _ in values]
        trend = [None for _ in values]
        seasonal = [None for _ in values]
        result = BaselineResult(
            metric_id,
            "direct_local_mad_raw" if rule.numeric_detectors == "mad" else "direct_ecod_raw",
            baseline,
            residual,
            "raw_value_direct_detection",
            {},
        )
        points.extend(detect_numeric_points(
            timestamps, values, detector_config, rule, component="raw",
        ))

    points = [
        point for point in points
        if point["event_type"] == "missing_value" or has_minimum_change(point, values, rule)
    ]
    metric_events: list[dict[str, Any]] = []
    for component in sorted({point["component"] for point in points}):
        component_points = [point for point in points if point["component"] == component]
        metric_events.extend(group_component_points(metric_id, profile, result, component_points, raw_values))
    if write_plots:
        write_plot_html(
            metric_id,
            timestamps,
            values,
            result.baseline,
            trend,
            seasonal,
            result.residual,
            metric_events,
            profile,
            result,
            plot_path_for_metric(plot_dir, metric_id),
        )
    return MetricDetectionOutcome(metric_id, result, values, metric_events)


REPRESENTATIVE_METRIC_KEYWORDS = (
    "cpu_usage",
    "memory_usage",
    "disk_io_util",
    "drop_rate",
    "error_rate",
    "interface_oper",
    "route_count",
    "bgp_peer",
    "ospf",
    "scrape",
)


def metric_source_name(metric_id: str) -> str:
    parts = metric_id.split(".")
    return parts[2] if len(parts) >= 3 else "other"


def select_representative_metric_ids(
    metric_ids: list[str],
    events: list[dict[str, Any]],
    limit: int,
) -> list[str]:
    if limit <= 0:
        return []
    event_counts: dict[str, int] = {}
    for event in events:
        metric_id = str(event.get("metric_name", ""))
        event_counts[metric_id] = event_counts.get(metric_id, 0) + 1

    def rank(metric_id: str) -> tuple[int, int, int, str]:
        lowered = metric_id.casefold()
        priority = next(
            (index for index, keyword in enumerate(REPRESENTATIVE_METRIC_KEYWORDS) if keyword in lowered),
            len(REPRESENTATIVE_METRIC_KEYWORDS),
        )
        count = event_counts.get(metric_id, 0)
        return (0 if count else 1, priority, -count, metric_id)

    by_source: dict[str, list[str]] = {}
    for metric_id in dict.fromkeys(metric_ids):
        by_source.setdefault(metric_source_name(metric_id), []).append(metric_id)
    for candidates in by_source.values():
        candidates.sort(key=rank)

    preferred_sources = ["node_metrics", "interface_metrics", "routing_metrics", "scrape_health"]
    source_order = [source for source in preferred_sources if source in by_source]
    source_order.extend(sorted(source for source in by_source if source not in preferred_sources))
    selected: list[str] = []
    for source in source_order:
        if len(selected) >= limit:
            break
        selected.append(by_source[source].pop(0))

    remaining = sorted(
        (metric_id for candidates in by_source.values() for metric_id in candidates),
        key=rank,
    )
    selected.extend(remaining[: max(0, limit - len(selected))])
    return selected


def write_representative_plot_manifest(
    selected_metric_ids: list[str],
    events: list[dict[str, Any]],
    plot_dir: Path,
    path: Path,
) -> None:
    events_by_metric: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        events_by_metric.setdefault(str(event.get("metric_name", "")), []).append(event)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["metric_name", "metric_source", "event_count", "event_types", "plot_file"],
        )
        writer.writeheader()
        for metric_id in selected_metric_ids:
            metric_events = events_by_metric.get(metric_id, [])
            writer.writerow(
                {
                    "metric_name": metric_id,
                    "metric_source": metric_source_name(metric_id),
                    "event_count": len(metric_events),
                    "event_types": ",".join(sorted({str(event["event_type"]) for event in metric_events})),
                    "plot_file": str(plot_path_for_metric(plot_dir, metric_id)),
                }
            )


def run_detection(
    testset_csv: Path,
    output_dir: Path,
    config: ResidualAdConfig,
    rules_config: Path = DEFAULT_RULES_CONFIG,
    verbose: bool = False,
    progress_every: int = 20,
    write_plots: bool = True,
    write_modeled_series: bool = True,
    workers: int = 1,
    representative_plot_limit: int = 0,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    plot_dir = output_dir / "plots"
    if write_plots:
        plot_dir.mkdir(parents=True, exist_ok=True)
        for stale_html in plot_dir.rglob("*.html"):
            stale_html.unlink()
        representative_manifest = output_dir / "representative_plot_metrics.csv"
        if representative_manifest.exists():
            representative_manifest.unlink()
    timestamps, raw_values_by_metric = load_raw_testset(testset_csv)
    rules = load_detection_rules(rules_config)
    if verbose:
        print(
            f"[metric-ad] loaded testset={testset_csv} rows={len(timestamps)} metrics={len(raw_values_by_metric)}",
            flush=True,
        )
    results: dict[str, BaselineResult] = {}
    numeric_values_by_metric: dict[str, list[float | None]] = {}
    events: list[dict[str, Any]] = []
    skipped_empty = 0
    skipped_disabled = 0
    skipped_constant = 0
    skipped_too_few = 0
    skipped_metrics: dict[str, list[str]] = {"empty": [], "disabled": [], "constant": [], "too_few": []}
    total_metrics = len(raw_values_by_metric)
    metric_items = list(raw_values_by_metric.items())
    worker_count = max(1, int(workers))
    write_all_plots = write_plots and representative_plot_limit <= 0

    def iter_outcomes():
        if worker_count == 1:
            for metric_id, raw_values in metric_items:
                yield detect_single_metric(
                    metric_id,
                    raw_values,
                    timestamps,
                    config,
                    rules,
                    write_all_plots,
                    plot_dir,
                )
            return

        with ProcessPoolExecutor(
            max_workers=worker_count,
            initializer=_initialize_detection_worker,
            initargs=(timestamps, config, rules, write_all_plots, plot_dir),
        ) as executor:
            item_iterator = iter(metric_items)
            batch_size = worker_count * 2
            while True:
                batch = []
                for _ in range(batch_size):
                    try:
                        batch.append(next(item_iterator))
                    except StopIteration:
                        break
                if not batch:
                    break
                futures = [executor.submit(_detect_metric_worker, item) for item in batch]
                for future in futures:
                    yield future.result()

    if verbose:
        print(f"[metric-ad] detection workers={worker_count}", flush=True)
    for ordinal, outcome in enumerate(iter_outcomes(), start=1):
        if verbose and (ordinal == 1 or ordinal == total_metrics or ordinal % max(1, progress_every) == 0):
            print(f"[metric-ad] detected {ordinal}/{total_metrics}: {outcome.metric_id}", flush=True)
        if outcome.skip_reason is not None:
            skipped_metrics[outcome.skip_reason].append(outcome.metric_id)
            if outcome.skip_reason == "empty":
                skipped_empty += 1
            elif outcome.skip_reason == "disabled":
                skipped_disabled += 1
            elif outcome.skip_reason == "constant":
                skipped_constant += 1
            elif outcome.skip_reason == "too_few":
                skipped_too_few += 1
        if outcome.result is not None:
            results[outcome.metric_id] = outcome.result
        if outcome.numeric_values is not None:
            numeric_values_by_metric[outcome.metric_id] = outcome.numeric_values
        events.extend(outcome.events)

    if write_plots and representative_plot_limit > 0:
        selected_metric_ids = select_representative_metric_ids(
            list(results),
            events,
            representative_plot_limit,
        )
        if verbose:
            print(
                f"[metric-ad] writing representative plots={len(selected_metric_ids)} "
                f"limit={representative_plot_limit}",
                flush=True,
            )
        for metric_id in selected_metric_ids:
            detect_single_metric(
                metric_id,
                raw_values_by_metric[metric_id],
                timestamps,
                config,
                rules,
                True,
                plot_dir,
            )
        write_representative_plot_manifest(
            selected_metric_ids,
            events,
            plot_dir,
            output_dir / "representative_plot_metrics.csv",
        )
    events.sort(key=lambda event: (event["start_time"], event["metric_name"], event["component"]))
    event_file = output_dir / "metric_anomaly_events.csv"
    write_events_csv(events, event_file)
    evidence_file = output_dir / "evidence_events.jsonl"
    coverage_file = output_dir / "observation_coverage.jsonl"
    write_evidence(events, testset_csv, evidence_file)
    coverage_count = write_coverage(
        timestamps, raw_values_by_metric, events, testset_csv, coverage_file,
    )
    if write_modeled_series:
        numeric_results = {metric_id: results[metric_id] for metric_id in numeric_values_by_metric}
        write_modeled_series_csv(timestamps, numeric_values_by_metric, numeric_results, output_dir / "modeled_metric_testset.csv")
    else:
        stale_modeled_series = output_dir / "modeled_metric_testset.csv"
        if stale_modeled_series.exists():
            stale_modeled_series.unlink()
    summary = {
        "testset_csv": str(testset_csv),
        "rules_config": str(rules_config),
        "rules_config_sha256": hashlib.sha256(rules_config.read_bytes()).hexdigest(),
        "detector_config": asdict(config),
        "metric_count": len(raw_values_by_metric),
        "processed_metric_count": len(results),
        "skipped_empty": skipped_empty,
        "skipped_disabled": skipped_disabled,
        "skipped_constant": skipped_constant,
        "skipped_too_few": skipped_too_few,
        "skipped_metrics": skipped_metrics,
        "event_count": len(events),
        "event_file": str(event_file),
        "evidence_file": str(evidence_file),
        "coverage_file": str(coverage_file),
        "coverage_interval_count": coverage_count,
        "plot_count": len(list(plot_dir.rglob("*.html"))) if write_plots else 0,
        "plot_dir": str(plot_dir),
    }
    (output_dir / "metric_anomaly_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    if verbose:
        print(
            f"[metric-ad] finished metrics={summary['processed_metric_count']} events={summary['event_count']} output={event_file}",
            flush=True,
        )
    return summary


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run lightweight residual/mechanism metric anomaly detection")
    parser.add_argument("--testset-csv", type=Path, default=Path("outputs/metric_anomalies/_base/updated_metric_testset.csv"))
    parser.add_argument("--output-dir", type=Path, default=Path("outputs/metric_anomalies/_base"))
    parser.add_argument("--rolling-window", type=int, default=ResidualAdConfig.rolling_window)
    parser.add_argument("--anomaly-fraction", type=float, default=ResidualAdConfig.anomaly_fraction)
    parser.add_argument("--n-sigma", type=float, default=ResidualAdConfig.n_sigma)
    parser.add_argument("--min-effect-size", type=float, default=ResidualAdConfig.min_effect_size)
    parser.add_argument(
        "--period-candidate-minutes",
        type=str,
        default=",".join(str(value) for value in ResidualAdConfig.period_candidate_minutes),
    )
    parser.add_argument(
        "--rules-config",
        type=Path,
        default=DEFAULT_RULES_CONFIG,
        help="JSON configuration for metric workflow and one-sided detection rules.",
    )
    parser.add_argument(
        "--include-resource-low-tail",
        action="store_true",
        help="Deprecated compatibility option; configure tail policies with --rules-config.",
    )
    parser.add_argument(
        "--dynamic-peak-period-min-minutes",
        type=int,
        default=ResidualAdConfig.dynamic_peak_period_min_minutes,
    )
    parser.add_argument(
        "--dynamic-peak-period-max-minutes",
        type=int,
        default=ResidualAdConfig.dynamic_peak_period_max_minutes,
    )
    parser.add_argument(
        "--dynamic-peak-tolerance-minutes",
        type=int,
        default=ResidualAdConfig.dynamic_peak_tolerance_minutes,
    )
    parser.add_argument("--progress", action="store_true", help="Print detection progress.")
    parser.add_argument("--progress-every", type=int, default=20)
    parser.add_argument("--workers", type=int, default=1, help="Number of metric detection worker processes.")
    parser.add_argument(
        "--representative-plot-limit",
        type=int,
        default=0,
        help="Plot only this many representative metrics; 0 plots every processed metric.",
    )
    parser.add_argument("--no-plots", action="store_true", help="Skip interactive HTML plot generation.")
    parser.add_argument("--no-modeled-series", action="store_true", help="Skip modeled wide-CSV generation.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    period_candidates = tuple(int(item.strip()) for item in args.period_candidate_minutes.split(",") if item.strip())
    summary = run_detection(
        args.testset_csv,
        args.output_dir,
        ResidualAdConfig(
            rolling_window=args.rolling_window,
            anomaly_fraction=args.anomaly_fraction,
            n_sigma=args.n_sigma,
            min_effect_size=args.min_effect_size,
            period_candidate_minutes=period_candidates,
            resource_high_tail_only=not args.include_resource_low_tail,
            dynamic_peak_period_min_minutes=args.dynamic_peak_period_min_minutes,
            dynamic_peak_period_max_minutes=args.dynamic_peak_period_max_minutes,
            dynamic_peak_tolerance_minutes=args.dynamic_peak_tolerance_minutes,
        ),
        rules_config=args.rules_config,
        verbose=args.progress,
        progress_every=args.progress_every,
        write_plots=not args.no_plots,
        write_modeled_series=not args.no_modeled_series,
        workers=args.workers,
        representative_plot_limit=args.representative_plot_limit,
    )
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
