"""Metric baseline records and output helpers used by the active detector."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime
import hashlib
from pathlib import Path
from statistics import median
from typing import Any


@dataclass
class BaselineResult:
    metric_id: str
    model_type: str
    baseline: list[float | None]
    residual: list[float | None]
    residual_kind: str
    summary: dict[str, Any]


def median_step_seconds(timestamps: list[datetime]) -> float:
    deltas = [
        (right - left).total_seconds()
        for left, right in zip(timestamps, timestamps[1:])
        if (right - left).total_seconds() > 0
    ]
    return median(deltas) if deltas else 0.0


def write_modeled_series_csv(
    timestamps: list[datetime],
    values_by_metric: dict[str, list[float | None]],
    results: dict[str, BaselineResult],
    path: Path,
) -> None:
    fields = ["timestamp"]
    for metric_id in results:
        fields.extend([metric_id, f"{metric_id}__baseline", f"{metric_id}__residual"])
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for index, timestamp in enumerate(timestamps):
            row: dict[str, Any] = {"timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S")}
            for metric_id, result in results.items():
                row[metric_id] = "" if values_by_metric[metric_id][index] is None else values_by_metric[metric_id][index]
                row[f"{metric_id}__baseline"] = "" if result.baseline[index] is None else result.baseline[index]
                row[f"{metric_id}__residual"] = "" if result.residual[index] is None else result.residual[index]
            writer.writerow(row)


def safe_filename(value: str) -> str:
    normalized = "".join(char if char.isalnum() or char in "-_." else "_" for char in value)
    if len(normalized) <= 120:
        return normalized
    digest = hashlib.sha1(value.encode("utf-8")).hexdigest()[:12]
    return f"{normalized[:107]}_{digest}"
