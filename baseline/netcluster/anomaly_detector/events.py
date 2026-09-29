"""Public anomaly-event CSV formats shared by metrics and logs."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Iterable


EVENT_FIELDS = (
    "地区",
    "实体名称",
    "数据类型",
    "名称",
    "异常类型",
    "开始时间",
    "结束时间",
    "异常值",
)

METRIC_EVENT_FIELDS = EVENT_FIELDS + ("基线值",)


def metric_event_type(event_type: str, direction: str) -> str:
    if event_type == "missing_value":
        return "缺失值"
    if event_type == "state_anomaly":
        return "异常状态"
    if direction in {"high", "up"}:
        return "突增"
    if direction in {"low", "down"}:
        return "突降"
    raise ValueError(f"Cannot map metric event type={event_type!r}, direction={direction!r}")


def metric_event_row(event: dict[str, Any]) -> dict[str, Any]:
    """Use the first anomalous raw sample for a multi-minute metric event."""
    metric_id = str(event["metric_name"])
    parts = metric_id.split(".", 3)
    if len(parts) != 4 and not (event.get("city") and event.get("node") and event.get("metric_column")):
        raise ValueError(f"Cannot identify region, entity, and metric from {metric_id!r}")
    city = str(event.get("city") or parts[0])
    entity = str(event.get("node") or parts[1])
    name = str(event.get("metric_column") or parts[3])
    anomaly_type = metric_event_type(str(event["event_type"]), str(event.get("direction", "")))
    value = event.get("raw_value", event.get("first_value", event.get("observed_value", "")))
    if anomaly_type == "缺失值" or value is None:
        value = ""
    return {
        "地区": city,
        "实体名称": entity,
        "数据类型": "指标",
        "名称": name,
        "异常类型": anomaly_type,
        "开始时间": event["start_time"],
        "结束时间": event["end_time"],
        "异常值": value,
        "基线值": event.get("baseline_value", ""),
    }


def write_event_rows(
    path: Path,
    rows: Iterable[dict[str, Any]],
    fieldnames: tuple[str, ...] = EVENT_FIELDS,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
