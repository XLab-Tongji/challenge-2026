"""Split routing_metrics CSV files by region and router entity."""

from __future__ import annotations

import argparse
import csv
from datetime import datetime, timedelta
from pathlib import Path
import re
from typing import Iterable
from urllib.parse import quote, unquote


REQUIRED_COLUMNS = ["timestamp", "region", "node", "node_type", "metric_name", "label", "value"]
KEY_COLUMNS = ["node", "timestamp", "metric_name", "label"]
NULL_VALUES = {"", "NULL", "\\N", "NaN", "nan", "None", "none"}


def parse_timestamp(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is not None:
        parsed = parsed.replace(tzinfo=None)
    return parsed


def format_timestamp(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S")


def complete_minute_range(start: datetime, end: datetime) -> list[datetime]:
    current = start
    values = []
    while current <= end:
        values.append(current)
        current += timedelta(minutes=1)
    return values


def normalize_value(value: str | None) -> str:
    if value is None:
        return "NULL"
    text = value.strip()
    return "NULL" if text in NULL_VALUES else text


def validate_header(fieldnames: Iterable[str] | None) -> None:
    present = set(fieldnames or [])
    missing = [column for column in REQUIRED_COLUMNS if column not in present]
    if missing:
        raise ValueError(f"routing_metrics CSV missing required columns: {', '.join(missing)}")


def sanitize_label_part(value: str) -> str:
    text = value.replace('"', "")
    text = re.sub(r"[^A-Za-z0-9]+", "_", text)
    text = re.sub(r"_+", "_", text)
    return text.strip("_")


def make_series_name(metric_name: str, label: str) -> str:
    metric = sanitize_label_part(metric_name)
    label = normalize_value(label)
    if label == "NULL":
        return metric
    return f"{metric}__label_urlencoded_{quote(label, safe='')}"


def parse_series_name(series_name: str) -> tuple[str, str]:
    marker = "__label_urlencoded_"
    if marker not in series_name:
        return series_name, ""
    metric_name, encoded_label = series_name.split(marker, 1)
    return metric_name, unquote(encoded_label)


def report_duplicate(existing: dict[str, str], duplicate: dict[str, str]) -> None:
    differing = [
        column
        for column in REQUIRED_COLUMNS
        if column not in KEY_COLUMNS and existing.get(column) != duplicate.get(column)
    ]
    print("duplicate routing_metrics rows detected")
    print(
        "key: "
        f"node={existing.get('node')} "
        f"timestamp={existing.get('timestamp')} "
        f"metric_name={existing.get('metric_name')} "
        f"label={existing.get('label')}"
    )
    print(f"existing: {existing}")
    print(f"duplicate: {duplicate}")
    if differing:
        print(f"differing non-key columns: {', '.join(differing)}")
    else:
        print("differing non-key columns: none; rows are identical on known fields")


def process_routing_metrics_file(input_path: str | Path, output_root: str | Path, region: str) -> dict[str, object]:
    input_path = Path(input_path)
    output_root = Path(output_root)

    rows_by_node: dict[str, dict[datetime, dict[str, str]]] = {}
    raw_rows_by_key: dict[tuple[str, datetime, str, str], dict[str, str]] = {}
    series_by_node: dict[str, dict[str, tuple[str, str]]] = {}
    all_timestamps: list[datetime] = []

    with input_path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        validate_header(reader.fieldnames)
        for raw_row in reader:
            normalized_row = {column: normalize_value(raw_row.get(column)) for column in REQUIRED_COLUMNS}
            node = normalized_row["node"]
            metric_name = normalized_row["metric_name"]
            label = "" if normalized_row["label"] == "NULL" else normalized_row["label"]
            if node == "NULL" or metric_name == "NULL":
                raise ValueError(f"routing_metrics row has empty node or metric_name in {input_path}")

            timestamp = parse_timestamp(normalized_row["timestamp"])
            normalized_row["timestamp"] = format_timestamp(timestamp)
            normalized_row["label"] = label
            key = (node, timestamp, metric_name, label)

            existing = raw_rows_by_key.get(key)
            if existing is not None:
                report_duplicate(existing, normalized_row)
                raise ValueError(
                    "duplicate routing_metrics rows for "
                    f"node={node}, timestamp={format_timestamp(timestamp)}, metric_name={metric_name}, label={label}"
                )
            raw_rows_by_key[key] = normalized_row

            series_name = make_series_name(metric_name, label)
            all_timestamps.append(timestamp)
            series_by_node.setdefault(node, {})[series_name] = (metric_name, label)
            rows_by_node.setdefault(node, {}).setdefault(timestamp, {})[series_name] = normalized_row["value"]

    if not all_timestamps:
        raise ValueError(f"routing_metrics CSV contains no data rows: {input_path}")

    timeline = complete_minute_range(min(all_timestamps), max(all_timestamps))
    entities = sorted(rows_by_node)

    for node in entities:
        series_names = sorted(
            series_by_node[node],
            key=lambda name: (series_by_node[node][name][0], series_by_node[node][name][1]),
        )
        fieldnames = ["timestamp", *series_names]

        output_dir = output_root / region / node / "metric"
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / "routing_metrics.csv"

        node_rows = rows_by_node[node]
        with output_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
            writer.writeheader()
            for timestamp in timeline:
                values_at_time = node_rows.get(timestamp, {})
                output_row = {"timestamp": format_timestamp(timestamp)}
                for series_name in series_names:
                    output_row[series_name] = values_at_time.get(series_name, "NULL")
                writer.writerow(output_row)

    return {
        "region": region,
        "entities": entities,
        "time_start": format_timestamp(timeline[0]),
        "time_end": format_timestamp(timeline[-1]),
        "time_points": len(timeline),
        "output_root": str(output_root),
        "series_by_entity": {node: sorted(series_by_node[node]) for node in entities},
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Split a region routing_metrics CSV into per-router first-stage metric files."
    )
    parser.add_argument("--input", required=True, help="Path to one routing_metrics_*.csv file.")
    parser.add_argument("--region", required=True, help="Region code, for example beida or shanghai.")
    parser.add_argument(
        "--output-root",
        default="data/updated/first_stage",
        help="Root directory for first-stage outputs.",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    summary = process_routing_metrics_file(args.input, args.output_root, args.region)
    series_counts = ", ".join(
        f"{node}:{len(series)}" for node, series in summary["series_by_entity"].items()
    )
    print(
        "processed routing_metrics: "
        f"region={summary['region']} "
        f"entities={len(summary['entities'])} "
        f"time_start={summary['time_start']} "
        f"time_end={summary['time_end']} "
        f"time_points={summary['time_points']} "
        f"series={series_counts} "
        f"output_root={summary['output_root']}"
    )


if __name__ == "__main__":
    main()
