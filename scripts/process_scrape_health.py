"""Split scrape_health CSV files by region and network entity."""

from __future__ import annotations

import argparse
import csv
from datetime import datetime, timedelta
from pathlib import Path
import re
from typing import Iterable
from urllib.parse import quote, unquote


OBSERVATION_COLUMNS = [
    "scrape_up",
    "scrape_duration_seconds",
    "scrape_samples",
    "scrape_error",
]

REQUIRED_COLUMNS = [
    "timestamp",
    "region",
    "target_id",
    "node",
    "exporter_type",
    *OBSERVATION_COLUMNS,
]

KEY_COLUMNS = ["node", "timestamp", "target_id", "exporter_type"]
NULL_VALUES = {"", "NULL", "\\N", "NaN", "nan", "None", "none"}
TARGET_MARKER = "__target_urlencoded_"


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
        raise ValueError(f"scrape_health CSV missing required columns: {', '.join(missing)}")


def sanitize_identifier(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9]+", "_", value.strip())
    text = re.sub(r"_+", "_", text)
    return text.strip("_")


def make_target_metric_name(exporter_type: str, target_id: str, metric_name: str) -> str:
    exporter = sanitize_identifier(exporter_type)
    metric = sanitize_identifier(metric_name)
    return f"{exporter}{TARGET_MARKER}{quote(target_id, safe='')}__{metric}"


def parse_target_metric_name(column_name: str) -> tuple[str, str, str]:
    exporter_type, rest = column_name.split(TARGET_MARKER, 1)
    encoded_target, metric_name = rest.rsplit("__", 1)
    return exporter_type, unquote(encoded_target), metric_name


def report_duplicate(existing: dict[str, str], duplicate: dict[str, str]) -> None:
    differing = [
        column
        for column in REQUIRED_COLUMNS
        if column not in KEY_COLUMNS and existing.get(column) != duplicate.get(column)
    ]
    print("duplicate scrape_health rows detected")
    print(
        "key: "
        f"node={existing.get('node')} "
        f"timestamp={existing.get('timestamp')} "
        f"target_id={existing.get('target_id')} "
        f"exporter_type={existing.get('exporter_type')}"
    )
    print(f"existing: {existing}")
    print(f"duplicate: {duplicate}")
    if differing:
        print(f"differing non-key columns: {', '.join(differing)}")
    else:
        print("differing non-key columns: none; rows are identical on known fields")


def process_scrape_health_file(input_path: str | Path, output_root: str | Path, region: str) -> dict[str, object]:
    input_path = Path(input_path)
    output_root = Path(output_root)

    rows_by_node: dict[str, dict[datetime, dict[tuple[str, str], dict[str, str]]]] = {}
    raw_rows_by_key: dict[tuple[str, datetime, str, str], dict[str, str]] = {}
    targets_by_node: dict[str, set[tuple[str, str]]] = {}
    all_timestamps: list[datetime] = []

    with input_path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        validate_header(reader.fieldnames)
        for raw_row in reader:
            normalized_row = {column: normalize_value(raw_row.get(column)) for column in REQUIRED_COLUMNS}
            node = normalized_row["node"]
            target_id = normalized_row["target_id"]
            exporter_type = normalized_row["exporter_type"]
            if node == "NULL" or target_id == "NULL" or exporter_type == "NULL":
                raise ValueError(f"scrape_health row has empty node, target_id, or exporter_type in {input_path}")

            timestamp = parse_timestamp(normalized_row["timestamp"])
            normalized_row["timestamp"] = format_timestamp(timestamp)
            key = (node, timestamp, target_id, exporter_type)

            existing = raw_rows_by_key.get(key)
            if existing is not None:
                report_duplicate(existing, normalized_row)
                raise ValueError(
                    "duplicate scrape_health rows for "
                    f"node={node}, timestamp={format_timestamp(timestamp)}, "
                    f"target_id={target_id}, exporter_type={exporter_type}"
                )
            raw_rows_by_key[key] = normalized_row

            all_timestamps.append(timestamp)
            target_key = (exporter_type, target_id)
            targets_by_node.setdefault(node, set()).add(target_key)
            observation_values = {column: normalized_row[column] for column in OBSERVATION_COLUMNS}
            rows_by_node.setdefault(node, {}).setdefault(timestamp, {})[target_key] = observation_values

    if not all_timestamps:
        raise ValueError(f"scrape_health CSV contains no data rows: {input_path}")

    timeline = complete_minute_range(min(all_timestamps), max(all_timestamps))
    entities = sorted(rows_by_node)

    for node in entities:
        targets = sorted(targets_by_node[node], key=lambda item: (item[0], item[1]))
        fieldnames = ["timestamp"]
        for exporter_type, target_id in targets:
            for metric_name in OBSERVATION_COLUMNS:
                fieldnames.append(make_target_metric_name(exporter_type, target_id, metric_name))

        output_dir = output_root / region / node / "metric"
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / "scrape_health.csv"

        node_rows = rows_by_node[node]
        with output_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
            writer.writeheader()
            for timestamp in timeline:
                output_row = {"timestamp": format_timestamp(timestamp)}
                targets_at_time = node_rows.get(timestamp, {})
                for exporter_type, target_id in targets:
                    values = targets_at_time.get((exporter_type, target_id))
                    for metric_name in OBSERVATION_COLUMNS:
                        column_name = make_target_metric_name(exporter_type, target_id, metric_name)
                        output_row[column_name] = values[metric_name] if values else "NULL"
                writer.writerow(output_row)

    return {
        "region": region,
        "entities": entities,
        "time_start": format_timestamp(timeline[0]),
        "time_end": format_timestamp(timeline[-1]),
        "time_points": len(timeline),
        "output_root": str(output_root),
        "targets_by_entity": {
            node: sorted(targets_by_node[node], key=lambda item: (item[0], item[1]))
            for node in entities
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Split a region scrape_health CSV into per-entity first-stage metric files."
    )
    parser.add_argument("--input", required=True, help="Path to one scrape_health_*.csv file.")
    parser.add_argument("--region", required=True, help="Region code, for example beida or shanghai.")
    parser.add_argument(
        "--output-root",
        default="data/updated/first_stage",
        help="Root directory for first-stage outputs.",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    summary = process_scrape_health_file(args.input, args.output_root, args.region)
    target_counts = ", ".join(
        f"{node}:{len(targets)}" for node, targets in summary["targets_by_entity"].items()
    )
    print(
        "processed scrape_health: "
        f"region={summary['region']} "
        f"entities={len(summary['entities'])} "
        f"time_start={summary['time_start']} "
        f"time_end={summary['time_end']} "
        f"time_points={summary['time_points']} "
        f"targets={target_counts} "
        f"output_root={summary['output_root']}"
    )


if __name__ == "__main__":
    main()
