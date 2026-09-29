"""Split interface_metrics CSV files by region and network entity."""

from __future__ import annotations

import argparse
import csv
from datetime import datetime, timedelta
from pathlib import Path
import re
from typing import Iterable


METRIC_COLUMNS = [
    "rx_bytes_rate",
    "tx_bytes_rate",
    "rx_packets_rate",
    "tx_packets_rate",
    "rx_drop_rate",
    "tx_drop_rate",
    "rx_error_rate",
    "tx_error_rate",
    "carrier_changes",
]

REQUIRED_COLUMNS = [
    "timestamp",
    "region",
    "node",
    "node_type",
    "interface_id",
    "if_role",
    *METRIC_COLUMNS,
]

KEY_COLUMNS = ["node", "timestamp", "interface_id"]
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
        raise ValueError(f"interface_metrics CSV missing required columns: {', '.join(missing)}")


def interface_sort_key(interface_id: str) -> tuple[str, int, str]:
    match = re.fullmatch(r"([A-Za-z_-]+)(\d+)", interface_id)
    if match:
        return (match.group(1), int(match.group(2)), "")
    return (interface_id, -1, interface_id)


def report_duplicate(existing: dict[str, str], duplicate: dict[str, str]) -> None:
    differing = [
        column
        for column in REQUIRED_COLUMNS
        if column not in KEY_COLUMNS and existing.get(column) != duplicate.get(column)
    ]
    print("duplicate interface_metrics rows detected")
    print(f"key: node={existing.get('node')} timestamp={existing.get('timestamp')} interface_id={existing.get('interface_id')}")
    print(f"existing: {existing}")
    print(f"duplicate: {duplicate}")
    if differing:
        print(f"differing non-key columns: {', '.join(differing)}")
    else:
        print("differing non-key columns: none; rows are identical on known fields")


def process_interface_metrics_file(input_path: str | Path, output_root: str | Path, region: str) -> dict[str, object]:
    input_path = Path(input_path)
    output_root = Path(output_root)

    rows_by_node: dict[str, dict[datetime, dict[str, dict[str, str]]]] = {}
    raw_rows_by_key: dict[tuple[str, datetime, str], dict[str, str]] = {}
    interfaces_by_node: dict[str, set[str]] = {}
    all_timestamps: list[datetime] = []

    with input_path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        validate_header(reader.fieldnames)
        for raw_row in reader:
            normalized_row = {column: normalize_value(raw_row.get(column)) for column in REQUIRED_COLUMNS}
            node = normalized_row["node"]
            interface_id = normalized_row["interface_id"]
            if node == "NULL" or interface_id == "NULL":
                raise ValueError(f"interface_metrics row has empty node or interface_id in {input_path}")

            timestamp = parse_timestamp(normalized_row["timestamp"])
            normalized_row["timestamp"] = format_timestamp(timestamp)
            key = (node, timestamp, interface_id)
            existing = raw_rows_by_key.get(key)
            if existing is not None:
                report_duplicate(existing, normalized_row)
                raise ValueError(
                    "duplicate interface_metrics rows for "
                    f"node={node}, timestamp={format_timestamp(timestamp)}, interface_id={interface_id}"
                )
            raw_rows_by_key[key] = normalized_row

            all_timestamps.append(timestamp)
            interfaces_by_node.setdefault(node, set()).add(interface_id)
            interface_values = {"if_role": normalized_row["if_role"]}
            interface_values.update({column: normalized_row[column] for column in METRIC_COLUMNS})
            rows_by_node.setdefault(node, {}).setdefault(timestamp, {})[interface_id] = interface_values

    if not all_timestamps:
        raise ValueError(f"interface_metrics CSV contains no data rows: {input_path}")

    timeline = complete_minute_range(min(all_timestamps), max(all_timestamps))
    entities = sorted(rows_by_node)

    for node in entities:
        interfaces = sorted(interfaces_by_node[node], key=interface_sort_key)
        fieldnames = ["timestamp"]
        for interface_id in interfaces:
            fieldnames.append(f"{interface_id}_if_role")
            fieldnames.extend(f"{interface_id}_{metric}" for metric in METRIC_COLUMNS)

        output_dir = output_root / region / node / "metric"
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / "interface_metrics.csv"

        node_rows = rows_by_node[node]
        with output_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
            writer.writeheader()
            for timestamp in timeline:
                output_row = {"timestamp": format_timestamp(timestamp)}
                interfaces_at_time = node_rows.get(timestamp, {})
                for interface_id in interfaces:
                    values = interfaces_at_time.get(interface_id)
                    output_row[f"{interface_id}_if_role"] = values["if_role"] if values else "NULL"
                    for metric in METRIC_COLUMNS:
                        output_row[f"{interface_id}_{metric}"] = values[metric] if values else "NULL"
                writer.writerow(output_row)

    return {
        "region": region,
        "entities": entities,
        "time_start": format_timestamp(timeline[0]),
        "time_end": format_timestamp(timeline[-1]),
        "time_points": len(timeline),
        "output_root": str(output_root),
        "interfaces_by_entity": {
            node: sorted(interfaces_by_node[node], key=interface_sort_key) for node in entities
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Split a region interface_metrics CSV into per-entity first-stage metric files."
    )
    parser.add_argument("--input", required=True, help="Path to one interface_metrics_*.csv file.")
    parser.add_argument("--region", required=True, help="Region code, for example beida or shanghai.")
    parser.add_argument(
        "--output-root",
        default="data/updated/first_stage",
        help="Root directory for first-stage outputs.",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    summary = process_interface_metrics_file(args.input, args.output_root, args.region)
    interface_counts = ", ".join(
        f"{node}:{len(interfaces)}" for node, interfaces in summary["interfaces_by_entity"].items()
    )
    print(
        "processed interface_metrics: "
        f"region={summary['region']} "
        f"entities={len(summary['entities'])} "
        f"time_start={summary['time_start']} "
        f"time_end={summary['time_end']} "
        f"time_points={summary['time_points']} "
        f"interfaces={interface_counts} "
        f"output_root={summary['output_root']}"
    )


if __name__ == "__main__":
    main()
