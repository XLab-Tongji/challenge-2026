"""Split node_metrics CSV files by region and network entity."""

from __future__ import annotations

import argparse
import csv
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable


METRIC_COLUMNS = [
    "cpu_usage",
    "load1",
    "load5",
    "memory_available_ratio",
    "swap_used_ratio",
    "disk_read_rate",
    "disk_write_rate",
    "disk_io_util",
    "filesystem_used_ratio",
    "inode_used_ratio",
    "open_fd_ratio",
    "process_count",
]

REQUIRED_COLUMNS = ["timestamp", "region", "node", "node_type", *METRIC_COLUMNS]
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
        raise ValueError(f"node_metrics CSV missing required columns: {', '.join(missing)}")


def process_node_metrics_file(input_path: str | Path, output_root: str | Path, region: str) -> dict[str, object]:
    input_path = Path(input_path)
    output_root = Path(output_root)

    rows_by_node: dict[str, dict[datetime, dict[str, str]]] = {}
    all_timestamps: list[datetime] = []

    with input_path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        validate_header(reader.fieldnames)
        for raw_row in reader:
            node = normalize_value(raw_row.get("node"))
            if node == "NULL":
                raise ValueError(f"node_metrics row has empty node in {input_path}")

            timestamp = parse_timestamp(normalize_value(raw_row.get("timestamp")))
            all_timestamps.append(timestamp)

            metric_row = {column: normalize_value(raw_row.get(column)) for column in METRIC_COLUMNS}
            rows_by_node.setdefault(node, {})[timestamp] = metric_row

    if not all_timestamps:
        raise ValueError(f"node_metrics CSV contains no data rows: {input_path}")

    timeline = complete_minute_range(min(all_timestamps), max(all_timestamps))
    fieldnames = ["timestamp", *METRIC_COLUMNS]
    entities = sorted(rows_by_node)

    for node in entities:
        output_dir = output_root / region / node / "metric"
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / "node_metrics.csv"

        node_rows = rows_by_node[node]
        with output_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
            writer.writeheader()
            for timestamp in timeline:
                metric_row = node_rows.get(timestamp)
                if metric_row is None:
                    metric_row = {column: "NULL" for column in METRIC_COLUMNS}
                writer.writerow({"timestamp": format_timestamp(timestamp), **metric_row})

    return {
        "region": region,
        "entities": entities,
        "time_start": format_timestamp(timeline[0]),
        "time_end": format_timestamp(timeline[-1]),
        "time_points": len(timeline),
        "output_root": str(output_root),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Split a region node_metrics CSV into per-entity first-stage metric files."
    )
    parser.add_argument("--input", required=True, help="Path to one node_metrics_*.csv file.")
    parser.add_argument("--region", required=True, help="Region code, for example beida or shanghai.")
    parser.add_argument(
        "--output-root",
        default="data/updated/first_stage",
        help="Root directory for first-stage outputs.",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    summary = process_node_metrics_file(args.input, args.output_root, args.region)
    print(
        "processed node_metrics: "
        f"region={summary['region']} "
        f"entities={len(summary['entities'])} "
        f"time_start={summary['time_start']} "
        f"time_end={summary['time_end']} "
        f"time_points={summary['time_points']} "
        f"output_root={summary['output_root']}"
    )


if __name__ == "__main__":
    main()
