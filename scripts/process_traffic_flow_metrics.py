"""Split traffic_flow_metrics CSV files by traffic probe series."""

from __future__ import annotations

import argparse
import csv
from datetime import datetime
from pathlib import Path
from typing import Iterable
from urllib.parse import quote


FLOW_TYPES = ["dns", "web", "auth", "elephant"]
BASE_COLUMNS = [
    "timestamp_utc",
    "prometheus_sample_time_utc",
    "id",
    "series_key",
    "flow_type",
    "source_region",
    "source_ip",
    "target_region",
    "target_domain",
    "protocol",
]
SERIES_DIMENSION_COLUMNS = [
    "series_key",
    "flow_type",
    "source_region",
    "source_ip",
    "target_region",
    "target_domain",
    "protocol",
]
REQUIRED_COLUMNS = BASE_COLUMNS
KEY_COLUMNS = ["series_key", "timestamp_utc"]
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


def normalize_value(value: str | None) -> str:
    if value is None:
        return "NULL"
    text = value.strip()
    return "NULL" if text in NULL_VALUES else text


def validate_header(fieldnames: Iterable[str] | None) -> list[str]:
    header = list(fieldnames or [])
    present = set(header)
    missing = [column for column in REQUIRED_COLUMNS if column not in present]
    if missing:
        raise ValueError(f"traffic_flow_metrics CSV missing required columns: {', '.join(missing)}")
    return header


def make_series_filename(series_key: str) -> str:
    return f"{quote(series_key, safe='')}.csv"


def flow_metric_columns(header: list[str]) -> dict[str, list[tuple[str, str]]]:
    columns_by_flow: dict[str, list[tuple[str, str]]] = {}
    for flow_type in FLOW_TYPES:
        prefix = f"{flow_type}_flow_"
        columns_by_flow[flow_type] = [
            (column, column.removeprefix(prefix))
            for column in header
            if column.startswith(prefix)
        ]
    return columns_by_flow


def report_duplicate(existing: dict[str, str], duplicate: dict[str, str], known_columns: list[str]) -> None:
    differing = [
        column
        for column in known_columns
        if column not in KEY_COLUMNS and existing.get(column) != duplicate.get(column)
    ]
    print("duplicate traffic_flow rows detected")
    print(
        "key: "
        f"series_key={existing.get('series_key')} "
        f"timestamp_utc={existing.get('timestamp_utc')}"
    )
    print(f"existing: {existing}")
    print(f"duplicate: {duplicate}")
    if differing:
        print(f"differing non-key columns: {', '.join(differing)}")
    else:
        print("differing non-key columns: none; rows are identical on known fields")


def report_dimension_conflict(existing: dict[str, str], conflicting: dict[str, str]) -> None:
    differing = [
        column
        for column in SERIES_DIMENSION_COLUMNS
        if existing.get(column) != conflicting.get(column)
    ]
    print("conflicting traffic_flow series dimensions detected")
    print(f"series_key={existing.get('series_key')}")
    print(f"existing: {existing}")
    print(f"conflicting: {conflicting}")
    print(f"differing dimension columns: {', '.join(differing)}")


def process_traffic_flow_metrics_file(input_path: str | Path, output_root: str | Path, region: str) -> dict[str, object]:
    input_path = Path(input_path)
    output_root = Path(output_root)

    rows_by_series: dict[str, list[dict[str, str]]] = {}
    dimensions_by_series: dict[str, dict[str, str]] = {}
    raw_rows_by_key: dict[tuple[str, datetime], dict[str, str]] = {}

    with input_path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        header = validate_header(reader.fieldnames)
        metrics_by_flow = flow_metric_columns(header)

        for raw_row in reader:
            row = {column: normalize_value(raw_row.get(column)) for column in header}
            series_key = row["series_key"]
            flow_type = row["flow_type"]
            if series_key == "NULL" or flow_type == "NULL":
                raise ValueError(f"traffic_flow row has empty series_key or flow_type in {input_path}")
            if flow_type not in metrics_by_flow:
                raise ValueError(f"traffic_flow row has unsupported flow_type={flow_type} in {input_path}")

            timestamp = parse_timestamp(row["timestamp_utc"])
            row["timestamp_utc"] = format_timestamp(timestamp)
            if row["prometheus_sample_time_utc"] != "NULL":
                row["prometheus_sample_time_utc"] = format_timestamp(
                    parse_timestamp(row["prometheus_sample_time_utc"])
                )

            duplicate_key = (series_key, timestamp)
            existing_row = raw_rows_by_key.get(duplicate_key)
            if existing_row is not None:
                report_duplicate(existing_row, row, header)
                raise ValueError(
                    "duplicate traffic_flow rows for "
                    f"series_key={series_key}, timestamp_utc={format_timestamp(timestamp)}"
                )
            raw_rows_by_key[duplicate_key] = row

            dimensions = {column: row[column] for column in SERIES_DIMENSION_COLUMNS}
            existing_dimensions = dimensions_by_series.get(series_key)
            if existing_dimensions is not None and existing_dimensions != dimensions:
                report_dimension_conflict(existing_dimensions, dimensions)
                raise ValueError(f"conflicting traffic_flow series dimensions for series_key={series_key}")
            dimensions_by_series[series_key] = dimensions

            output_row = {column: row[column] for column in BASE_COLUMNS}
            for source_column, metric_name in metrics_by_flow[flow_type]:
                output_row[metric_name] = row[source_column]
            rows_by_series.setdefault(series_key, []).append(output_row)

    output_dir = output_root / region / "traffic-vm" / "traffic_flow"
    output_dir.mkdir(parents=True, exist_ok=True)

    index_rows = []
    for series_key in sorted(rows_by_series):
        rows = sorted(rows_by_series[series_key], key=lambda item: parse_timestamp(item["timestamp_utc"]))
        flow_type = rows[0]["flow_type"]
        metric_names = [metric_name for _, metric_name in metrics_by_flow[flow_type]]
        fieldnames = [*BASE_COLUMNS, *metric_names]
        filename = make_series_filename(series_key)

        with (output_dir / filename).open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)

        index_rows.append({**dimensions_by_series[series_key], "file_path": filename})

    index_fieldnames = [*SERIES_DIMENSION_COLUMNS, "file_path"]
    with (output_dir / "series_index.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=index_fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(sorted(index_rows, key=lambda item: item["series_key"]))

    return {
        "region": region,
        "series_count": len(rows_by_series),
        "row_count": sum(len(rows) for rows in rows_by_series.values()),
        "output_dir": str(output_dir),
        "rows_by_series": {series_key: len(rows) for series_key, rows in rows_by_series.items()},
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Split a region traffic_flow_metrics CSV into per-series first-stage files."
    )
    parser.add_argument("--input", required=True, help="Path to one traffic_flow_metrics.csv file.")
    parser.add_argument("--region", required=True, help="Region code, for example beida or shanghai.")
    parser.add_argument(
        "--output-root",
        default="data/updated/first_stage",
        help="Root directory for first-stage outputs.",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    summary = process_traffic_flow_metrics_file(args.input, args.output_root, args.region)
    print(
        "processed traffic_flow_metrics: "
        f"region={summary['region']} "
        f"series={summary['series_count']} "
        f"rows={summary['row_count']} "
        f"output_dir={summary['output_dir']}"
    )


if __name__ == "__main__":
    main()
