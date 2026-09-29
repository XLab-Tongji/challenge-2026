"""Split FRR syslog event CSV files by region and router entity."""

from __future__ import annotations

import argparse
import csv
from datetime import datetime
from pathlib import Path
import re
from typing import Iterable


SOURCE_COLUMNS = [
    "id",
    "received_at",
    "event_time",
    "received_at_raw",
    "event_time_raw",
    "source_ip",
    "hostname",
    "region",
    "facility",
    "severity",
    "severity_code",
    "program",
    "pid",
    "message",
    "inserted_at",
]
OUTPUT_COLUMNS = ["entity", *SOURCE_COLUMNS]
HOSTNAME_ENTITY_RE = re.compile(r"^(br-\d+|cr-\d+)-")


def parse_timestamp(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is not None:
        parsed = parsed.replace(tzinfo=None)
    return parsed


def validate_header(fieldnames: Iterable[str] | None) -> None:
    present = set(fieldnames or [])
    missing = [column for column in SOURCE_COLUMNS if column not in present]
    if missing:
        raise ValueError(f"frr_syslog_events CSV missing required columns: {', '.join(missing)}")


def extract_entity_from_hostname(hostname: str) -> str:
    match = HOSTNAME_ENTITY_RE.match(hostname.strip())
    if not match:
        raise ValueError(f"cannot parse entity from hostname={hostname}")
    return match.group(1)


def sort_key(row: dict[str, str]) -> tuple[datetime, datetime, int]:
    event_time = parse_timestamp(row["event_time"])
    received_at = parse_timestamp(row["received_at"])
    try:
        row_id = int(row["id"])
    except ValueError:
        row_id = 0
    return event_time, received_at, row_id


def process_frr_syslog_events_file(input_path: str | Path, output_root: str | Path, region: str) -> dict[str, object]:
    input_path = Path(input_path)
    output_root = Path(output_root)

    rows_by_entity: dict[str, list[dict[str, str]]] = {}

    with input_path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        validate_header(reader.fieldnames)
        for raw_row in reader:
            row = {column: raw_row.get(column, "") for column in SOURCE_COLUMNS}
            try:
                entity = extract_entity_from_hostname(row["hostname"])
            except ValueError:
                print("invalid frr_syslog_events hostname")
                print(f"row: {row}")
                raise
            rows_by_entity.setdefault(entity, []).append({"entity": entity, **row})

    entities = sorted(rows_by_entity)
    for entity in entities:
        output_dir = output_root / region / entity / "log"
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / "frr_syslog_events.csv"
        rows = sorted(rows_by_entity[entity], key=sort_key)

        with output_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=OUTPUT_COLUMNS, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)

    return {
        "region": region,
        "entities": entities,
        "row_count": sum(len(rows) for rows in rows_by_entity.values()),
        "rows_by_entity": {entity: len(rows_by_entity[entity]) for entity in entities},
        "output_root": str(output_root),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Split a region frr_syslog_events CSV into per-router first-stage log files."
    )
    parser.add_argument("--input", required=True, help="Path to one frr_syslog_events CSV file.")
    parser.add_argument("--region", required=True, help="Region code, for example beida or shanghai.")
    parser.add_argument(
        "--output-root",
        default="data/updated/first_stage",
        help="Root directory for first-stage outputs.",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    summary = process_frr_syslog_events_file(args.input, args.output_root, args.region)
    entity_counts = ", ".join(
        f"{entity}:{count}" for entity, count in summary["rows_by_entity"].items()
    )
    print(
        "processed frr_syslog_events: "
        f"region={summary['region']} "
        f"entities={len(summary['entities'])} "
        f"rows={summary['row_count']} "
        f"entity_rows={entity_counts} "
        f"output_root={summary['output_root']}"
    )


if __name__ == "__main__":
    main()
