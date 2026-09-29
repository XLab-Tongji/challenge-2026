"""Split minute-level NetFlow 5-tuple CSV files by router entity."""

from __future__ import annotations

import argparse
import csv
from datetime import datetime
from pathlib import Path
import re
from typing import Iterable


SOURCE_COLUMNS = [
    "minute_utc",
    "region_code",
    "region",
    "node_key",
    "node",
    "node_type",
    "interface_id",
    "if_role",
    "collector_port",
    "protocol",
    "src_addr",
    "src_port",
    "dst_addr",
    "dst_port",
    "packets",
    "bytes",
    "flow_record_count",
    "first_seen",
    "last_seen",
]
OUTPUT_COLUMNS = [
    "entity",
    "minute_utc",
    "region_code",
    "region",
    "interface_id",
    "if_role",
    "collector_port",
    "protocol",
    "protocol_name",
    "src_addr",
    "src_port",
    "src_region_inferred",
    "dst_addr",
    "dst_port",
    "dst_region_inferred",
    "packets",
    "bytes",
    "flow_record_count",
    "first_seen",
    "last_seen",
]
NULL_VALUES = {"", "NULL", "\\N", "NaN", "nan", "None", "none"}
NODE_KEY_RE = re.compile(r"^(br|cr)(\d+)$", re.IGNORECASE)
REGION_BY_FD00_SEGMENT = {
    "1": "beida",
    "2": "shenyang",
    "3": "xian",
    "4": "chengdu",
    "5": "wuhan",
    "6": "shanghai",
    "7": "nanjing",
    "8": "guangzhou",
}
PROTOCOL_NAMES = {
    "6": "TCP",
    "17": "UDP",
    "58": "ICMPv6",
    "89": "OSPF",
}
DUPLICATE_KEY_COLUMNS = [
    "minute_utc",
    "interface_id",
    "protocol",
    "src_addr",
    "src_port",
    "dst_addr",
    "dst_port",
]


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


def validate_header(fieldnames: Iterable[str] | None) -> None:
    present = set(fieldnames or [])
    missing = [column for column in SOURCE_COLUMNS if column not in present]
    if missing:
        raise ValueError(f"netflow_5tuple CSV missing required columns: {', '.join(missing)}")


def extract_entity_from_node_key(node_key: str) -> str:
    match = NODE_KEY_RE.match(node_key.strip())
    if not match:
        raise ValueError(f"cannot parse entity from node_key={node_key}")
    return f"{match.group(1).lower()}-{match.group(2)}"


def infer_region_from_ipv6(address: str) -> str:
    text = address.strip().lower()
    parts = text.split(":")
    if len(parts) < 2 or parts[0] != "fd00":
        return "NULL"
    return REGION_BY_FD00_SEGMENT.get(parts[1], "NULL")


def protocol_name(protocol: str) -> str:
    return PROTOCOL_NAMES.get(protocol, "UNKNOWN")


def duplicate_key(row: dict[str, str]) -> tuple[str, ...]:
    return tuple(row[column] for column in DUPLICATE_KEY_COLUMNS)


def report_duplicate(existing: dict[str, str], duplicate: dict[str, str]) -> None:
    print("duplicate netflow_5tuple key detected")
    print(
        "key: "
        + ", ".join(f"{column}={existing.get(column)}" for column in DUPLICATE_KEY_COLUMNS)
    )
    print(f"existing: {existing}")
    print(f"duplicate: {duplicate}")


def process_netflow_5tuple_file(
    input_path: str | Path,
    output_root: str | Path,
    region: str,
    progress_interval: int = 100000,
    detect_duplicates: bool = False,
) -> dict[str, object]:
    input_path = Path(input_path)
    output_root = Path(output_root)

    output_handles: dict[str, object] = {}
    writers: dict[str, csv.DictWriter] = {}
    rows_by_entity: dict[str, int] = {}
    seen_keys_by_entity: dict[str, dict[tuple[str, ...], dict[str, str]]] = {} if detect_duplicates else {}
    row_count = 0

    print(f"[netflow] start region={region} input={input_path}")

    def writer_for_entity(entity: str) -> csv.DictWriter:
        writer = writers.get(entity)
        if writer is not None:
            return writer
        output_dir = output_root / region / entity / "netflow"
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / "netflow_5tuple.csv"
        handle = output_path.open("w", newline="", encoding="utf-8")
        output_handles[entity] = handle
        writer = csv.DictWriter(handle, fieldnames=OUTPUT_COLUMNS, lineterminator="\n")
        writer.writeheader()
        writers[entity] = writer
        print(f"[netflow] opened output region={region} entity={entity} output={output_path}")
        return writer

    try:
        with input_path.open(newline="", encoding="utf-8-sig") as handle:
            reader = csv.DictReader(handle)
            validate_header(reader.fieldnames)
            for raw_row in reader:
                row_count += 1
                source_row = {column: normalize_value(raw_row.get(column)) for column in SOURCE_COLUMNS}
                try:
                    entity = extract_entity_from_node_key(source_row["node_key"])
                except ValueError:
                    print("invalid netflow_5tuple node_key")
                    print(f"row: {source_row}")
                    raise

                source_row["minute_utc"] = format_timestamp(parse_timestamp(source_row["minute_utc"]))
                if source_row["first_seen"] != "NULL":
                    source_row["first_seen"] = format_timestamp(parse_timestamp(source_row["first_seen"]))
                if source_row["last_seen"] != "NULL":
                    source_row["last_seen"] = format_timestamp(parse_timestamp(source_row["last_seen"]))

                output_row = {
                    "entity": entity,
                    "minute_utc": source_row["minute_utc"],
                    "region_code": source_row["region_code"],
                    "region": source_row["region"],
                    "interface_id": source_row["interface_id"],
                    "if_role": source_row["if_role"],
                    "collector_port": source_row["collector_port"],
                    "protocol": source_row["protocol"],
                    "protocol_name": protocol_name(source_row["protocol"]),
                    "src_addr": source_row["src_addr"],
                    "src_port": source_row["src_port"],
                    "src_region_inferred": infer_region_from_ipv6(source_row["src_addr"]),
                    "dst_addr": source_row["dst_addr"],
                    "dst_port": source_row["dst_port"],
                    "dst_region_inferred": infer_region_from_ipv6(source_row["dst_addr"]),
                    "packets": source_row["packets"],
                    "bytes": source_row["bytes"],
                    "flow_record_count": source_row["flow_record_count"],
                    "first_seen": source_row["first_seen"],
                    "last_seen": source_row["last_seen"],
                }

                if detect_duplicates:
                    key = duplicate_key(output_row)
                    seen_for_entity = seen_keys_by_entity.setdefault(entity, {})
                    existing = seen_for_entity.get(key)
                    if existing is not None:
                        report_duplicate(existing, output_row)
                    else:
                        seen_for_entity[key] = output_row

                writer_for_entity(entity).writerow(output_row)
                rows_by_entity[entity] = rows_by_entity.get(entity, 0) + 1
                if progress_interval > 0 and row_count % progress_interval == 0:
                    entity_counts = ", ".join(
                        f"{name}:{count}" for name, count in sorted(rows_by_entity.items())
                    )
                    print(f"[netflow] read region={region} rows={row_count} entity_rows={entity_counts}")
    finally:
        for handle in output_handles.values():
            handle.close()

    entities = sorted(rows_by_entity)
    print(f"[netflow] finished region={region} rows={row_count} entities={len(entities)}")
    for entity in entities:
        output_path = output_root / region / entity / "netflow" / "netflow_5tuple.csv"
        print(f"[netflow] wrote region={region} entity={entity} rows={rows_by_entity[entity]} output={output_path}")

    return {
        "region": region,
        "entities": entities,
        "row_count": row_count,
        "rows_by_entity": {entity: rows_by_entity[entity] for entity in entities},
        "output_root": str(output_root),
    }


def infer_region_from_path(path: Path) -> str:
    for part in reversed(path.parts):
        match = re.match(r"^([a-z]+)_\d{14}_\d{14}$", part)
        if match:
            return match.group(1)
    raise ValueError(f"cannot infer region from path: {path}")


def discover_netflow_files(input_root: str | Path) -> list[tuple[str, Path]]:
    input_root = Path(input_root)
    files = sorted(input_root.rglob("netflow_5tuple_minute_readable.csv"))
    return [(infer_region_from_path(path), path) for path in files]


def process_netflow_5tuple_root(
    input_root: str | Path,
    output_root: str | Path,
    progress_interval: int = 100000,
    detect_duplicates: bool = False,
) -> list[dict[str, object]]:
    summaries = []
    discovered = discover_netflow_files(input_root)
    print(f"[netflow] discovered files={len(discovered)} input_root={input_root}")
    for index, (region, input_path) in enumerate(discovered, start=1):
        print(f"[netflow] processing file {index}/{len(discovered)} region={region}")
        summaries.append(
            process_netflow_5tuple_file(
                input_path,
                output_root,
                region,
                progress_interval,
                detect_duplicates,
            )
        )
    return summaries


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Split NetFlow 5-tuple minute CSV files into per-router first-stage files."
    )
    parser.add_argument("--input", help="Path to one netflow_5tuple_minute_readable.csv file.")
    parser.add_argument("--region", help="Region code for --input mode, for example beida or shanghai.")
    parser.add_argument(
        "--input-root",
        default="../../AIOps_Challenge/2026_CCF_AIOps_challenge_processed",
        help="Root directory to scan for netflow_5tuple_minute_readable.csv files.",
    )
    parser.add_argument(
        "--output-root",
        default="data/updated/first_stage",
        help="Root directory for first-stage outputs.",
    )
    parser.add_argument(
        "--progress-interval",
        type=int,
        default=100000,
        help="Print row-level progress every N input rows; use 0 to disable row-level progress.",
    )
    parser.add_argument(
        "--detect-duplicates",
        action="store_true",
        help="Detect duplicate 5-tuple keys while processing. This stores keys in memory, so keep it off for large files.",
    )
    return parser


def print_summary(summary: dict[str, object]) -> None:
    entity_counts = ", ".join(
        f"{entity}:{count}" for entity, count in summary["rows_by_entity"].items()
    )
    print(
        "processed netflow_5tuple: "
        f"region={summary['region']} "
        f"entities={len(summary['entities'])} "
        f"rows={summary['row_count']} "
        f"entity_rows={entity_counts} "
        f"output_root={summary['output_root']}"
    )


def main() -> None:
    args = build_parser().parse_args()
    if args.input:
        if not args.region:
            raise SystemExit("--region is required when --input is used")
        print_summary(
            process_netflow_5tuple_file(
                args.input,
                args.output_root,
                args.region,
                args.progress_interval,
                args.detect_duplicates,
            )
        )
        return

    summaries = process_netflow_5tuple_root(
        args.input_root,
        args.output_root,
        args.progress_interval,
        args.detect_duplicates,
    )
    if not summaries:
        raise SystemExit(f"no netflow_5tuple_minute_readable.csv files found under {args.input_root}")
    for summary in summaries:
        print_summary(summary)


if __name__ == "__main__":
    main()
