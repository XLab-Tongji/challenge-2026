"""Rename existing routing_metrics output headers to reversible label names."""

from __future__ import annotations

import argparse
import csv
import io
import os
import shutil
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.process_routing_metrics import make_series_name, sanitize_label_part


def legacy_make_series_name(metric_name: str, label: str) -> str:
    metric = sanitize_label_part(metric_name)
    if not label:
        return metric

    parts = []
    for raw_part in label.split(","):
        part = sanitize_label_part(raw_part)
        if part:
            parts.append(part)
    return "__".join([metric, *parts]) if parts else metric


def normalize_label(value: str | None) -> str:
    if value is None:
        return ""
    text = value.strip()
    return "" if text in {"", "NULL", "\\N"} else text


def build_header_mappings(routing_input: Path) -> dict[str, dict[str, str]]:
    mappings: dict[str, dict[str, str]] = {}
    reverse_seen: dict[tuple[str, str], str] = {}

    with routing_input.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            node = row["node"].strip()
            metric_name = row["metric_name"].strip()
            label = normalize_label(row.get("label"))
            old_name = legacy_make_series_name(metric_name, label)
            new_name = make_series_name(metric_name, label)

            node_mapping = mappings.setdefault(node, {})
            existing_new = node_mapping.get(old_name)
            if existing_new is not None and existing_new != new_name:
                previous_label = reverse_seen.get((node, old_name), "<unknown>")
                raise ValueError(
                    "cannot safely rename routing header because legacy column name collides: "
                    f"node={node}, old_name={old_name}, previous_label={previous_label}, new_label={label}"
                )
            node_mapping[old_name] = new_name
            reverse_seen[(node, old_name)] = label

    return mappings


def rewrite_header_only(output_file: Path, mapping: dict[str, str]) -> int:
    with output_file.open("rb") as source:
        first_line = source.readline()
        if not first_line:
            raise ValueError(f"empty routing output file: {output_file}")

        header_text = first_line.decode("utf-8-sig").rstrip("\r\n")
        header = next(csv.reader([header_text]))
        new_header = [mapping.get(column, column) for column in header]
        if len(set(new_header)) != len(new_header):
            duplicates = sorted({column for column in new_header if new_header.count(column) > 1})
            raise ValueError(f"renamed header would contain duplicate columns in {output_file}: {duplicates}")

        if new_header == header:
            return 0

        header_buffer = io.StringIO()
        writer = csv.writer(header_buffer, lineterminator="\n")
        writer.writerow(new_header)
        new_header_bytes = header_buffer.getvalue().encode("utf-8")

        fd, temp_name = tempfile.mkstemp(
            prefix=f"{output_file.name}.",
            suffix=".tmp",
            dir=str(output_file.parent),
        )
        with os.fdopen(fd, "wb") as target:
            target.write(new_header_bytes)
            shutil.copyfileobj(source, target, length=1024 * 1024 * 16)

    os.replace(temp_name, output_file)
    return sum(1 for old, new in zip(header, new_header) if old != new)


def output_file_has_reversible_header(output_file: Path) -> bool:
    if not output_file.exists():
        return False
    with output_file.open("r", encoding="utf-8") as handle:
        first_line = handle.readline()
    return "__label_urlencoded_" in first_line


def region_outputs_are_renamed(output_root: Path, region: str) -> bool:
    routing_files = list((output_root / region).glob("*/metric/routing_metrics.csv"))
    return bool(routing_files) and all(output_file_has_reversible_header(path) for path in routing_files)


def rename_region_headers(routing_input: Path, output_root: Path, region: str) -> dict[str, object]:
    if region_outputs_are_renamed(output_root, region):
        return {"region": region, "nodes": [], "changed_by_node": {}, "skipped": True}

    mappings = build_header_mappings(routing_input)
    changed_by_node: dict[str, int] = {}
    for node, mapping in sorted(mappings.items()):
        output_file = output_root / region / node / "metric" / "routing_metrics.csv"
        if output_file.exists():
            changed_by_node[node] = rewrite_header_only(output_file, mapping)

    return {"region": region, "nodes": sorted(changed_by_node), "changed_by_node": changed_by_node, "skipped": False}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Rename existing first-stage routing_metrics headers without recomputing data rows."
    )
    parser.add_argument("--input", required=True, help="Path to one original routing_metrics_*.csv file.")
    parser.add_argument("--region", required=True, help="Region code, for example beida or shanghai.")
    parser.add_argument(
        "--output-root",
        default="data/updated/first_stage",
        help="Root directory containing existing first-stage outputs.",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    summary = rename_region_headers(Path(args.input), Path(args.output_root), args.region)
    if summary["skipped"]:
        print(f"renamed routing headers: region={summary['region']} skipped=already_reversible")
        return

    changed = ", ".join(
        f"{node}:{count}" for node, count in summary["changed_by_node"].items()
    )
    print(f"renamed routing headers: region={summary['region']} nodes={len(summary['nodes'])} changed={changed}")


if __name__ == "__main__":
    main()
